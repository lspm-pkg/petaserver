import os
import io
import secrets
import asyncio
import time
import httpx
from typing import Any, Set, List, Dict
from uuid import UUID
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from discord.ext import commands
import discord
from tortoise.exceptions import DoesNotExist
from .models import File, User
from .globals import logger
from .utils import get_at_path, crypto
from . import config

class UploadBot:
    def __init__(self, upload_channel: int, token: str, chunk_size: int) -> None:
        self.upload_channel = upload_channel
        self.token = token
        self.chunk_size = chunk_size
        intents = discord.Intents.default()
        intents.message_content = True
        self.bot = commands.Bot(command_prefix="!", intents=intents)
        self.bot.event(self.on_ready)
        os.makedirs(config.Cache.DIR, exist_ok=True)
        self.upload_queue = asyncio.Queue()
        self._uploader_task = None
        
        self.ready_event = asyncio.Event()
        
        self.ratelimit_remaining = 5
        self.ratelimit_reset_after = 0.0
        self.ratelimit_timestamp = time.monotonic()
        self.ratelimit_lock = asyncio.Lock()
        
        self.thread_executor = ThreadPoolExecutor(max_workers=32)
        self.http_client = httpx.AsyncClient()

    def _get_cache_key(self, file_id: Any, chunk_idx: int) -> str:
        return f"{str(file_id)}__{chunk_idx}"

    def _chunk_cache_path(self, file_id: str, idx: int) -> str:
        return os.path.join(config.Cache.DIR, f"{file_id}__{idx}.chunk")

    async def start(self):
        logger.info("Scanning cache for pending uploads...")
        try:
            for entry in os.scandir(config.Cache.DIR):
                if entry.is_file() and entry.name.endswith(".chunk"):
                    try:
                        file_id_str, chunk_idx_str = entry.name.rsplit('.', 1)[0].split('__')
                        self.upload_queue.put_nowait((file_id_str, int(chunk_idx_str)))
                    except (ValueError, IndexError):
                        logger.warning(f"Could not parse chunk filename, skipping: {entry.name}")
            if not self.upload_queue.empty():
                logger.info(f"Re-queued {self.upload_queue.qsize()} pending uploads from cache.")
        except Exception as e:
            logger.error(f"Failed to scan cache directory: {e}")
        self._uploader_task = asyncio.create_task(self._upload_worker())
        await self.bot.start(self.token)
        
    async def close(self):
        if self._uploader_task: self._uploader_task.cancel()
        await self.http_client.aclose()
        self.thread_executor.shutdown(wait=False, cancel_futures=True)
        if self.bot.is_ready(): await self.bot.close()

    async def wait_for_uploads(self):
        await self.upload_queue.join()

    async def _get_chunk(self, file: File, chunk_idx: int) -> bytes:
        # THE BEDROCK: Check the on-disk decrypted cache first. This is the new hot path.
        chunk_path = self._chunk_cache_path(str(file.id), chunk_idx)
        if os.path.exists(chunk_path):
            with open(chunk_path, "rb") as f:
                raw_data = f.read()
            if len(raw_data) < self.chunk_size:
                raw_data += b'\x00' * (self.chunk_size - len(raw_data))
            return raw_data

        # COLD READ: If not on disk, it's a cold read from Discord.
        await self.ready_event.wait()
        cmeta = file.chunks.get(str(chunk_idx))
        if cmeta and cmeta.get("msg_id"):
            try:
                msg = await self.channel.fetch_message(cmeta["msg_id"])
                attachment_url = msg.attachments[0].url
                
                async with self.ratelimit_lock:
                    if self.ratelimit_remaining <= 1 and time.monotonic() < self.ratelimit_timestamp + self.ratelimit_reset_after:
                        await asyncio.sleep(self.ratelimit_reset_after)
                
                response = await self.http_client.get(attachment_url)
                response.raise_for_status()
                
                async with self.ratelimit_lock:
                    self.ratelimit_remaining = int(response.headers.get("x-ratelimit-remaining", 5))
                    self.ratelimit_reset_after = float(response.headers.get("x-ratelimit-reset-after", 1.0))
                    self.ratelimit_timestamp = time.monotonic()
                
                enc_data = response.content
                loop = asyncio.get_running_loop()
                raw_data = await loop.run_in_executor(self.thread_executor, crypto.decrypt, enc_data)
                
                # CRITICAL: Save the freshly decrypted data to the on-disk cache for next time.
                with open(chunk_path, "wb") as f:
                    f.write(raw_data)

                if len(raw_data) < self.chunk_size:
                    raw_data += b'\x00' * (self.chunk_size - len(raw_data))
                return raw_data
            except (discord.NotFound, httpx.HTTPStatusError):
                logger.warning(f"Message/Attachment for chunk {chunk_idx} of file {file.id} not found.")
        
        # If all else fails, return an empty block.
        return b'\x00' * self.chunk_size

    async def discord_ranged_download(self, file: File, download_range: list[int]):
        start_byte, end_byte = download_range
        if not file.size or start_byte >= file.size: return b""
        if end_byte >= file.size: end_byte = file.size - 1
        
        start_chunk_idx = start_byte // self.chunk_size
        end_chunk_idx = end_byte // self.chunk_size
        
        # THE LONE WOLF: A simple, unbreakable, one-at-a-time loop.
        payload_parts = []
        for i in range(start_chunk_idx, end_chunk_idx + 1):
            chunk_data = await self._get_chunk(file, i)
            
            start_in_chunk = 0
            if i == start_chunk_idx:
                start_in_chunk = start_byte % self.chunk_size
            
            end_in_chunk = self.chunk_size
            if i == end_chunk_idx:
                end_in_chunk = (end_byte % self.chunk_size) + 1
            
            payload_parts.append(chunk_data[start_in_chunk:end_in_chunk])
        
        return b"".join(payload_parts)

    async def discord_patch(self, file: File, start: int, buf: bytes):
        start_chunk = start // self.chunk_size
        end_chunk = (start + len(buf) - 1) // self.chunk_size
        buf_ptr = 0
        for i in range(start_chunk, end_chunk + 1):
            chunk_data = bytearray(await self._get_chunk(file, i))
            patch_start = 0
            if i == start_chunk: patch_start = start % self.chunk_size
            patch_end = self.chunk_size
            if i == end_chunk: patch_end = ((start + len(buf) - 1) % self.chunk_size) + 1
            len_to_write = patch_end - patch_start
            data_slice = buf[buf_ptr : buf_ptr + len_to_write]
            chunk_data[patch_start : patch_start + len(data_slice)] = data_slice
            
            decrypted_chunk_bytes = bytes(chunk_data)
            chunk_path = self._chunk_cache_path(str(file.id), i)
            
            with open(chunk_path, "wb") as f:
                f.write(decrypted_chunk_bytes)
            
            await self.upload_queue.put((str(file.id), i))
            buf_ptr += len_to_write

    async def discord_discard(self, file: File, size: int, offset: int):
        start_chunk = offset // self.chunk_size
        end_chunk = (offset + size - 1) // self.chunk_size
        needs_save = False
        for i in range(start_chunk, end_chunk + 1):
            chunk_key = str(i)
            if chunk_key in file.chunks:
                del file.chunks[chunk_key]
                needs_save = True
            chunk_path = self._chunk_cache_path(str(file.id), i)
            if os.path.exists(chunk_path): os.remove(chunk_path)
        if needs_save: await file.save(update_fields=['chunks'])

    async def _upload_worker(self):
        await self.ready_event.wait()
        while True:
            try:
                file_id_str, chunk_idx = await self.upload_queue.get()
                chunk_path = self._chunk_cache_path(file_id_str, chunk_idx)
                if not os.path.exists(chunk_path):
                    self.upload_queue.task_done()
                    continue
                
                with open(chunk_path, "rb") as f:
                    decrypted_data = f.read()

                loop = asyncio.get_running_loop()
                enc_data = await loop.run_in_executor(self.thread_executor, crypto.encrypt, decrypted_data)
                
                attempt = 0
                msg = None
                while attempt < 5:
                    try:
                        chunk_io = io.BytesIO(enc_data)
                        discord_name = secrets.token_urlsafe(16)
                        msg = await self.channel.send(file=discord.File(fp=chunk_io, filename=discord_name))
                        break
                    except Exception as e:
                        logger.error(f"Upload worker attempt failed for {file_id_str} chunk {chunk_idx}: {e}")
                        attempt += 1
                        await asyncio.sleep(1 + attempt)
                if msg:
                    try:
                        file = await File.get(id=UUID(file_id_str))
                        file.chunks[str(chunk_idx)] = {"msg_id": msg.id}
                        await file.save(update_fields=['chunks'])
                        os.remove(chunk_path)
                    except DoesNotExist:
                        logger.warning(f"File {file_id_str} was deleted before chunk {chunk_idx} could be uploaded.")
                        if os.path.exists(chunk_path): os.remove(chunk_path)
                self.upload_queue.task_done()
            except asyncio.CancelledError: break
            except Exception as e:
                logger.error(f"Critical error in upload worker: {e}", exc_info=True)
                if 'chunk_idx' in locals(): await self.upload_queue.put((file_id_str, chunk_idx))

    async def on_ready(self):
        chan = self.bot.get_channel(self.upload_channel)
        if chan is None: chan = await self.bot.fetch_channel(self.upload_channel)
        if not isinstance(chan, discord.TextChannel): raise Exception("Channel must be a TextChannel.")
        self.channel = chan
        logger.info(f"Discord bot ready as {self.bot.user}")
        self.ready_event.set()
