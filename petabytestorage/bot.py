import os
import io
import secrets
import asyncio
from typing import Any, Set
from uuid import UUID
from collections import OrderedDict
import zstandard
from discord.ext import commands
import discord
from tortoise.exceptions import DoesNotExist
from .models import File
from .globals import logger
from .utils.crypto import encrypt, decrypt
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
        self.read_cache = OrderedDict()
        self.cache_limit = config.Cache.IN_MEMORY_CHUNK_LIMIT
        self.zstd_cctx = zstandard.ZstdCompressor(level=config.Cache.COMPRESSION_LEVEL)
        self.zstd_dctx = zstandard.ZstdDecompressor()
        self.primed_files: Set[UUID] = set()

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
        if self._uploader_task:
            self._uploader_task.cancel()
        if self.bot.is_ready():
            await self.bot.close()

    async def wait_for_uploads(self):
        await self.upload_queue.join()

    async def _fetch_chunk_from_source(self, file: File, chunk_idx: int) -> bytes:
        cache_key = self._get_cache_key(file.id, chunk_idx)
        if cache_key in self.read_cache:
            self.read_cache.move_to_end(cache_key)
            return self.read_cache[cache_key]

        on_disk_cache_path = self._chunk_cache_path(str(file.id), chunk_idx)
        if os.path.exists(on_disk_cache_path):
            with open(on_disk_cache_path, "rb") as f:
                data = f.read()
            if len(data) < self.chunk_size:
                data += b'\x00' * (self.chunk_size - len(data))
            return data

        cmeta = file.chunks.get(str(chunk_idx))
        if cmeta and cmeta.get("msg_id"):
            try:
                msg = await self.channel.fetch_message(cmeta["msg_id"])
                encrypted_compressed_data = await msg.attachments[0].read()
                compressed_data = decrypt(encrypted_compressed_data)
                data = self.zstd_dctx.decompress(compressed_data)

                if len(data) < self.chunk_size:
                    data += b'\x00' * (self.chunk_size - len(data))
                
                with open(on_disk_cache_path, "wb") as f: f.write(data)
                return data
            except discord.NotFound:
                logger.warning(f"Message for chunk {chunk_idx} of file {file.id} not found. Returning sparse data.")
            except zstandard.ZstdError:
                 logger.warning(f"Zstd decompression failed for chunk {chunk_idx} of file {file.id}. Returning sparse data.")
        
        return b'\x00' * self.chunk_size

    async def _prime_file_cache(self, file: File):
        if file.id in self.primed_files:
            return
        
        logger.info(f"Priming cache for file {file.id}...")
        try:
            chunk_zero_data = await self._fetch_chunk_from_source(file, 0)
            cache_key = self._get_cache_key(file.id, 0)
            if len(self.read_cache) >= self.cache_limit:
                self.read_cache.popitem(last=False)
            self.read_cache[cache_key] = chunk_zero_data
            self.primed_files.add(file.id)
            logger.info(f"Cache priming successful for file {file.id}.")
        except Exception as e:
            logger.error(f"Failed to prime cache for file {file.id}: {e}")

    async def discord_ranged_download(self, file: File, download_range: list[int]):
        if file.id not in self.primed_files:
            await self._prime_file_cache(file)
            
        start_byte, end_byte = download_range
        if not file.size or start_byte >= file.size: return b""
        if end_byte >= file.size: end_byte = file.size - 1
        
        start_chunk = start_byte // self.chunk_size
        end_chunk = end_byte // self.chunk_size
        buf = io.BytesIO()

        for i in range(start_chunk, end_chunk + 1):
            chunk_data = await self._fetch_chunk_from_source(file, i)
            start_in_chunk = 0
            if i == start_chunk:
                start_in_chunk = start_byte % self.chunk_size
            
            end_in_chunk = self.chunk_size
            if i == end_chunk:
                end_in_chunk = (end_byte % self.chunk_size) + 1
            
            buf.write(chunk_data[start_in_chunk:end_in_chunk])
        return buf.getvalue()

    async def discord_patch(self, file: File, start: int, buf: bytes):
        start_chunk = start // self.chunk_size
        end_chunk = (start + len(buf) - 1) // self.chunk_size
        buf_ptr = 0

        for i in range(start_chunk, end_chunk + 1):
            chunk_data = bytearray(await self._fetch_chunk_from_source(file, i))
            
            patch_start = 0
            if i == start_chunk: patch_start = start % self.chunk_size
            
            patch_end = self.chunk_size
            if i == end_chunk: patch_end = ((start + len(buf) - 1) % self.chunk_size) + 1
            
            len_to_write = patch_end - patch_start
            data_slice = buf[buf_ptr : buf_ptr + len_to_write]
            
            chunk_data[patch_start : patch_start + len(data_slice)] = data_slice
            
            on_disk_cache_path = self._chunk_cache_path(str(file.id), i)
            with open(on_disk_cache_path, "wb") as f: f.write(chunk_data)

            cache_key = self._get_cache_key(file.id, i)
            if len(self.read_cache) >= self.cache_limit:
                self.read_cache.popitem(last=False)
            self.read_cache[cache_key] = bytes(chunk_data)
            
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
            
            cache_key = self._get_cache_key(file.id, i)
            self.read_cache.pop(cache_key, None)
            
            on_disk_cache_path = self._chunk_cache_path(str(file.id), i)
            if os.path.exists(on_disk_cache_path): os.remove(on_disk_cache_path)
        if needs_save:
            await file.save(update_fields=['chunks'])

    async def _upload_worker(self):
        await self.bot.wait_until_ready()
        while True:
            try:
                file_id_str, chunk_idx = await self.upload_queue.get()
                on_disk_cache_path = self._chunk_cache_path(file_id_str, chunk_idx)

                if not os.path.exists(on_disk_cache_path):
                    self.upload_queue.task_done()
                    continue

                with open(on_disk_cache_path, "rb") as f:
                    plaintext_data = f.read()
                
                compressed_data = self.zstd_cctx.compress(plaintext_data)
                encrypted_compressed_data = encrypt(compressed_data)
                
                attempt = 0
                msg = None
                while attempt < 5:
                    try:
                        chunk_io = io.BytesIO(encrypted_compressed_data)
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
                        file.chunks[str(chunk_idx)] = {"msg_id": msg.id, "size": len(plaintext_data)}
                        await file.save(update_fields=['chunks'])
                        os.remove(on_disk_cache_path)
                    except DoesNotExist:
                        logger.warning(f"File {file_id_str} was deleted before chunk {chunk_idx} could be uploaded.")
                        if os.path.exists(on_disk_cache_path):
                            os.remove(on_disk_cache_path)
                
                self.upload_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Critical error in upload worker: {e}", exc_info=True)
                if 'chunk_idx' in locals():
                    await self.upload_queue.put((file_id_str, chunk_idx))

    async def on_ready(self):
        chan = self.bot.get_channel(self.upload_channel)
        if chan is None: chan = await self.bot.fetch_channel(self.upload_channel)
        if not isinstance(chan, discord.TextChannel): raise Exception("Channel must be a TextChannel.")
        self.channel = chan
        logger.info(f"Discord bot ready as {self.bot.user}")
