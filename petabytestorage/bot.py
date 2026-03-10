import os, io, secrets, asyncio, zstandard, discord, time, psutil, aiofiles
from typing import Any, Dict, List
from uuid import UUID
from collections import OrderedDict
from discord.ext import commands
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
        self.db_queue = asyncio.Queue()
        self.read_cache = OrderedDict()
        self.zstd_cctx = zstandard.ZstdCompressor(level=config.Cache.COMPRESSION_LEVEL)
        self.zstd_dctx = zstandard.ZstdDecompressor()
        self._current_usage = self._calculate_initial_usage()
        self.upload_semaphore = asyncio.Semaphore(20)
        self.db_batch = {}
        self._uploader_task = None
        self._db_worker_task = None

    def _calculate_initial_usage(self) -> int:
        total = 0
        try:
            with os.scandir(config.Cache.DIR) as it:
                for entry in it:
                    if entry.is_file(): total += entry.stat().st_size
        except: pass
        return total

    def _evict_disk_cache(self, required_bytes: int):
        files = []
        try:
            with os.scandir(config.Cache.DIR) as it:
                for entry in it:
                    if entry.is_file() and entry.name.endswith(".chunk"):
                        files.append((entry.path, entry.stat().st_mtime))
            files.sort(key=lambda x: x[1])
            for path, _ in files:
                if self._current_usage + required_bytes < config.Cache.SIZE_BYTES:
                    break
                try:
                    sz = os.path.getsize(path)
                    os.remove(path)
                    self._current_usage -= sz
                except: pass
        except: pass

    async def _db_background_worker(self):
        while True:
            await asyncio.sleep(0.5)
            if not self.db_batch: continue
            processing = self.db_batch.copy()
            self.db_batch.clear()
            for file_id, updates in processing.items():
                try:
                    file = await File.get(id=file_id)
                    file.chunks.update(updates)
                    await file.save(update_fields=['chunks'])
                except: pass
                finally:
                    for _ in range(len(updates)): self.db_queue.task_done()

    async def _upload_to_discord(self, file_id_str: str, chunk_idx: int, compressed_data: bytes, original_size: int):
        async with self.upload_semaphore:
            payload = encrypt(compressed_data)
            for attempt in range(3):
                try:
                    msg = await self.channel.send(file=discord.File(fp=io.BytesIO(payload), filename=secrets.token_urlsafe(16)))
                    fid = UUID(file_id_str)
                    if fid not in self.db_batch: self.db_batch[fid] = {}
                    self.db_batch[fid][str(chunk_idx)] = {"msg_id": msg.id, "size": original_size}
                    await self.db_queue.put(True)
                    return True
                except: await asyncio.sleep(0.2 * attempt)
            return False

    async def discord_patch(self, file: File, start: int, buf: bytes):
        s_chunk, e_chunk = start // self.chunk_size, (start + len(buf) - 1) // self.chunk_size
        ptr = 0
        tasks = []
        for i in range(s_chunk, e_chunk + 1):
            p_s = start % self.chunk_size if i == s_chunk else 0
            p_e = ((start + len(buf) - 1) % self.chunk_size) + 1 if i == e_chunk else self.chunk_size
            tasks.append(self._apply_chunk_patch(file, i, buf[ptr:ptr+(p_e-p_s)], p_s, p_e))
            ptr += (p_e - p_s)
        await asyncio.gather(*tasks)

    async def _apply_chunk_patch(self, file, idx, patch_data, p_s, p_e):
        raw_chunk = bytearray(await self._fetch_chunk_from_source(file, idx))
        raw_chunk[p_s:p_e] = patch_data
        final_raw = bytes(raw_chunk)
        compressed_payload = self.zstd_cctx.compress(final_raw)
        key = self._get_cache_key(file.id, idx)
        self.read_cache[key] = final_raw
        self.read_cache.move_to_end(key)
        if len(self.read_cache) > config.Cache.IN_MEMORY_CHUNK_LIMIT: self.read_cache.popitem(last=False)
        path = self._chunk_cache_path(str(file.id), idx)
        new_size = len(compressed_payload)
        old_size = os.path.getsize(path) if os.path.exists(path) else 0
        if self._current_usage - old_size + new_size > config.Cache.SIZE_BYTES:
            self._evict_disk_cache(new_size)
        async with aiofiles.open(path, "wb") as f: 
            await f.write(compressed_payload)
        self._current_usage = self._current_usage - old_size + new_size
        await self.upload_queue.put((str(file.id), idx, len(final_raw)))

    async def _upload_worker(self):
        await self.bot.wait_until_ready()
        while True:
            fid, idx, orig_size = await self.upload_queue.get()
            try:
                p = self._chunk_cache_path(fid, idx)
                if os.path.exists(p):
                    async with aiofiles.open(p, "rb") as f: 
                        compressed_data = await f.read()
                    await self._upload_to_discord(fid, idx, compressed_data, orig_size)
            finally: self.upload_queue.task_done()

    async def _fetch_chunk_from_source(self, file: File, chunk_idx: int) -> bytes:
        key = self._get_cache_key(file.id, chunk_idx)
        if key in self.read_cache:
            self.read_cache.move_to_end(key)
            return self.read_cache[key]
        path = self._chunk_cache_path(str(file.id), chunk_idx)
        if os.path.exists(path):
            os.utime(path, None)
            async with aiofiles.open(path, "rb") as f:
                compressed_data = await f.read()
                data = self.zstd_dctx.decompress(compressed_data)
                self.read_cache[key] = data
                return data
        cmeta = file.chunks.get(str(chunk_idx))
        if cmeta and cmeta.get("msg_id"):
            try:
                msg = await self.channel.fetch_message(cmeta["msg_id"])
                compressed_payload = decrypt(await msg.attachments[0].read())
                if self._current_usage + len(compressed_payload) > config.Cache.SIZE_BYTES:
                    self._evict_disk_cache(len(compressed_payload))
                async with aiofiles.open(path, "wb") as f: 
                    await f.write(compressed_payload)
                self._current_usage += len(compressed_payload)
                data = self.zstd_dctx.decompress(compressed_payload)
                self.read_cache[key] = data
                return data
            except: pass
        return b'\x00' * self.chunk_size

    async def discord_ranged_download(self, file: File, download_range: list[int]):
        s_byte, e_byte = download_range[0], min(download_range[1], file.size - 1)
        if s_byte >= file.size: return b""
        s_chunk, e_chunk = s_byte // self.chunk_size, e_byte // self.chunk_size
        chunks = await asyncio.gather(*[self._fetch_chunk_from_source(file, i) for i in range(s_chunk, e_chunk + 1)])
        buf = io.BytesIO()
        for i, chunk_data in enumerate(chunks):
            curr_idx = s_chunk + i
            s_in = s_byte % self.chunk_size if curr_idx == s_chunk else 0
            e_in = (e_byte % self.chunk_size) + 1 if curr_idx == e_chunk else self.chunk_size
            buf.write(chunk_data[s_in:e_in])
        return buf.getvalue()

    async def discord_discard(self, file: File, size: int, offset: int):
        s_chunk, e_chunk = offset // self.chunk_size, (offset + size - 1) // self.chunk_size
        for i in range(s_chunk, e_chunk + 1):
            self.read_cache.pop(self._get_cache_key(file.id, i), None)
            p = self._chunk_cache_path(str(file.id), i)
            if os.path.exists(p):
                try:
                    self._current_usage -= os.path.getsize(p)
                    os.remove(p)
                except: pass

    def _get_cache_key(self, file_id: Any, chunk_idx: int) -> str:
        return f"{str(file_id)}__{chunk_idx}"

    def _chunk_cache_path(self, file_id: str, idx: int) -> str:
        return os.path.join(config.Cache.DIR, f"{file_id}__{idx}.chunk")

    async def start(self):
        self._uploader_task = asyncio.create_task(self._upload_worker())
        self._db_worker_task = asyncio.create_task(self._db_background_worker())
        await self.bot.start(self.token)

    async def on_ready(self):
        self.channel = self.bot.get_channel(self.upload_channel) or await self.bot.fetch_channel(self.upload_channel)

    async def wait_for_uploads(self):
        await self.upload_queue.join()
        await self.db_queue.join()

    async def close(self):
        if self._uploader_task: self._uploader_task.cancel()
        if self._db_worker_task: self._db_worker_task.cancel()
        await self.bot.close()
