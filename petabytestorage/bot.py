import os,io,secrets,asyncio,zstandard,discord,time,psutil
from typing import Any,Set
from uuid import UUID
from collections import OrderedDict
from discord.ext import commands
from .models import File
from .globals import logger
from .utils.crypto import encrypt,decrypt
from . import config

class UploadBot:
    def __init__(self,upload_channel:int,token:str,chunk_size:int)->None:
        self.upload_channel=upload_channel
        self.token=token
        self.chunk_size=chunk_size
        intents=discord.Intents.default()
        intents.message_content=True
        self.bot=commands.Bot(command_prefix="!",intents=intents)
        self.bot.event(self.on_ready)
        os.makedirs(config.Cache.DIR,exist_ok=True)
        self.upload_queue=asyncio.Queue()
        self.db_queue=asyncio.Queue()
        self.read_cache=OrderedDict()
        self.zstd_cctx=zstandard.ZstdCompressor(level=config.Cache.COMPRESSION_LEVEL)
        self.zstd_dctx=zstandard.ZstdDecompressor()
        self._current_usage = self._calculate_initial_usage()
        self.upload_semaphore = asyncio.Semaphore(10)

    def _calculate_initial_usage(self)->int:
        total=0
        try:
            with os.scandir(config.Cache.DIR) as it:
                for entry in it:
                    if entry.is_file(): total+=entry.stat().st_size
        except: pass
        return total

    def _get_ram_usage_percent(self)->float:
        return psutil.virtual_memory().percent

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
            file_id,updates=await self.db_queue.get()
            try:
                file=await File.get(id=file_id)
                file.chunks.update(updates)
                await file.save(update_fields=['chunks'])
            except Exception as e: logger.error(f"DB Error: {e}")
            finally: self.db_queue.task_done()

    async def _upload_to_discord(self,file_id_str:str,chunk_idx:int,data:bytes):
        async with self.upload_semaphore:
            if self.bot.latency < 0.2: await asyncio.sleep(0.3)
            c_data=encrypt(self.zstd_cctx.compress(data))
            attempt=0
            while attempt<5:
                try:
                    msg=await self.channel.send(file=discord.File(fp=io.BytesIO(c_data),filename=secrets.token_urlsafe(16)))
                    await self.db_queue.put((UUID(file_id_str),{str(chunk_idx):{"msg_id":msg.id,"size":len(data)}}))
                    return True
                except:
                    attempt+=1
                    await asyncio.sleep(1+attempt)
            return False

    async def discord_patch(self,file:File,start:int,buf:bytes):
        disk_ratio = self._current_usage / config.Cache.SIZE_BYTES
        ram_percent = self._get_ram_usage_percent()

        s_chunk,e_chunk=start//self.chunk_size,(start+len(buf)-1)//self.chunk_size
        ptr=0
        for i in range(s_chunk,e_chunk+1):
            chunk_data=bytearray(await self._fetch_chunk_from_source(file,i))
            p_s=start%self.chunk_size if i==s_chunk else 0
            p_e=((start+len(buf)-1)%self.chunk_size)+1 if i==e_chunk else self.chunk_size
            chunk_data[p_s:p_s+(p_e-p_s)]=buf[ptr:ptr+(p_e-p_s)]
            final=bytes(chunk_data)

            k=self._get_cache_key(file.id,i)
            self.read_cache[k]=final # Store in RAM buffer

            if disk_ratio >= 0.97 and ram_percent >= 70:
                await self._upload_to_discord(str(file.id), i, final)
            # If Disk has space -> Write to SSD
            elif disk_ratio < 0.98:
                p=self._chunk_cache_path(str(file.id),i)
                if not os.path.exists(p):
                    if (self._current_usage + len(final) > config.Cache.SIZE_BYTES):
                        self._evict_disk_cache(len(final))
                    self._current_usage += len(final)
                with open(p,"wb")as f: f.write(final)
                await self.upload_queue.put((str(file.id),i))

            if len(self.read_cache) >= config.Cache.IN_MEMORY_CHUNK_LIMIT:
                self.read_cache.popitem(last=False)
            ptr+=(p_e-p_s)

    async def _upload_worker(self):
        await self.bot.wait_until_ready()
        while True:
            fid,idx=await self.upload_queue.get()
            try:
                p=self._chunk_cache_path(fid,idx)
                if os.path.exists(p):
                    sz = os.path.getsize(p)
                    with open(p,"rb")as f: d=f.read()
                    if await self._upload_to_discord(fid,idx,d):
                        try:
                            os.remove(p)
                            self._current_usage -= sz
                        except: pass
            except: pass
            finally: self.upload_queue.task_done()

    async def _fetch_chunk_from_source(self,file:File,chunk_idx:int)->bytes:
        key=self._get_cache_key(file.id,chunk_idx)
        if key in self.read_cache:
            self.read_cache.move_to_end(key)
            return self.read_cache[key]
        path=self._chunk_cache_path(str(file.id),chunk_idx)
        if os.path.exists(path):
            with open(path,"rb")as f: return f.read()
        cmeta=file.chunks.get(str(chunk_idx))
        if cmeta and cmeta.get("msg_id"):
            try:
                msg=await self.channel.fetch_message(cmeta["msg_id"])
                data=self.zstd_dctx.decompress(decrypt(await msg.attachments[0].read()))
                if self._current_usage + len(data) > config.Cache.SIZE_BYTES:
                    self._evict_disk_cache(len(data))
                with open(path,"wb")as f: f.write(data)
                self._current_usage += len(data)
                return data
            except: pass
        return b'\x00'*self.chunk_size

    async def discord_ranged_download(self,file:File,download_range:list[int]):
        s_byte,e_byte=download_range
        if not file.size or s_byte>=file.size:return b""
        if e_byte>=file.size:e_byte=file.size-1
        s_chunk,e_chunk=s_byte//self.chunk_size,e_byte//self.chunk_size
        buf=io.BytesIO()
        for i in range(s_chunk,e_chunk+1):
            chunk_data=await self._fetch_chunk_from_source(file,i)
            s_in=s_byte%self.chunk_size if i==s_chunk else 0
            e_in=(e_byte%self.chunk_size)+1 if i==e_chunk else self.chunk_size
            buf.write(chunk_data[s_in:e_in])
        return buf.getvalue()

    async def discord_discard(self,file:File,size:int,offset:int):
        s_chunk,e_chunk=offset//self.chunk_size,(offset+size-1)//self.chunk_size
        for i in range(s_chunk,e_chunk+1):
            self.read_cache.pop(self._get_cache_key(file.id,i),None)
            p=self._chunk_cache_path(str(file.id),i)
            if os.path.exists(p):
                try:
                    sz = os.path.getsize(p)
                    os.remove(p)
                    self._current_usage -= sz
                except: pass

    def _get_cache_key(self,file_id:Any,chunk_idx:int)->str:
        return f"{str(file_id)}__{chunk_idx}"

    def _chunk_cache_path(self,file_id:str,idx:int)->str:
        return os.path.join(config.Cache.DIR,f"{file_id}__{idx}.chunk")

    async def start(self):
        self._uploader_task=asyncio.create_task(self._upload_worker())
        self._db_worker_task=asyncio.create_task(self._db_background_worker())
        await self.bot.start(self.token)

    async def on_ready(self):
        self.channel=self.bot.get_channel(self.upload_channel) or await self.bot.fetch_channel(self.upload_channel)
        logger.info(f"Bot Active: {self.bot.user}")

    async def wait_for_uploads(self):
        await self.upload_queue.join()
        await self.db_queue.join()

    async def close(self):
        if self._uploader_task: self._uploader_task.cancel()
        if self._db_worker_task: self._db_worker_task.cancel()
        await self.bot.close()
