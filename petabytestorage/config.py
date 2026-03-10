from typing import cast
from dotenv import load_dotenv
from base64 import b16decode
from pathlib import Path
import os, toml

load_dotenv()
config = toml.loads(Path("config.toml").read_text())

if not config.get("network"): config["network"] = {}
if not config.get("uploads"): config["uploads"] = {"discord": {}}
if not config.get("auth"): config["auth"] = {}
if not config.get("cache"): config["cache"] = {}

SESSION_SECRET: str = cast(str, os.getenv("SESSION_SECRET"))
ENCRYPTION_KEY = b16decode(cast(str, os.getenv("ENCRYPTION_KEY")), casefold=True)

class Network:
    HOST: str = config["network"].get("host", "0.0.0.0")
    PORT: int = config["network"].get("port", 8080)

class Database:
    URL: str = cast(str, os.getenv("MARIADB_URL"))

class Upload:
    CHUNK_SIZE: int = cast(int, config["uploads"].get("chunk_size", 8388608))
    class Discord:
        UPLOAD_CHANNEL_ID = cast(int, config["uploads"]["discord"].get("channel_id"))
        TOKEN = cast(str, os.getenv("DISCORD_BOT_TOKEN"))

class Auth:
    REGISTRATION_ENABLED: bool = config["auth"].get("registration_enabled", True)
    ONE_ACCOUNT_MODE: bool = config["auth"].get("one_account_mode", False)

class Cache:
    DIR: str = config["cache"].get("dir", "petafuse_cache")
    UPLOAD_CONCURRENCY: int = config["cache"].get("upload_concurrency", 3)
    DEBOUNCE_SECONDS: float = config["cache"].get("debounce_seconds", 0.5)
    IN_MEMORY_CHUNK_LIMIT: int = config["cache"].get("in_memory_chunk_limit", 128)
    COMPRESSION_LEVEL: int = config["cache"].get("compression_level", 3)
    SIZE_GB: float = float(config["cache"].get("cache_size_gb", 10.0))
    SIZE_BYTES: int = int(SIZE_GB * 1024**3)

if not Upload.Discord.TOKEN: raise RuntimeError("Missing DISCORD_BOT_TOKEN")
if not Upload.Discord.UPLOAD_CHANNEL_ID: raise RuntimeError("Missing DISCORD_UPLOAD_CHANNEL_ID")
if not SESSION_SECRET: raise RuntimeError("Missing SESSION_SECRET")
if not ENCRYPTION_KEY: raise RuntimeError("Missing ENCRYPTION_KEY")
if not Database.URL: raise RuntimeError("Missing MARIADB_URL")
