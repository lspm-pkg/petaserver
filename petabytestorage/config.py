import os
from typing import cast
from dotenv import load_dotenv
from base64 import b16decode
from pathlib import Path
import toml

load_dotenv()
config = toml.loads(Path("config.toml").read_text())

if not config.get("network"): config["network"] = {}
if not config.get("uploads"): config["uploads"] = {"discord": {}}
if not config.get("auth"): config["auth"] = {}
if not config.get("cache"): config["cache"] = {}
if not cast(dict, config.get("uploads")).get("discord"): config["uploads"]["discord"] = {}

SESSION_SECRET: str = cast(str, os.getenv("SESSION_SECRET"))
ENCRYPTION_KEY = b16decode(cast(str, os.getenv("ENCRYPTION_KEY")), casefold=True)

class Network:
    HOST: str = config["network"].get("host", "0.0.0.0")
    PORT: int = config["network"].get("port", "8080")

class Cache:
    DIR: str = config["cache"].get("dir", "petafuse_cache")

class Upload:
    CHUNK_SIZE: int = cast(int, config["uploads"].get("chunk_size", 8388608))
    MAX_REQUESTS_PER_SECOND: int = config["uploads"].get("max_requests_per_second", 40)
    class Discord:
        UPLOAD_CHANNEL_ID = cast(int, config["uploads"]["discord"].get("channel_id"))
        TOKEN = cast(str, os.getenv("DISCORD_BOT_TOKEN"))

class Auth:
    REGISTRATION_ENABLED: bool = config["auth"].get("registration_enabled", True)
    ONE_ACCOUNT_MODE: bool = config["auth"].get("one_account_mode", False)

if not Upload.Discord.TOKEN: raise RuntimeError("Missing DISCORD_BOT_TOKEN in .env")
if not Upload.Discord.UPLOAD_CHANNEL_ID: raise RuntimeError("Missing DISCORD_UPLOAD_CHANNEL_ID in config.toml")
if not SESSION_SECRET: raise RuntimeError("Missing SESSION_SECRET in .env")
if not ENCRYPTION_KEY: raise RuntimeError("Missing ENCRYPTION_KEY in .env")
if len(ENCRYPTION_KEY) != 32: raise RuntimeError(f"ENCRYPTION_KEY must be 32 bytes encoded in hex, not {len(ENCRYPTION_KEY)} bytes")
