from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..config import ENCRYPTION_KEY
import secrets

def encrypt(chunk: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(ENCRYPTION_KEY).encrypt(nonce, chunk, b"")

def decrypt(chunk: bytes) -> bytes:
    return AESGCM(ENCRYPTION_KEY).decrypt(chunk[:12], chunk[12:], b"")
