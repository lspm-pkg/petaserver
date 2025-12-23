from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..config import ENCRYPTION_KEY
import secrets
import zstandard as zstd

def encrypt(chunk: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(ENCRYPTION_KEY).encrypt(nonce, chunk, b"")

def decrypt(chunk: bytes) -> bytes:
    return AESGCM(ENCRYPTION_KEY).decrypt(chunk[:12], chunk[12:], b"")

def compress_and_encrypt(chunk: bytes) -> bytes:
    compressed_data = zstd.compress(chunk)
    return encrypt(compressed_data)

def decrypt_and_decompress(chunk: bytes) -> bytes:
    decrypted_data = decrypt(chunk)
    return zstd.decompress(decrypted_data)
