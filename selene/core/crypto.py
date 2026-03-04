"""
selene/core/crypto.py
Enkripsi AES-256-GCM + key derivation PBKDF2.
"""

import os
import gzip
import struct
import hashlib
import secrets
from pathlib import Path
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

SALT_SIZE   = 32
NONCE_SIZE  = 12
KEY_SIZE    = 32
KDF_ITER    = 480_000
MAGIC       = b"SLNE"
FORMAT_VER  = b"\x03"

def _need_crypto():
    if not HAS_CRYPTO:
        raise RuntimeError(
            "Library 'cryptography' tidak tersedia.\n"
            "Jalankan: pip install -r requirements.txt"
        )

def derive_key(password: str, salt: bytes) -> bytes:
    _need_crypto()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITER,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt(data: bytes, password: str, compress: bool = True) -> bytes:
    _need_crypto()
    salt  = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key   = derive_key(password, salt)
    orig  = len(data)
    if compress:
        payload = gzip.compress(data, compresslevel=6)
        cflag   = b"\x01"
    else:
        payload = data
        cflag   = b"\x00"
    ct = AESGCM(key).encrypt(nonce, payload, None)
    return MAGIC + FORMAT_VER + salt + struct.pack(">Q", orig) + cflag + nonce + ct

def decrypt(data: bytes, password: str) -> bytes:
    _need_crypto()
    MIN = 4 + 1 + SALT_SIZE + 8 + 1 + NONCE_SIZE + 16
    if len(data) < MIN:
        raise ValueError("Data terlalu kecil.")
    off  = 0
    magic = data[off:off+4]; off += 4
    if magic != MAGIC:
        raise ValueError("Bukan file enkripsi Selene yang valid.")
    off  += 1  # version
    salt  = data[off:off+SALT_SIZE]; off += SALT_SIZE
    orig  = struct.unpack(">Q", data[off:off+8])[0]; off += 8
    cflag = data[off:off+1]; off += 1
    nonce = data[off:off+NONCE_SIZE]; off += NONCE_SIZE
    ct    = data[off:]
    key   = derive_key(password, salt)
    try:
        payload = AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Dekripsi gagal — password salah atau data korup.")
    if cflag == b"\x01":
        try:    return gzip.decompress(payload)
        except Exception: raise ValueError("Dekompresi gagal.")
    return payload

def hash_file(path: Path) -> Optional[dict]:
    """Hash file dengan SHA-256 dan BLAKE2b. Returns None jika error."""
    try:
        st = path.stat()
        if st.st_size > 100 * 1024 * 1024:
            return {"sha256":None,"blake2b":None,"size":st.st_size,
                    "mtime":st.st_mtime,"skipped":"too_large"}
        h1 = hashlib.sha256()
        h2 = hashlib.blake2b()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h1.update(chunk)
                h2.update(chunk)
        return {"sha256":h1.hexdigest(),"blake2b":h2.hexdigest(),
                "size":st.st_size,"mtime":st.st_mtime}
    except PermissionError:
        return {"error":"permission_denied","size":0,"mtime":0}
    except OSError as e:
        return {"error":str(e),"size":0,"mtime":0}

def secure_random_password(length: int = 20, symbols: bool = True) -> str:
    import string
    chars = string.ascii_letters + string.digits
    if symbols: chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
    ]
    if symbols: pwd.append(secrets.choice("!@#$%^&*()"))
    pwd += [secrets.choice(chars) for _ in range(length - len(pwd))]
    import random
    random.SystemRandom().shuffle(pwd)
    return "".join(pwd)
