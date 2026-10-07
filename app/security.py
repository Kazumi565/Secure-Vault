import hashlib
import secrets

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

hasher = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def random_token():
    return secrets.token_urlsafe(32)


def hash_password(value):
    return hasher.hash(value)


def verify_password(value, hashed):
    try:
        if hashed.startswith(("$2b$", "$2a$", "$2y$")):
            return bcrypt.checkpw(value.encode()[:72], hashed.encode())
        return hasher.verify(hashed, value)
    except (VerificationError, ValueError, TypeError):
        return False


class Crypto:
    def __init__(self, settings):
        keys = [settings.master_key] + [k.strip() for k in settings.previous_master_keys.split(",") if k.strip()]
        self.keys = MultiFernet([Fernet(k.encode()) for k in keys])

    def wrap(self, data):
        return self.keys.encrypt(data).decode()

    def unwrap(self, value):
        return self.keys.decrypt(value.encode())

    def encrypt(self, data, storage_key):
        key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(key).encrypt(nonce, data, storage_key.encode()), self.wrap(key)

    def decrypt(self, blob, wrapped_key, storage_key, format="gcm-v2"):
        key = self.unwrap(wrapped_key)
        if format == "eax-v1":
            from Crypto.Cipher import AES

            return AES.new(key, AES.MODE_EAX, nonce=blob[:16]).decrypt_and_verify(blob[32:], blob[16:32])
        return AESGCM(key).decrypt(blob[:12], blob[12:], storage_key.encode())
