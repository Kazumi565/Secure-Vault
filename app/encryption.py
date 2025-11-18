from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def pad(data: bytes) -> bytes:
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)


def encrypt_file(file_data: bytes, key: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(file_data))
    return iv + encrypted  # prepend IV so we can use it during decryption


def generate_key() -> bytes:
    return get_random_bytes(32)  # AES-256 = 32 bytes key
