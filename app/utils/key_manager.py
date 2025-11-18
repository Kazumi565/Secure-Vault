"""Utilities for envelope-encrypting per-file data keys."""
from __future__ import annotations

import base64
import logging
import os
from typing import Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.fernet import Fernet, InvalidToken
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)


def _require_data_key_strategy() -> Tuple[str | None, str | None]:
    kms_key_id = os.getenv("KMS_KEY_ID")
    master_key = os.getenv("MASTER_KEY")
    if kms_key_id:
        return kms_key_id, None
    if master_key:
        return None, master_key
    raise RuntimeError(
        "Either KMS_KEY_ID (preferred) or MASTER_KEY must be configured for encryption"
    )


def _kms_client():
    region = os.getenv("AWS_REGION") or "us-east-1"
    return boto3.client("kms", region_name=region)


def generate_encrypted_data_key() -> Tuple[bytes, str]:
    """Generate a plaintext AES-256 key and an encrypted blob for storage."""
    kms_key_id, master_key = _require_data_key_strategy()

    if kms_key_id:
        try:
            response = _kms_client().generate_data_key(KeyId=kms_key_id, KeySpec="AES_256")
        except (ClientError, BotoCoreError) as exc:
            logger.error("Failed to generate KMS data key: %s", exc)
            raise
        plaintext_key = response["Plaintext"]
        ciphertext = base64.b64encode(response["CiphertextBlob"]).decode("utf-8")
        return plaintext_key, ciphertext

    fernet = Fernet(master_key.encode())
    plaintext_key = get_random_bytes(32)
    encrypted = fernet.encrypt(plaintext_key)
    ciphertext = base64.b64encode(encrypted).decode("utf-8")
    return plaintext_key, ciphertext


def decrypt_data_key(encrypted_data_key: str) -> bytes:
    kms_key_id = os.getenv("KMS_KEY_ID")
    master_key = os.getenv("MASTER_KEY")
    if not encrypted_data_key:
        raise RuntimeError("No encrypted data key supplied")

    data = base64.b64decode(encrypted_data_key)

    if kms_key_id:
        try:
            response = _kms_client().decrypt(CiphertextBlob=data)
        except (ClientError, BotoCoreError) as exc:
            logger.error("Failed to decrypt KMS data key: %s", exc)
            raise
        return response["Plaintext"]

    if master_key:
        try:
            fernet = Fernet(master_key.encode())
            return fernet.decrypt(data)
        except InvalidToken as exc:
            logger.error("Invalid Fernet token for encrypted data key: %s", exc)
            raise RuntimeError("Encrypted key could not be decrypted") from exc

    raise RuntimeError("MASTER_KEY or KMS_KEY_ID must be configured to decrypt data keys")
