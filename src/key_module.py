"""
Key Generation Module (Section 7.2 & Level 2 DFD of Project Synopsis)
---------------------------------------------------------------------
Generates and manages secure cryptographic keys required for AES encryption
and decryption.

Supports:
1. AES key lengths: 128-bit (16 bytes), 192-bit (24 bytes), and 256-bit (32 bytes)
   as specified in the Literature Review (Section 5).
2. Password-Based Key Derivation (PBKDF2-HMAC-SHA256) with cryptographic salt
   (matching the Level 2 DFD: Password Input -> AES Key Generation Module).
3. Random Cryptographic Key Generation & Key File (.key) Export/Import.
"""

import base64
import json
import os
import secrets
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


VALID_KEY_BITS = {
    128: 16,  # 128-bit = 16 bytes (10 AES rounds)
    192: 24,  # 192-bit = 24 bytes (12 AES rounds)
    256: 32,  # 256-bit = 32 bytes (14 AES rounds)
}

DEFAULT_PBKDF2_ITERATIONS = 200_000
SALT_SIZE_BYTES = 16


class KeyManagementError(Exception):
    """Raised when key generation, derivation, or loading fails."""
    pass


@dataclass
class DerivedKeySet:
    """
    Holds the derived AES encryption key and HMAC authentication key,
    along with the salt and key bit length.
    """
    encryption_key: bytes
    hmac_key: bytes
    salt: bytes
    key_bits: int


class KeyGenerationModule:
    """
    Handles AES key generation, PBKDF2 password key derivation, and .key file export/import.
    """

    @staticmethod
    def validate_key_bits(key_bits: int) -> int:
        """Ensures the requested AES key size is 128, 192, or 256 bits."""
        if key_bits not in VALID_KEY_BITS:
            raise KeyManagementError(
                f"Invalid AES key size: {key_bits}. Supported sizes are 128, 192, or 256 bits."
            )
        return VALID_KEY_BITS[key_bits]

    @classmethod
    def derive_keys_from_password(
        cls,
        password: str,
        key_bits: int = 256,
        salt: bytes = None,
        iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    ) -> DerivedKeySet:
        """
        Derives both an AES encryption key (128/192/256-bit) and a 256-bit HMAC key
        from a user password or raw secret string using PBKDF2-HMAC-SHA256.
        """
        if not password or len(password.strip()) == 0:
            raise KeyManagementError("Password / secret key cannot be empty.")

        aes_key_len = cls.validate_key_bits(key_bits)
        hmac_key_len = 32  # 256-bit key for HMAC-SHA256 integrity authentication

        if salt is None:
            salt = secrets.token_bytes(SALT_SIZE_BYTES)
        elif len(salt) != SALT_SIZE_BYTES:
            raise KeyManagementError(f"Invalid salt length: expected {SALT_SIZE_BYTES} bytes.")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=aes_key_len + hmac_key_len,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        key_material = kdf.derive(password.encode("utf-8"))
        encryption_key = key_material[:aes_key_len]
        hmac_key = key_material[aes_key_len:]

        return DerivedKeySet(
            encryption_key=encryption_key,
            hmac_key=hmac_key,
            salt=salt,
            key_bits=key_bits,
        )

    @classmethod
    def generate_random_passkey(cls, key_bits: int = 256) -> str:
        """
        Generates a cryptographically strong random Base64 key string suitable for
        high-entropy encryption or saving to a .key file.
        """
        key_bytes_len = cls.validate_key_bits(key_bits)
        raw_bytes = secrets.token_bytes(key_bytes_len)
        return base64.urlsafe_b64encode(raw_bytes).decode("ascii")

    @classmethod
    def save_key_file(cls, file_path: str, passkey: str, key_bits: int = 256) -> str:
        """
        Saves a generated cryptographic key and its metadata to a JSON .key file.
        """
        cls.validate_key_bits(key_bits)
        if not passkey:
            raise KeyManagementError("Cannot save an empty key.")

        payload = {
            "application": "AES Secure File Encryption System",
            "algorithm": f"AES-{key_bits}",
            "key_bits": key_bits,
            "key_secret": passkey,
        }
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return file_path

    @classmethod
    def load_key_file(cls, file_path: str) -> Tuple[str, int]:
        """
        Loads a cryptographic key string and its bit size from a .key file.
        """
        if not os.path.exists(file_path):
            raise KeyManagementError(f"Key file not found: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            key_secret = data.get("key_secret")
            key_bits = int(data.get("key_bits", 256))
            if not key_secret:
                raise KeyManagementError("Invalid key file: missing 'key_secret' field.")
            cls.validate_key_bits(key_bits)
            return key_secret, key_bits
        except json.JSONDecodeError as exc:
            raise KeyManagementError(f"Corrupted or invalid .key file format: {exc}") from exc
