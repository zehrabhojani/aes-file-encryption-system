"""
Encryption Module (Section 7.2 & Level 2 DFD of Project Synopsis)
-----------------------------------------------------------------
Converts plaintext files into encrypted ciphertext using the Advanced Encryption
Standard (AES) algorithm in CBC mode with PKCS7 padding and Encrypt-then-MAC
(HMAC-SHA256) authentication.

Features:
- Supports AES-128, AES-192, and AES-256 key lengths.
- Chunked streaming encryption for fast, low-memory processing of large files (TC-06).
- Preserves original file metadata and computes SHA-256 hashes.
- Emits step-by-step status messages as specified in Section 10 (Expected Output).
"""

import json
import os
import secrets
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.input_module import FileMetadata, InputModule
from src.key_module import DerivedKeySet, KeyGenerationModule


MAGIC_HEADER = b"AESSEC01"  # 8-byte file signature for AES Secure File System v1
AES_BLOCK_BYTES = 16        # 128-bit block size standard for AES
HMAC_DIGEST_BYTES = 32      # 256-bit HMAC-SHA256 authentication tag
CHUNK_SIZE = 64 * 1024      # 64 KB streaming chunk size


class EncryptionError(Exception):
    """Raised when an error occurs during file encryption."""
    pass


@dataclass
class EncryptionResult:
    """Stores complete details of a completed file encryption operation."""
    input_path: str
    output_path: str
    original_name: str
    original_size_bytes: int
    encrypted_size_bytes: int
    key_bits: int
    original_sha256: str
    encrypted_sha256: str
    elapsed_seconds: float
    status_messages: List[str]


class EncryptionModule:
    """
    Implements the AES Encryption Engine as defined in the Level 2 DFD.
    """

    @classmethod
    def encrypt_file(
        cls,
        input_path: str,
        password: str,
        key_bits: int = 256,
        output_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> EncryptionResult:
        """
        Encrypts a target file using AES-(128/192/256)-CBC + HMAC-SHA256.

        Parameters:
            input_path: Path to the plaintext file to encrypt.
            password: User password or key secret string.
            key_bits: AES key size in bits (128, 192, or 256).
            output_path: Optional custom path for the encrypted (.aes) output file.
            progress_callback: Optional callback(bytes_processed, total_bytes).

        Returns:
            EncryptionResult containing paths, hashes, timing, and status logs.
        """
        start_time = time.perf_counter()
        status_messages: List[str] = []

        # Step 1: Validate Input File
        file_meta: FileMetadata = InputModule.validate_and_inspect(input_path, compute_hash=True)
        status_messages.append("File Selected Successfully")

        # Step 2: Derive AES Encryption Key & HMAC Integrity Key
        derived_keys: DerivedKeySet = KeyGenerationModule.derive_keys_from_password(
            password=password,
            key_bits=key_bits,
        )
        status_messages.append(f"Encryption Key Generated (AES-{key_bits})")

        # Determine destination path
        if not output_path:
            output_path = f"{file_meta.file_path}.aes"
        output_path = str(Path(output_path).resolve())

        # Generate cryptographically random 128-bit Initialization Vector (IV)
        iv = secrets.token_bytes(AES_BLOCK_BYTES)

        # Prepare authenticated metadata header
        meta_dict = {
            "orig_name": file_meta.file_name,
            "orig_ext": file_meta.extension,
            "orig_size": file_meta.size_bytes,
            "orig_sha256": file_meta.sha256_hash,
            "algorithm": f"AES-{key_bits}-CBC-HMAC-SHA256",
            "encrypted_at": datetime.now(timezone.utc).isoformat(),
        }
        meta_bytes = json.dumps(meta_dict).encode("utf-8")
        if len(meta_bytes) > 65535:
            raise EncryptionError("File metadata exceeds maximum header size.")

        # Header structure: MAGIC (8B) + key_bits (2B) + salt (16B) + iv (16B) + meta_len (2B) + meta_bytes
        fixed_header = (
            MAGIC_HEADER
            + struct.pack(">H", key_bits)
            + derived_keys.salt
            + iv
            + struct.pack(">H", len(meta_bytes))
            + meta_bytes
        )

        # Initialize AES-CBC cipher, PKCS7 padder, and HMAC-SHA256 authenticator
        cipher = Cipher(
            algorithms.AES(derived_keys.encryption_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        mac = hmac.HMAC(derived_keys.hmac_key, hashes.SHA256(), backend=default_backend())
        mac.update(fixed_header)

        total_bytes = file_meta.size_bytes
        processed_bytes = 0

        try:
            with open(file_meta.file_path, "rb") as infile, open(output_path, "wb") as outfile:
                # Write fixed header
                outfile.write(fixed_header)

                # Stream plaintext chunks through PKCS7 padder -> AES encryptor -> HMAC -> output file
                while True:
                    chunk = infile.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    padded_data = padder.update(chunk)
                    if padded_data:
                        ciphertext_chunk = encryptor.update(padded_data)
                        mac.update(ciphertext_chunk)
                        outfile.write(ciphertext_chunk)

                    processed_bytes += len(chunk)
                    if progress_callback:
                        progress_callback(processed_bytes, max(total_bytes, 1))

                # Finalize padding and encryption
                final_padded = padder.finalize()
                final_ciphertext = encryptor.update(final_padded) + encryptor.finalize()
                if final_ciphertext:
                    mac.update(final_ciphertext)
                    outfile.write(final_ciphertext)

                # Compute and append 32-byte HMAC-SHA256 authentication tag
                auth_tag = mac.finalize()
                outfile.write(auth_tag)

        except Exception as exc:
            # Clean up partial output file if an error occurred
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except OSError:
                    pass
            raise EncryptionError(f"Failed to encrypt file: {exc}") from exc

        elapsed = time.perf_counter() - start_time
        encrypted_size = os.path.getsize(output_path)
        encrypted_sha256 = InputModule.compute_sha256(output_path)

        status_messages.append("Encryption Completed")
        status_messages.append("Encrypted File Saved")

        return EncryptionResult(
            input_path=file_meta.file_path,
            output_path=output_path,
            original_name=file_meta.file_name,
            original_size_bytes=file_meta.size_bytes,
            encrypted_size_bytes=encrypted_size,
            key_bits=key_bits,
            original_sha256=file_meta.sha256_hash,
            encrypted_sha256=encrypted_sha256,
            elapsed_seconds=elapsed,
            status_messages=status_messages,
        )
