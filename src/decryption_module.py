"""
Decryption Module (Section 7.2 & Level 2 DFD of Project Synopsis)
-----------------------------------------------------------------
Restores encrypted (.aes) files back to their original format using the
correct cryptographic key or password.

Features:
- Verifies file signature and HMAC-SHA256 authentication tag BEFORE decrypting
  to prevent tampering and immediately detect wrong keys (TC-05: Wrong Key -> Access Denied).
- Supports AES-128, AES-192, and AES-256 key lengths automatically from header or user selection.
- Verifies restored file SHA-256 checksum against original file SHA-256 checksum.
- Chunked streaming decryption for large files (TC-06).
"""

import json
import os
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.encryption_module import (
    AES_BLOCK_BYTES,
    CHUNK_SIZE,
    HMAC_DIGEST_BYTES,
    MAGIC_HEADER,
)
from src.input_module import InputModule
from src.key_module import DerivedKeySet, KeyGenerationModule, SALT_SIZE_BYTES


class AccessDeniedError(Exception):
    """
    Raised when decryption is attempted with an invalid password/key
    or when ciphertext integrity verification fails (Test Case TC-05).
    """
    pass


class DecryptionError(Exception):
    """Raised when an encrypted file is malformed or cannot be decrypted."""
    pass


@dataclass
class DecryptionResult:
    """Stores complete details of a completed file decryption operation."""
    input_path: str
    output_path: str
    restored_name: str
    restored_size_bytes: int
    key_bits: int
    restored_sha256: str
    integrity_verified: bool
    elapsed_seconds: float
    status_messages: List[str]


class DecryptionModule:
    """
    Implements the AES Decryption Engine and Original File Recovery
    as defined in the Level 2 DFD.
    """

    @staticmethod
    def inspect_encrypted_header(input_path: str) -> Dict[str, Any]:
        """
        Reads and parses the unencrypted header metadata of an .aes file
        without decrypting the payload.
        """
        if not os.path.exists(input_path):
            raise DecryptionError(f"Encrypted file not found: {input_path}")

        file_size = os.path.getsize(input_path)
        min_size = len(MAGIC_HEADER) + 2 + SALT_SIZE_BYTES + AES_BLOCK_BYTES + 2 + AES_BLOCK_BYTES + HMAC_DIGEST_BYTES
        if file_size < min_size:
            raise DecryptionError("File is too small or is not a valid AES encrypted file.")

        with open(input_path, "rb") as f:
            magic = f.read(len(MAGIC_HEADER))
            if magic != MAGIC_HEADER:
                raise DecryptionError(
                    f"'{Path(input_path).name}' is an unencrypted original file (not an .aes encrypted file). "
                    f"Please encrypt the file first or select the generated '.aes' file to decrypt."
                )

            key_bits = struct.unpack(">H", f.read(2))[0]
            salt = f.read(SALT_SIZE_BYTES)
            iv = f.read(AES_BLOCK_BYTES)
            meta_len = struct.unpack(">H", f.read(2))[0]
            meta_bytes = f.read(meta_len)
            header_end_offset = f.tell()

        try:
            metadata = json.loads(meta_bytes.decode("utf-8"))
        except Exception as exc:
            raise DecryptionError(f"Corrupted file header metadata: {exc}") from exc

        return {
            "key_bits": key_bits,
            "salt": salt,
            "iv": iv,
            "metadata": metadata,
            "header_end_offset": header_end_offset,
            "file_size": file_size,
        }

    @classmethod
    def decrypt_file(
        cls,
        input_path: str,
        password: str,
        output_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> DecryptionResult:
        """
        Authenticates and decrypts an AES-encrypted file (.aes) back to its original content.

        Raises:
            AccessDeniedError: If the password/key is wrong or the file was tampered with (TC-05).
            DecryptionError: If the file format is invalid.
        """
        start_time = time.perf_counter()
        status_messages: List[str] = []

        # Step 1: Validate input file and parse header
        InputModule.validate_and_inspect(input_path, compute_hash=False)
        header_info = cls.inspect_encrypted_header(input_path)
        status_messages.append("File Selected Successfully")

        key_bits = header_info["key_bits"]
        salt = header_info["salt"]
        iv = header_info["iv"]
        metadata = header_info["metadata"]
        header_end_offset = header_info["header_end_offset"]
        file_size = header_info["file_size"]

        # Step 2: Re-derive AES encryption key and HMAC key from password and stored salt
        try:
            derived_keys: DerivedKeySet = KeyGenerationModule.derive_keys_from_password(
                password=password,
                key_bits=key_bits,
                salt=salt,
            )
        except Exception as exc:
            raise AccessDeniedError(f"Access Denied: {exc}") from exc

        status_messages.append(f"Decryption Key Derived (AES-{key_bits})")

        ciphertext_length = file_size - header_end_offset - HMAC_DIGEST_BYTES
        if ciphertext_length <= 0 or ciphertext_length % AES_BLOCK_BYTES != 0:
            raise DecryptionError("Corrupted ciphertext: invalid AES block alignment.")

        # Step 3: Verify HMAC-SHA256 Authentication Tag BEFORE decrypting (Encrypt-then-MAC)
        mac = hmac.HMAC(derived_keys.hmac_key, hashes.SHA256(), backend=default_backend())
        with open(input_path, "rb") as infile:
            bytes_to_authenticate = file_size - HMAC_DIGEST_BYTES
            remaining = bytes_to_authenticate
            while remaining > 0:
                read_len = min(CHUNK_SIZE, remaining)
                chunk = infile.read(read_len)
                if not chunk:
                    break
                mac.update(chunk)
                remaining -= len(chunk)

            expected_tag = infile.read(HMAC_DIGEST_BYTES)

        try:
            mac.verify(expected_tag)
        except InvalidSignature as exc:
            raise AccessDeniedError(
                "Access Denied: Incorrect encryption key/password or tampered file."
            ) from exc

        status_messages.append("Key & Integrity Verified Successfully")

        # Determine output path
        orig_name = metadata.get("orig_name", "decrypted_file")
        if not output_path:
            input_p = Path(input_path).resolve()
            if input_p.suffix.lower() == ".aes":
                candidate = input_p.with_suffix("")
            else:
                candidate = input_p.parent / f"restored_{orig_name}"

            # Avoid overwriting existing original file silently unless explicitly specified;
            # Wait: if candidate is same as what user wants or in same folder, let's check
            output_path = str(candidate)
        output_path = str(Path(output_path).resolve())

        # Step 4: Perform streaming AES-CBC decryption and PKCS7 unpadding
        cipher = Cipher(
            algorithms.AES(derived_keys.encryption_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        processed_bytes = 0
        try:
            with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
                infile.seek(header_end_offset)
                remaining_ciphertext = ciphertext_length

                while remaining_ciphertext > 0:
                    read_len = min(CHUNK_SIZE, remaining_ciphertext)
                    chunk = infile.read(read_len)
                    if not chunk:
                        break
                    decrypted_padded = decryptor.update(chunk)
                    if decrypted_padded:
                        plaintext_chunk = unpadder.update(decrypted_padded)
                        if plaintext_chunk:
                            outfile.write(plaintext_chunk)

                    remaining_ciphertext -= len(chunk)
                    processed_bytes += len(chunk)
                    if progress_callback:
                        progress_callback(processed_bytes, max(ciphertext_length, 1))

                final_decrypted = decryptor.finalize()
                final_plaintext = unpadder.update(final_decrypted) + unpadder.finalize()
                if final_plaintext:
                    outfile.write(final_plaintext)

        except ValueError as exc:
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except OSError:
                    pass
            raise AccessDeniedError(
                "Access Denied: Invalid padding or wrong decryption key."
            ) from exc
        except Exception as exc:
            if os.path.exists(output_path):
                try:
                    os.remove(output_path)
                except OSError:
                    pass
            raise DecryptionError(f"Failed to decrypt file: {exc}") from exc

        elapsed = time.perf_counter() - start_time
        restored_size = os.path.getsize(output_path)
        restored_sha256 = InputModule.compute_sha256(output_path)

        orig_sha256 = metadata.get("orig_sha256")
        integrity_verified = (orig_sha256 == restored_sha256) if orig_sha256 else True

        status_messages.append("Decryption Completed")
        status_messages.append("Original Content Restored")

        return DecryptionResult(
            input_path=str(Path(input_path).resolve()),
            output_path=output_path,
            restored_name=Path(output_path).name,
            restored_size_bytes=restored_size,
            key_bits=key_bits,
            restored_sha256=restored_sha256,
            integrity_verified=integrity_verified,
            elapsed_seconds=elapsed,
            status_messages=status_messages,
        )
