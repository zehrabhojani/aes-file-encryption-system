"""
Input Module (Section 7.2 of Project Synopsis)
----------------------------------------------
Allows users to select and validate files for encryption and decryption operations.
Supports multiple file formats including:
- Text files (.txt)
- PDF files (.pdf)
- Microsoft Word documents (.docx)
- Image files (.jpg, .jpeg, .png)
- Spreadsheet files (.xlsx, .csv)
- Any other binary/document format
"""

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


SUPPORTED_FORMAT_CATEGORIES = {
    ".txt": "Text Document (.txt)",
    ".pdf": "PDF Document (.pdf)",
    ".docx": "Microsoft Word Document (.docx)",
    ".doc": "Microsoft Word Document (.doc)",
    ".jpg": "JPEG Image (.jpg)",
    ".jpeg": "JPEG Image (.jpeg)",
    ".png": "PNG Image (.png)",
    ".xlsx": "Microsoft Excel Spreadsheet (.xlsx)",
    ".xls": "Microsoft Excel Spreadsheet (.xls)",
    ".csv": "CSV Spreadsheet (.csv)",
    ".aes": "AES Encrypted File (.aes)",
}


@dataclass
class FileMetadata:
    """Represents validated metadata for an input file."""
    file_path: str
    file_name: str
    extension: str
    category: str
    size_bytes: int
    size_formatted: str
    sha256_hash: str
    is_encrypted_file: bool


class InputValidationError(Exception):
    """Raised when a selected input file fails validation."""
    pass


class InputModule:
    """
    Handles file selection validation, format identification, and integrity hashing.
    """

    @staticmethod
    def format_size(size_bytes: int) -> str:
        """Converts raw byte count to a human-readable size string."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

    @staticmethod
    def compute_sha256(file_path: str, chunk_size: int = 65536) -> str:
        """Computes the SHA-256 hash of a file in chunks to support large files."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()

    @classmethod
    def validate_and_inspect(cls, file_path: str, compute_hash: bool = True) -> FileMetadata:
        """
        Validates that a file exists, is readable, and is non-empty (or valid).
        Returns structured FileMetadata.
        """
        if not file_path or not str(file_path).strip():
            raise InputValidationError("No file selected. Please select a valid file.")

        path = Path(file_path).resolve()

        if not path.exists():
            raise InputValidationError(f"File does not exist: {path}")

        if not path.is_file():
            raise InputValidationError(f"Selected path is not a regular file: {path}")

        if not os.access(path, os.R_OK):
            raise InputValidationError(f"Permission denied: Cannot read file {path}")

        size_bytes = path.stat().st_size
        ext = path.suffix.lower()
        category = SUPPORTED_FORMAT_CATEGORIES.get(
            ext, f"Binary / Other File ({ext or 'no extension'})"
        )
        is_encrypted = ext == ".aes"

        sha256_digest = cls.compute_sha256(str(path)) if compute_hash else "N/A"

        return FileMetadata(
            file_path=str(path),
            file_name=path.name,
            extension=ext,
            category=category,
            size_bytes=size_bytes,
            size_formatted=cls.format_size(size_bytes),
            sha256_hash=sha256_digest,
            is_encrypted_file=is_encrypted,
        )
