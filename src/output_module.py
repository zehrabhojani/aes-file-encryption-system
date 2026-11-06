"""
Output Module & Encrypted File Database (Section 7.2 & Level 2 DFD)
-------------------------------------------------------------------
1. Formats and emits user-facing status feedback during encryption and decryption
   processes (matching Section 10: Expected Output).
2. Maintains the 'Encrypted File Database' (SQLite) shown in the Level 2 DFD to
   log all encryption, decryption, and failed access attempts for auditing.
"""

import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_DB_PATH = str(
    Path(__file__).resolve().parent.parent / "data" / "encrypted_files_db.sqlite"
)


class OutputModule:
    """
    Manages operation status reporting and the local Encrypted File Database (SQLite).
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_database()

    def _init_database(self) -> None:
        """Creates the operations audit table in SQLite if it does not exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS file_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    output_path TEXT,
                    algorithm TEXT NOT NULL,
                    original_size INTEGER,
                    result_size INTEGER,
                    sha256_hash TEXT,
                    elapsed_ms REAL,
                    status TEXT NOT NULL,
                    details TEXT
                )
                """
            )
            conn.commit()

    def record_operation(
        self,
        operation: str,
        file_name: str,
        source_path: str,
        output_path: Optional[str],
        algorithm: str,
        original_size: int = 0,
        result_size: int = 0,
        sha256_hash: str = "",
        elapsed_seconds: float = 0.0,
        status: str = "SUCCESS",
        details: str = "",
    ) -> int:
        """Inserts an encryption/decryption record into the Encrypted File Database."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        elapsed_ms = round(elapsed_seconds * 1000.0, 2)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                INSERT INTO file_operations (
                    timestamp, operation, file_name, source_path, output_path,
                    algorithm, original_size, result_size, sha256_hash,
                    elapsed_ms, status, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    operation,
                    file_name,
                    source_path,
                    output_path or "",
                    algorithm,
                    original_size,
                    result_size,
                    sha256_hash,
                    elapsed_ms,
                    status,
                    details,
                ),
            )
            conn.commit()
            return int(cursor.lastrowid)

    def get_recent_operations(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves the most recent records from the Encrypted File Database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT * FROM file_operations
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def clear_history(self) -> None:
        """Clears all records from the Encrypted File Database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM file_operations")
            conn.commit()

    @staticmethod
    def format_expected_output_log(messages: List[str], summary_lines: Optional[List[str]] = None) -> str:
        """
        Formats operation status messages matching Section 10 (Expected Output) of the Synopsis.
        Example Output:
            [OK] File Selected Successfully
            [OK] Encryption Key Generated
            [OK] Encryption Completed
            [OK] Encrypted File Saved
        """
        lines = []
        for msg in messages:
            lines.append(f"[OK] {msg}")
        if summary_lines:
            lines.append("-" * 56)
            lines.extend(summary_lines)
        return "\n".join(lines)
