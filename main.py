"""
Main Entry Point — Secure File Encryption and Decryption System Using AES
-------------------------------------------------------------------------
Usage:
  1. Launch Graphical User Interface (Default):
       python main.py

  2. Command-Line Interface (CLI) Mode:
       python main.py encrypt <file_path> -p <password> [-b 128|192|256] [-o <output_path>]
       python main.py decrypt <file_path.aes> -p <password> [-o <output_path>]
       python main.py keygen [-b 128|192|256] [-o my_secret.key]
       python main.py history
"""

import argparse
import sys
from pathlib import Path

from src.decryption_module import AccessDeniedError, DecryptionError, DecryptionModule
from src.encryption_module import EncryptionError, EncryptionModule
from src.input_module import InputValidationError
from src.key_module import KeyGenerationModule, KeyManagementError
from src.output_module import OutputModule


def run_cli(args: argparse.Namespace) -> int:
    output_mod = OutputModule()

    if args.command == "encrypt":
        try:
            password = args.password
            bits = args.bits
            if args.key_file:
                password, bits = KeyGenerationModule.load_key_file(args.key_file)

            result = EncryptionModule.encrypt_file(
                input_path=args.file,
                password=password,
                key_bits=bits,
                output_path=args.output,
            )
            output_mod.record_operation(
                operation="ENCRYPT",
                file_name=result.original_name,
                source_path=result.input_path,
                output_path=result.output_path,
                algorithm=f"AES-{result.key_bits}-CBC",
                original_size=result.original_size_bytes,
                result_size=result.encrypted_size_bytes,
                sha256_hash=result.encrypted_sha256,
                elapsed_seconds=result.elapsed_seconds,
                status="SUCCESS",
                details="CLI Encryption",
            )
            summary = [
                f"Algorithm        : AES-{result.key_bits}",
                f"Input File       : {result.input_path} ({result.original_size_bytes:,} bytes)",
                f"Encrypted Output : {result.output_path} ({result.encrypted_size_bytes:,} bytes)",
                f"Original SHA256  : {result.original_sha256}",
                f"Elapsed Time     : {result.elapsed_seconds * 1000:.2f} ms",
            ]
            print(OutputModule.format_expected_output_log(result.status_messages, summary))
            return 0
        except (InputValidationError, KeyManagementError, EncryptionError) as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 1

    elif args.command == "decrypt":
        try:
            password = args.password
            if args.key_file:
                password, _ = KeyGenerationModule.load_key_file(args.key_file)

            result = DecryptionModule.decrypt_file(
                input_path=args.file,
                password=password,
                output_path=args.output,
            )
            output_mod.record_operation(
                operation="DECRYPT",
                file_name=result.restored_name,
                source_path=result.input_path,
                output_path=result.output_path,
                algorithm=f"AES-{result.key_bits}-CBC",
                result_size=result.restored_size_bytes,
                sha256_hash=result.restored_sha256,
                elapsed_seconds=result.elapsed_seconds,
                status="SUCCESS",
                details="CLI Decryption",
            )
            summary = [
                f"Algorithm        : AES-{result.key_bits}",
                f"Encrypted Input  : {result.input_path}",
                f"Restored Output  : {result.output_path} ({result.restored_size_bytes:,} bytes)",
                f"Restored SHA256  : {result.restored_sha256}",
                f"Integrity Match  : {result.integrity_verified}",
                f"Elapsed Time     : {result.elapsed_seconds * 1000:.2f} ms",
            ]
            print(OutputModule.format_expected_output_log(result.status_messages, summary))
            return 0
        except AccessDeniedError as exc:
            output_mod.record_operation(
                operation="DECRYPT",
                file_name=Path(args.file).name,
                source_path=args.file,
                output_path=args.output,
                algorithm="AES-CBC",
                status="ACCESS DENIED",
                details=str(exc),
            )
            print(f"[ACCESS DENIED] {exc}", file=sys.stderr)
            return 2
        except (InputValidationError, KeyManagementError, DecryptionError) as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 1

    elif args.command == "keygen":
        key_str = KeyGenerationModule.generate_random_passkey(args.bits)
        print(f"[OK] Encryption Key Generated (AES-{args.bits}): {key_str}")
        if args.output:
            KeyGenerationModule.save_key_file(args.output, key_str, args.bits)
            print(f"[OK] Key File Saved: {args.output}")
        return 0

    elif args.command == "history":
        rows = output_mod.get_recent_operations(limit=25)
        if not rows:
            print("No operations recorded in Encrypted File Database yet.")
            return 0
        print(f"{'ID':<4} {'TIMESTAMP':<20} {'OP':<8} {'ALGORITHM':<12} {'STATUS':<14} {'FILE NAME'}")
        print("-" * 80)
        for r in rows:
            print(
                f"{r['id']:<4} {r['timestamp']:<20} {r['operation']:<8} "
                f"{r['algorithm']:<12} {r['status']:<14} {r['file_name']}"
            )
        return 0

    elif args.command == "web":
        from src.web_app import run_web_server
        run_web_server(port=args.port)
        return 0

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Secure File Encryption and Decryption System Using AES (128/192/256-bit)"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Encrypt subcommand
    enc = subparsers.add_parser("encrypt", help="Encrypt a file using AES")
    enc.add_argument("file", help="Path to plaintext file")
    enc.add_argument("-p", "--password", default="", help="Password or secret key string")
    enc.add_argument("-k", "--key-file", help="Path to a .key file")
    enc.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256, help="AES key size in bits")
    enc.add_argument("-o", "--output", help="Output .aes file path")

    # Decrypt subcommand
    dec = subparsers.add_parser("decrypt", help="Decrypt an .aes file")
    dec.add_argument("file", help="Path to encrypted .aes file")
    dec.add_argument("-p", "--password", default="", help="Password or secret key string")
    dec.add_argument("-k", "--key-file", help="Path to a .key file")
    dec.add_argument("-o", "--output", help="Output restored file path")

    # Keygen subcommand
    kg = subparsers.add_parser("keygen", help="Generate a random AES key or .key file")
    kg.add_argument("-b", "--bits", type=int, choices=[128, 192, 256], default=256, help="AES key size in bits")
    kg.add_argument("-o", "--output", help="Optional path to save .key file")

    # History subcommand
    subparsers.add_parser("history", help="Display Encrypted File Database operation history")

    # Web server subcommand
    web = subparsers.add_parser("web", help="Launch localhost web interface")
    web.add_argument("--port", type=int, default=8000, help="Port number (default: 8000)")

    return parser


def main() -> None:
    if len(sys.argv) > 1:
        parser = build_parser()
        args = parser.parse_args()
        if args.command:
            sys.exit(run_cli(args))

    # Default: Launch Graphical User Interface
    from src.gui import launch_gui
    launch_gui()


if __name__ == "__main__":
    main()
