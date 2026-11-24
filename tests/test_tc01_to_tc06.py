"""
Automated Testing Plan Suite (Section 9 of Project Synopsis)
------------------------------------------------------------
Executes and verifies all 6 formal Test Cases defined in the Synopsis:
- TC-01: Encrypt Text File      -> Successful Encryption
- TC-02: Decrypt Text File      -> Original Content Restored
- TC-03: Encrypt PDF            -> Encrypted Successfully
- TC-04: Decrypt PDF            -> PDF Restored
- TC-05: Wrong Key              -> Access Denied
- TC-06: Large File Test        -> Successful Processing

Plus multi-format (.docx, .png, .xlsx) and multi-key-size (AES-128, AES-192, AES-256)
verification.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from generate_sample_files import (
    create_sample_docx,
    create_sample_pdf,
    create_sample_png,
    create_sample_txt,
    create_sample_xlsx,
)
from src.decryption_module import AccessDeniedError, DecryptionModule
from src.encryption_module import EncryptionModule
from src.key_module import KeyGenerationModule


class TestSynopsisPlan(unittest.TestCase):
    """Formal test suite verifying TC-01 through TC-06 from Section 9 of the Project Synopsis."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.work_dir = Path(cls.temp_dir.name)
        cls.password = "AES_Secure_MasterKey_2026!@#$"

        cls.txt_path = cls.work_dir / "confidential_notes.txt"
        cls.pdf_path = cls.work_dir / "financial_report.pdf"
        create_sample_txt(cls.txt_path)
        create_sample_pdf(cls.pdf_path)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_tc01_and_tc02_text_file_encrypt_decrypt(self):
        """TC-01: Encrypt Text File & TC-02: Decrypt Text File."""
        enc_path = self.work_dir / "confidential_notes.txt.aes"
        dec_path = self.work_dir / "restored_confidential_notes.txt"

        # TC-01: Encrypt Text File
        enc_res = EncryptionModule.encrypt_file(
            input_path=str(self.txt_path),
            password=self.password,
            key_bits=256,
            output_path=str(enc_path),
        )
        self.assertTrue(enc_path.exists())
        self.assertIn("Encryption Completed", enc_res.status_messages)
        self.assertNotEqual(self.txt_path.read_bytes(), enc_path.read_bytes())

        # TC-02: Decrypt Text File
        dec_res = DecryptionModule.decrypt_file(
            input_path=str(enc_path),
            password=self.password,
            output_path=str(dec_path),
        )
        self.assertTrue(dec_path.exists())
        self.assertTrue(dec_res.integrity_verified)
        self.assertEqual(self.txt_path.read_text(encoding="utf-8"), dec_path.read_text(encoding="utf-8"))

    def test_tc03_and_tc04_pdf_file_encrypt_decrypt(self):
        """TC-03: Encrypt PDF & TC-04: Decrypt PDF."""
        enc_path = self.work_dir / "financial_report.pdf.aes"
        dec_path = self.work_dir / "restored_financial_report.pdf"

        # TC-03: Encrypt PDF
        enc_res = EncryptionModule.encrypt_file(
            input_path=str(self.pdf_path),
            password=self.password,
            key_bits=256,
            output_path=str(enc_path),
        )
        self.assertTrue(enc_path.exists())
        self.assertEqual(enc_res.original_sha256, DecryptionModule.inspect_encrypted_header(str(enc_path))["metadata"]["orig_sha256"])

        # TC-04: Decrypt PDF
        dec_res = DecryptionModule.decrypt_file(
            input_path=str(enc_path),
            password=self.password,
            output_path=str(dec_path),
        )
        self.assertTrue(dec_path.exists())
        self.assertTrue(dec_res.integrity_verified)
        self.assertEqual(self.pdf_path.read_bytes(), dec_path.read_bytes())

    def test_tc05_wrong_key_access_denied(self):
        """TC-05: Wrong Key -> Access Denied."""
        enc_path = self.work_dir / "tc05_protected.txt.aes"
        dec_path = self.work_dir / "tc05_should_not_exist.txt"

        EncryptionModule.encrypt_file(
            input_path=str(self.txt_path),
            password="Correct_Master_Password_256",
            key_bits=256,
            output_path=str(enc_path),
        )

        with self.assertRaises(AccessDeniedError) as ctx:
            DecryptionModule.decrypt_file(
                input_path=str(enc_path),
                password="Wrong_Attacker_Password_999",
                output_path=str(dec_path),
            )
        self.assertIn("Access Denied", str(ctx.exception))
        self.assertFalse(dec_path.exists())

    def test_tc06_large_file_test(self):
        """TC-06: Large File Test (5 MB multi-chunk binary file) -> Successful Processing."""
        large_file = self.work_dir / "large_dataset_5mb.bin"
        enc_large = self.work_dir / "large_dataset_5mb.bin.aes"
        dec_large = self.work_dir / "restored_large_dataset_5mb.bin"

        # Create 5 MB pseudo-random binary payload
        payload = os.urandom(5 * 1024 * 1024)
        large_file.write_bytes(payload)

        enc_res = EncryptionModule.encrypt_file(
            input_path=str(large_file),
            password=self.password,
            key_bits=256,
            output_path=str(enc_large),
        )
        self.assertTrue(enc_large.exists())
        self.assertGreater(enc_res.encrypted_size_bytes, 5 * 1024 * 1024)

        dec_res = DecryptionModule.decrypt_file(
            input_path=str(enc_large),
            password=self.password,
            output_path=str(dec_large),
        )
        self.assertTrue(dec_res.integrity_verified)
        self.assertEqual(enc_res.original_sha256, dec_res.restored_sha256)

    def test_aes_128_192_256_and_office_image_formats(self):
        """Verifies AES-128, AES-192, and AES-256 across .docx, .png, and .xlsx formats."""
        docx_p = self.work_dir / "doc.docx"
        png_p = self.work_dir / "img.png"
        xlsx_p = self.work_dir / "sheet.xlsx"
        create_sample_docx(docx_p)
        create_sample_png(png_p)
        create_sample_xlsx(xlsx_p)

        test_matrix = [
            (docx_p, 128),
            (png_p, 192),
            (xlsx_p, 256),
        ]
        for path, bits in test_matrix:
            key_str = KeyGenerationModule.generate_random_passkey(bits)
            key_file = self.work_dir / f"key_{bits}.key"
            KeyGenerationModule.save_key_file(str(key_file), key_str, bits)
            loaded_key, loaded_bits = KeyGenerationModule.load_key_file(str(key_file))
            self.assertEqual(loaded_bits, bits)

            enc_out = self.work_dir / f"{path.name}.aes"
            dec_out = self.work_dir / f"restored_{path.name}"

            EncryptionModule.encrypt_file(str(path), loaded_key, key_bits=loaded_bits, output_path=str(enc_out))
            res = DecryptionModule.decrypt_file(str(enc_out), loaded_key, output_path=str(dec_out))
            self.assertTrue(res.integrity_verified)
            self.assertEqual(path.read_bytes(), dec_out.read_bytes())


def run_formatted_test_plan_report() -> None:
    """Prints a formatted Section 9 Testing Plan Execution Table for project report screenshots."""
    print("=" * 84)
    print("  SECTION 9: TESTING PLAN EXECUTION REPORT - AES FILE ENCRYPTION SYSTEM")
    print("=" * 84)
    print(f"{'Test Case':<11} | {'Description':<24} | {'Expected Outcome':<25} | {'Actual Status'}")
    print("-" * 84)

    with tempfile.TemporaryDirectory() as tmp:
        wdir = Path(tmp)
        pw = "MasterSecretKey#2026"

        # Prepare files
        txt_f = wdir / "sample.txt"
        pdf_f = wdir / "sample.pdf"
        large_f = wdir / "large_5mb.bin"
        create_sample_txt(txt_f)
        create_sample_pdf(pdf_f)
        large_f.write_bytes(os.urandom(5 * 1024 * 1024))

        # TC-01
        enc_txt = EncryptionModule.encrypt_file(str(txt_f), pw, 256, str(wdir / "sample.txt.aes"))
        tc01_ok = Path(enc_txt.output_path).exists()
        print(f"{'TC-01':<11} | {'Encrypt Text File':<24} | {'Successful Encryption':<25} | {'PASS [OK]' if tc01_ok else 'FAIL'}")

        # TC-02
        dec_txt = DecryptionModule.decrypt_file(enc_txt.output_path, pw, str(wdir / "restored.txt"))
        tc02_ok = dec_txt.integrity_verified and (txt_f.read_bytes() == Path(dec_txt.output_path).read_bytes())
        print(f"{'TC-02':<11} | {'Decrypt Text File':<24} | {'Original Content Restored':<25} | {'PASS [OK]' if tc02_ok else 'FAIL'}")

        # TC-03
        enc_pdf = EncryptionModule.encrypt_file(str(pdf_f), pw, 256, str(wdir / "sample.pdf.aes"))
        tc03_ok = Path(enc_pdf.output_path).exists()
        print(f"{'TC-03':<11} | {'Encrypt PDF':<24} | {'Encrypted Successfully':<25} | {'PASS [OK]' if tc03_ok else 'FAIL'}")

        # TC-04
        dec_pdf = DecryptionModule.decrypt_file(enc_pdf.output_path, pw, str(wdir / "restored.pdf"))
        tc04_ok = dec_pdf.integrity_verified and (pdf_f.read_bytes() == Path(dec_pdf.output_path).read_bytes())
        print(f"{'TC-04':<11} | {'Decrypt PDF':<24} | {'PDF Restored':<25} | {'PASS [OK]' if tc04_ok else 'FAIL'}")

        # TC-05
        tc05_ok = False
        try:
            DecryptionModule.decrypt_file(enc_pdf.output_path, "WrongPassword123!", str(wdir / "bad.pdf"))
        except AccessDeniedError:
            tc05_ok = True
        print(f"{'TC-05':<11} | {'Wrong Key':<24} | {'Access Denied':<25} | {'PASS [OK]' if tc05_ok else 'FAIL'}")

        # TC-06
        enc_lg = EncryptionModule.encrypt_file(str(large_f), pw, 256, str(wdir / "large.aes"))
        dec_lg = DecryptionModule.decrypt_file(enc_lg.output_path, pw, str(wdir / "restored_large.bin"))
        tc06_ok = dec_lg.integrity_verified
        print(f"{'TC-06':<11} | {'Large File Test (5 MB)':<24} | {'Successful Processing':<25} | {'PASS [OK]' if tc06_ok else 'FAIL'}")

    print("=" * 84)
    print()


if __name__ == "__main__":
    run_formatted_test_plan_report()
    unittest.main(verbosity=2)
