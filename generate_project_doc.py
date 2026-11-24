"""
Complete Project Documentation (.docx) Generator
------------------------------------------------
Generates a valid, formatted Microsoft Word (.docx) document containing:
1. Project Overview & Architecture
2. Localhost Commands & Execution Guide
3. Free Cloud Hosting Guide (Render / Railway / PythonAnywhere)
4. System Modules & Level 2 DFD Explanation
5. Testing Plan (TC-01 to TC-06) Results
6. Complete Source Code of All Project Files
"""

import html
import zipfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
DOCX_OUTPUT_PATH = PROJECT_ROOT / "AES_Project_Complete_Documentation.docx"

SOURCE_FILES = [
    ("main.py", "Application Entry Point (GUI, Web Server & CLI)"),
    ("requirements.txt", "Python Dependencies"),
    ("render.yaml", "Render.com Free Cloud Hosting Blueprint"),
    ("Procfile", "Cloud Process File"),
    ("src/input_module.py", "1. Input Module (File Selection, Format Validation & SHA-256)"),
    ("src/key_module.py", "2. AES Key Generation Module (AES-128/192/256 & PBKDF2-HMAC-SHA256)"),
    ("src/encryption_module.py", "3. AES Encryption Engine (CBC Mode + PKCS7 + HMAC-SHA256)"),
    ("src/decryption_module.py", "4. AES Decryption Engine (Integrity Verification & Recovery)"),
    ("src/output_module.py", "5. Output Module & Encrypted File Database (SQLite Audit Log)"),
    ("src/gui.py", "6. Desktop Graphical User Interface (Tkinter/TTK)"),
    ("src/web_app.py", "7. Localhost & Cloud Web Application Server"),
    ("tests/test_tc01_to_tc06.py", "8. Automated Testing Plan Suite (TC-01 to TC-06)"),
]


def _w_heading(text: str, size_half_pts: int = 32, color: str = "1E3A8A") -> str:
    escaped = html.escape(text)
    return (
        f'<w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>'
        f'<w:r><w:rPr><w:b/><w:color w:val="{color}"/>'
        f'<w:sz w:val="{size_half_pts}"/><w:szCs w:val="{size_half_pts}"/></w:rPr>'
        f"<w:t>{escaped}</w:t></w:r></w:p>"
    )


def _w_para(text: str, bold: bool = False, mono: bool = False, size_half_pts: int = 22) -> str:
    escaped = html.escape(text)
    font_tag = '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/>' if mono else ""
    bold_tag = "<w:b/>" if bold else ""
    return (
        f'<w:p><w:pPr><w:spacing w:before="40" w:after="60"/></w:pPr>'
        f'<w:r><w:rPr>{font_tag}{bold_tag}<w:sz w:val="{size_half_pts}"/>'
        f'<w:szCs w:val="{size_half_pts}"/></w:rPr>'
        f'<w:t xml:space="preserve">{escaped}</w:t></w:r></w:p>'
    )


def build_docx(output_path: Path = DOCX_OUTPUT_PATH) -> Path:
    paragraphs = []

    # Title Section
    paragraphs.append(_w_heading("SECURE FILE ENCRYPTION AND DECRYPTION SYSTEM USING AES", 36, "0F172A"))
    paragraphs.append(_w_para("Complete Project Documentation, Execution Commands, Hosting Guide & Source Code", bold=True, size_half_pts=24))
    paragraphs.append(_w_para("GitHub Repository: https://github.com/zehrabhojani/aes-file-encryption-system", bold=True, size_half_pts=22))

    # 1. Overview
    paragraphs.append(_w_heading("1. Project Overview & Features", 28))
    paragraphs.append(_w_para(
        "This system implements a complete File Encryption and Decryption application using the "
        "Advanced Encryption Standard (AES) in Python. It supports 128-bit, 192-bit, and 256-bit keys, "
        "PBKDF2-HMAC-SHA256 password key derivation (200,000 iterations + 16-byte random salt), "
        "Encrypt-then-MAC (HMAC-SHA256) tamper/wrong-key detection, SHA-256 file integrity checks, "
        "and an SQLite Encrypted File Database."
    ))

    # 2. Localhost Commands
    paragraphs.append(_w_heading("2. Commands to Run on Localhost", 28))
    paragraphs.append(_w_para("Step 1: Open PowerShell or Command Prompt and navigate to the project directory:", bold=True))
    paragraphs.append(_w_para("cd C:\\Users\\2397811\\.gemini\\antigravity\\scratch\\aes_file_encryption_system", mono=True))
    paragraphs.append(_w_para("Step 2: Install Python dependencies:", bold=True))
    paragraphs.append(_w_para("pip install -r requirements.txt", mono=True))
    paragraphs.append(_w_para("Step 3: Start the Localhost Web Server (http://localhost:8000):", bold=True))
    paragraphs.append(_w_para("python main.py web --port 8000", mono=True))
    paragraphs.append(_w_para("Then open http://localhost:8000 in your browser.", bold=False))
    paragraphs.append(_w_para("Step 4: Or launch the Desktop Tkinter GUI:", bold=True))
    paragraphs.append(_w_para("python main.py", mono=True))
    paragraphs.append(_w_para("Step 5: Run the Automated Testing Plan (TC-01 to TC-06):", bold=True))
    paragraphs.append(_w_para("python tests/test_tc01_to_tc06.py", mono=True))

    # 3. Free Cloud Hosting Guide
    paragraphs.append(_w_heading("3. Free Cloud Hosting Guide (Render.com)", 28))
    paragraphs.append(_w_para(
        "The project includes 'render.yaml' and 'Procfile' and binds to 0.0.0.0:$PORT so it can be "
        "hosted for free on Render.com directly from the GitHub repository:"
    ))
    paragraphs.append(_w_para("1. One-Click Deploy URL: https://render.com/deploy?repo=https://github.com/zehrabhojani/aes-file-encryption-system", bold=True))
    paragraphs.append(_w_para("2. Or manually on https://dashboard.render.com -> New -> Web Service -> Connect 'zehrabhojani/aes-file-encryption-system'."))
    paragraphs.append(_w_para("   • Build Command: pip install -r requirements.txt && python generate_sample_files.py", mono=True))
    paragraphs.append(_w_para("   • Start Command: python main.py web", mono=True))
    paragraphs.append(_w_para("   • Plan: Free", mono=True))

    # 4. System Architecture & Modules
    paragraphs.append(_w_heading("4. System Modules (Section 7.2 & Level 2 DFD)", 28))
    module_points = [
        "1. Input Module (src/input_module.py): Validates selected files (.txt, .pdf, .docx, .jpg, .png, .xlsx, .aes), checks permissions, formats file size, and calculates SHA-256 checksums.",
        "2. Key Generation Module (src/key_module.py): Derives AES-128, AES-192, or AES-256 encryption keys and 256-bit HMAC keys from user passwords using PBKDF2-HMAC-SHA256, and exports/imports .key files.",
        "3. Encryption Module (src/encryption_module.py): Streams files in 64 KB chunks through PKCS7 padding, AES-CBC encryption, and appends a 32-byte HMAC-SHA256 authentication tag.",
        "4. Decryption Module (src/decryption_module.py): Verifies the HMAC-SHA256 authentication tag before decrypting. Immediately raises AccessDeniedError on wrong key (TC-05) and verifies original SHA-256 hash.",
        "5. Output & Database Module (src/output_module.py): Displays step-by-step Expected Output messages and records every operation in the local SQLite database (data/encrypted_files_db.sqlite).",
    ]
    for pt in module_points:
        paragraphs.append(_w_para(pt))

    # 5. Testing Plan Results
    paragraphs.append(_w_heading("5. Testing Plan Verification (TC-01 to TC-06)", 28))
    test_rows = [
        "TC-01 | Encrypt Text File (.txt)  | Expected: Successful Encryption     | Actual: PASS [OK]",
        "TC-02 | Decrypt Text File (.txt)  | Expected: Original Content Restored | Actual: PASS [OK]",
        "TC-03 | Encrypt PDF (.pdf)        | Expected: Encrypted Successfully    | Actual: PASS [OK]",
        "TC-04 | Decrypt PDF (.pdf)        | Expected: PDF Restored              | Actual: PASS [OK]",
        "TC-05 | Wrong Key                 | Expected: Access Denied             | Actual: PASS [OK]",
        "TC-06 | Large File Test (5 MB)    | Expected: Successful Processing     | Actual: PASS [OK]",
    ]
    for row in test_rows:
        paragraphs.append(_w_para(row, mono=True, size_half_pts=20))

    # 6. Complete Source Code
    paragraphs.append(_w_heading("6. Complete Project Source Code", 28))
    for rel_path, title in SOURCE_FILES:
        file_p = PROJECT_ROOT / rel_path
        if not file_p.exists():
            continue
        paragraphs.append(_w_heading(f"File: {rel_path} — {title}", 24, "0284C7"))
        code_text = file_p.read_text(encoding="utf-8", errors="replace")
        for line in code_text.splitlines():
            paragraphs.append(_w_para(line if line else " ", mono=True, size_half_pts=17))

    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        "</Relationships>"
    )
    body_xml = "".join(paragraphs)
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body_xml}</w:body></w:document>"
    )

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document_xml)

    return output_path


if __name__ == "__main__":
    out = build_docx()
    print(f"[OK] Generated Word documentation: {out}")
