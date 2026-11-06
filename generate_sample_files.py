"""
Sample Test File Generator (Section 4: Scope of the Project)
------------------------------------------------------------
Generates valid sample files covering all 5 file categories required in the
Project Synopsis so users can immediately test encryption and decryption:
1. Text files (.txt)
2. PDF files (.pdf)
3. Microsoft Word documents (.docx)
4. Image files (.png, .jpg)
5. Spreadsheet files (.xlsx)
"""

import os
import struct
import zipfile
import zlib
from pathlib import Path


SAMPLE_DIR = Path(__file__).resolve().parent / "sample_files"


def create_sample_txt(path: Path) -> None:
    content = (
        "====================================================================\n"
        "CONFIDENTIAL INFORMATION SECURITY DOCUMENT\n"
        "Project: Secure File Encryption and Decryption System Using AES\n"
        "====================================================================\n\n"
        "This text file demonstrates plaintext confidentiality protection using\n"
        "the Advanced Encryption Standard (AES-128 / AES-192 / AES-256).\n"
    )
    path.write_text(content, encoding="utf-8")


def create_sample_pdf(path: Path) -> None:
    """Creates a valid, standards-compliant single-page PDF file."""
    pdf_bytes = (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> "
        b"/MediaBox [0 0 612 792] /Contents 5 0 R >> endobj\n"
        b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n"
        b"5 0 obj << /Length 118 >> stream\n"
        b"BT /F1 16 Tf 72 700 Td (Confidential Financial & Security Report - AES Demo) Tj ET\n"
        b"BT /F1 12 Tf 72 670 Td (Protected by AES Encryption System) Tj ET\n"
        b"endstream endobj\n"
        b"xref\n0 6\n0000000000 65535 f \n"
        b"0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n"
        b"0000000241 00000 n \n0000000309 00000 n \n"
        b"trailer << /Size 6 /Root 1 0 R >>\nstartxref\n479\n%%EOF\n"
    )
    path.write_bytes(pdf_bytes)


def create_sample_docx(path: Path) -> None:
    """Creates a valid minimal OpenXML Word Document (.docx)."""
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
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body>"
        "<w:p><w:r><w:t>Secure File Encryption and Decryption System Using AES</w:t></w:r></w:p>"
        "<w:p><w:r><w:t>Sample Microsoft Word (.docx) Confidential Document for Encryption Testing.</w:t></w:r></w:p>"
        "</w:body></w:document>"
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", document_xml)


def create_sample_png(path: Path) -> None:
    """Creates a valid 64x64 RGB PNG image."""
    width, height = 64, 64

    def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
        chunk = chunk_type + data
        return struct.pack(">I", len(data)) + chunk + struct.pack(">I", zlib.crc32(chunk) & 0xFFFFFFFF)

    raw_scanlines = bytearray()
    for y in range(height):
        raw_scanlines.append(0)  # Filter type 0
        for x in range(width):
            raw_scanlines.extend((x * 4 % 256, y * 4 % 256, 180))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress(bytes(raw_scanlines))
    png_bytes = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", idat)
        + png_chunk(b"IEND", b"")
    )
    path.write_bytes(png_bytes)


def create_sample_xlsx(path: Path) -> None:
    """Creates a valid minimal OpenXML Excel Spreadsheet (.xlsx)."""
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    wb_rels = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/>'
        "</Relationships>"
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="ConfidentialData" sheetId="1" r:id="rId1"/></sheets>'
        "</workbook>"
    )
    sheet1 = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        "<sheetData>"
        '<row r="1"><c r="A1" t="inlineStr"><is><t>RecordID</t></is></c>'
        '<c r="B1" t="inlineStr"><is><t>Classification</t></is></c></row>'
        '<row r="2"><c r="A2" t="inlineStr"><is><t>SEC-001</t></is></c>'
        '<c r="B2" t="inlineStr"><is><t>AES-256 Protected</t></is></c></row>'
        "</sheetData></worksheet>"
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        zf.writestr("xl/workbook.xml", workbook)
        zf.writestr("xl/worksheets/sheet1.xml", sheet1)


def generate_all_samples() -> Path:
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    create_sample_txt(SAMPLE_DIR / "sample_confidential_notes.txt")
    create_sample_pdf(SAMPLE_DIR / "sample_financial_report.pdf")
    create_sample_docx(SAMPLE_DIR / "sample_project_document.docx")
    create_sample_png(SAMPLE_DIR / "sample_security_badge.png")
    create_sample_xlsx(SAMPLE_DIR / "sample_employee_records.xlsx")
    return SAMPLE_DIR


if __name__ == "__main__":
    out_dir = generate_all_samples()
    print(f"[OK] Generated 5 sample files (.txt, .pdf, .docx, .png, .xlsx) in: {out_dir}")
