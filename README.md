# Secure File Encryption and Decryption System Using AES (Advanced Encryption Standard)

---

## 1. Project Overview

This project implements a complete **Secure File Encryption and Decryption System Using AES** in Python, strictly aligned with the system design, modules, Level 2 Data Flow Diagram (DFD), and testing plan specified in the project synopsis.

### Key Highlights
- **Supported AES Key Sizes (Section 5):** Supports **128-bit**, **192-bit**, and **256-bit** AES keys in CBC mode with PKCS7 block padding.
- **Cryptographic Key Management (Section 7.2):**
  - Derives keys from user passwords using **PBKDF2-HMAC-SHA256** (200,000 iterations + 128-bit random cryptographic salt).
  - Generates high-entropy random cryptographic keys and supports exporting/importing `.key` files.
- **Authenticated Integrity Protection:** Uses **Encrypt-then-MAC (HMAC-SHA256)** over the file header and ciphertext, plus original file **SHA-256 checksum verification**, immediately rejecting wrong passwords or tampered files with `Access Denied` (`TC-05`).
- **Multi-Format Support (Section 4):** Seamlessly encrypts and restores Text files (`.txt`), PDF files (`.pdf`), Word documents (`.docx`), Images (`.jpg`, `.png`), Spreadsheets (`.xlsx`), and large binary files (`TC-06`).
- **Graphical User Interface & CLI:** Includes a modern desktop GUI built with `tkinter`/`ttk` as well as a full Command-Line Interface (CLI).

---

## 2. Architecture & Synopsis Module Mapping (Section 7.2)

```
aes_file_encryption_system/
├── main.py                      # Application Entry Point (GUI + CLI)
├── requirements.txt             # Python dependencies (cryptography)
├── generate_sample_files.py     # Generates sample .txt, .pdf, .docx, .png, .xlsx files
├── src/
│   ├── input_module.py          # 1. Input Module (File selection, validation, SHA-256 hashing)
│   ├── key_module.py            # 2. Key Generation Module (PBKDF2-HMAC-SHA256 & .key files)
│   ├── encryption_module.py     # 3. Encryption Module (AES-128/192/256 Engine)
│   ├── decryption_module.py     # 4. Decryption Module (HMAC verification & Original File Recovery)
│   ├── output_module.py         # 5. Output Module & Encrypted File Database (SQLite audit log)
│   └── gui.py                   # User-Friendly Graphical Interface (Tkinter/TTK)
└── tests/
    └── test_tc01_to_tc06.py     # Automated Testing Plan Runner (TC-01 to TC-06)
```

---

## 3. Setup & Running Instructions

### Step 1: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 2: Generate Sample Test Files (`.txt`, `.pdf`, `.docx`, `.png`, `.xlsx`)
```powershell
python generate_sample_files.py
```
This creates a `sample_files/` folder containing valid test files for every file format listed in Section 4 of the synopsis.

### Step 3: Launch the Graphical User Interface (GUI)
```powershell
python main.py
```

### Step 4: Run the Formal Testing Plan (`TC-01` to `TC-06`)
```powershell
python tests/test_tc01_to_tc06.py
```

---

## 4. Command-Line Interface (CLI) Examples

You can also run all operations from the terminal:

```powershell
# Encrypt a file using AES-256 and a password
python main.py encrypt sample_files/sample_confidential_notes.txt -p "MySecretPassword123" -b 256

# Decrypt an encrypted .aes file
python main.py decrypt sample_files/sample_confidential_notes.txt.aes -p "MySecretPassword123" -o sample_files/restored_notes.txt

# Generate and save a 256-bit cryptographic .key file
python main.py keygen -b 256 -o sample_files/master.key

# View the Encrypted File Database audit log
python main.py history
```
