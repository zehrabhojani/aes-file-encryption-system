"""
Graphical User Interface (GUI) Module (Section 4 & Section 7 of Project Synopsis)
---------------------------------------------------------------------------------
Provides an intuitive, user-friendly desktop interface integrating:
- Input Module (File Selection & Metadata Inspection)
- Key Generation Module (Password Input, AES-128/192/256 Selection, Random Key & .key File Export/Import)
- AES Encryption Engine
- AES Decryption Engine
- Output Module (Status Console & Encrypted File Database Viewer)
"""

import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from src.decryption_module import AccessDeniedError, DecryptionError, DecryptionModule
from src.encryption_module import EncryptionError, EncryptionModule
from src.input_module import FileMetadata, InputModule, InputValidationError
from src.key_module import KeyGenerationModule, KeyManagementError
from src.output_module import OutputModule


class AESFileSecurityGUI:
    """Main Tkinter GUI application for the AES File Encryption & Decryption System."""

    BG_DARK = "#0f172a"
    BG_CARD = "#1e293b"
    BG_INPUT = "#0b1120"
    FG_PRIMARY = "#f8fafc"
    FG_SECONDARY = "#94a3b8"
    ACCENT_BLUE = "#38bdf8"
    ACCENT_GREEN = "#10b981"
    ACCENT_AMBER = "#f59e0b"
    ACCENT_RED = "#ef4444"

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure File Encryption & Decryption System Using AES")
        self.root.geometry("980x740")
        self.root.minsize(900, 680)
        self.root.configure(bg=self.BG_DARK)

        self.output_module = OutputModule()
        self.current_file_meta: Optional[FileMetadata] = None

        # Tkinter state variables
        self.selected_file_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar(value=False)
        self.key_bits_var = tk.IntVar(value=256)
        self.progress_var = tk.DoubleVar(value=0.0)
        self.status_banner_var = tk.StringVar(value="Ready — Select a file to encrypt or decrypt.")

        self.meta_name_var = tk.StringVar(value="—")
        self.meta_type_var = tk.StringVar(value="—")
        self.meta_size_var = tk.StringVar(value="—")
        self.meta_hash_var = tk.StringVar(value="—")

        self._configure_styles()
        self._build_layout()
        self._refresh_database_table()

    def _configure_styles(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=self.BG_DARK)
        style.configure("Card.TFrame", background=self.BG_CARD, relief="flat")
        style.configure(
            "Header.TLabel",
            background=self.BG_DARK,
            foreground=self.ACCENT_BLUE,
            font=("Segoe UI", 16, "bold"),
        )
        style.configure(
            "SubHeader.TLabel",
            background=self.BG_DARK,
            foreground=self.FG_SECONDARY,
            font=("Segoe UI", 9),
        )
        style.configure(
            "CardTitle.TLabel",
            background=self.BG_CARD,
            foreground=self.ACCENT_BLUE,
            font=("Segoe UI", 11, "bold"),
        )
        style.configure(
            "CardText.TLabel",
            background=self.BG_CARD,
            foreground=self.FG_PRIMARY,
            font=("Segoe UI", 9),
        )
        style.configure(
            "CardMuted.TLabel",
            background=self.BG_CARD,
            foreground=self.FG_SECONDARY,
            font=("Segoe UI", 9),
        )
        style.configure(
            "TRadiobutton",
            background=self.BG_CARD,
            foreground=self.FG_PRIMARY,
            font=("Segoe UI", 9, "bold"),
        )
        style.configure(
            "TCheckbutton",
            background=self.BG_CARD,
            foreground=self.FG_SECONDARY,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview",
            background=self.BG_INPUT,
            foreground=self.FG_PRIMARY,
            fieldbackground=self.BG_INPUT,
            rowheight=24,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background=self.BG_CARD,
            foreground=self.ACCENT_BLUE,
            font=("Segoe UI", 9, "bold"),
        )
        style.configure(
            "TNotebook",
            background=self.BG_DARK,
            borderwidth=0,
        )
        style.configure(
            "TNotebook.Tab",
            background=self.BG_CARD,
            foreground=self.FG_SECONDARY,
            padding=(14, 6),
            font=("Segoe UI", 9, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.ACCENT_BLUE)],
            foreground=[("selected", "#0f172a")],
        )

    def _build_layout(self) -> None:
        # Top Header
        header_frame = ttk.Frame(self.root, padding=(20, 14, 20, 6))
        header_frame.pack(fill="x")

        ttk.Label(
            header_frame,
            text="🛡️ SECURE FILE ENCRYPTION & DECRYPTION SYSTEM USING AES",
            style="Header.TLabel",
        ).pack(anchor="w")

        ttk.Label(
            header_frame,
            text="Advanced Encryption Standard (AES-128 / AES-192 / AES-256) • PBKDF2-HMAC-SHA256 Key Derivation • Integrity Verification",
            style="SubHeader.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        # Main Upper Grid: Left (Input Module) & Right (Key Generation Module)
        upper_container = ttk.Frame(self.root, padding=(20, 6, 20, 6))
        upper_container.pack(fill="x")
        upper_container.columnconfigure(0, weight=1)
        upper_container.columnconfigure(1, weight=1)

        self._build_input_module_card(upper_container)
        self._build_key_module_card(upper_container)

        # Action Bar (Encrypt / Decrypt / Progress)
        self._build_action_bar()

        # Bottom Notebook: Expected Output Console & Encrypted File Database
        self._build_output_notebook()

    def _build_input_module_card(self, parent: ttk.Frame) -> None:
        card = ttk.Frame(parent, style="Card.TFrame", padding=14)
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 8), pady=4)

        ttk.Label(card, text="1. Input Module (File Selection)", style="CardTitle.TLabel").pack(
            anchor="w", pady=(0, 8)
        )

        file_row = ttk.Frame(card, style="Card.TFrame")
        file_row.pack(fill="x", pady=(0, 10))

        entry = tk.Entry(
            file_row,
            textvariable=self.selected_file_var,
            bg=self.BG_INPUT,
            fg=self.FG_PRIMARY,
            insertbackground=self.FG_PRIMARY,
            relief="flat",
            font=("Consolas", 9),
        )
        entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))

        browse_btn = tk.Button(
            file_row,
            text="📂 Browse File...",
            command=self._on_browse_file,
            bg=self.ACCENT_BLUE,
            fg="#0f172a",
            activebackground="#0284c7",
            relief="flat",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=4,
            cursor="hand2",
        )
        browse_btn.pack(side="right")

        # File Metadata Display Grid
        meta_grid = ttk.Frame(card, style="Card.TFrame")
        meta_grid.pack(fill="x", pady=(2, 0))
        meta_grid.columnconfigure(1, weight=1)

        labels = [
            ("File Name:", self.meta_name_var),
            ("Format / Type:", self.meta_type_var),
            ("File Size:", self.meta_size_var),
            ("SHA-256 Digest:", self.meta_hash_var),
        ]
        for idx, (title, var) in enumerate(labels):
            ttk.Label(meta_grid, text=title, style="CardMuted.TLabel").grid(
                row=idx, column=0, sticky="w", pady=2, padx=(0, 8)
            )
            ttk.Label(meta_grid, textvariable=var, style="CardText.TLabel").grid(
                row=idx, column=1, sticky="w", pady=2
            )

    def _build_key_module_card(self, parent: ttk.Frame) -> None:
        card = ttk.Frame(parent, style="Card.TFrame", padding=14)
        card.grid(row=0, column=1, sticky="nsew", padx=(8, 0), pady=4)

        ttk.Label(
            card, text="2. AES Key Generation Module", style="CardTitle.TLabel"
        ).pack(anchor="w", pady=(0, 8))

        # Key size selector
        size_row = ttk.Frame(card, style="Card.TFrame")
        size_row.pack(fill="x", pady=(0, 8))
        ttk.Label(size_row, text="AES Key Size:", style="CardMuted.TLabel").pack(
            side="left", padx=(0, 10)
        )
        for bits, label in [(128, "128-bit"), (192, "192-bit"), (256, "256-bit (Recommended)")]:
            ttk.Radiobutton(
                size_row,
                text=label,
                variable=self.key_bits_var,
                value=bits,
            ).pack(side="left", padx=(0, 10))

        # Password / Secret Key Input
        ttk.Label(
            card, text="Password / Cryptographic Secret Key:", style="CardMuted.TLabel"
        ).pack(anchor="w", pady=(2, 4))

        pw_row = ttk.Frame(card, style="Card.TFrame")
        pw_row.pack(fill="x", pady=(0, 6))

        self.pw_entry = tk.Entry(
            pw_row,
            textvariable=self.password_var,
            show="•",
            bg=self.BG_INPUT,
            fg=self.FG_PRIMARY,
            insertbackground=self.FG_PRIMARY,
            relief="flat",
            font=("Consolas", 10),
        )
        self.pw_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 8))

        ttk.Checkbutton(
            pw_row,
            text="Show Key",
            variable=self.show_password_var,
            command=self._toggle_password_visibility,
        ).pack(side="right")

        # Key Management Utility Buttons
        btn_row = ttk.Frame(card, style="Card.TFrame")
        btn_row.pack(fill="x", pady=(8, 0))

        tk.Button(
            btn_row,
            text="🔑 Generate Random Key",
            command=self._on_generate_random_key,
            bg="#334155",
            fg=self.FG_PRIMARY,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
            padx=8,
            pady=4,
            cursor="hand2",
        ).pack(side="left", padx=(0, 6))

        tk.Button(
            btn_row,
            text="💾 Save .key File",
            command=self._on_save_key_file,
            bg="#334155",
            fg=self.FG_PRIMARY,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
            padx=8,
            pady=4,
            cursor="hand2",
        ).pack(side="left", padx=(0, 6))

        tk.Button(
            btn_row,
            text="📥 Load .key File",
            command=self._on_load_key_file,
            bg="#334155",
            fg=self.FG_PRIMARY,
            relief="flat",
            font=("Segoe UI", 8, "bold"),
            padx=8,
            pady=4,
            cursor="hand2",
        ).pack(side="left")

    def _build_action_bar(self) -> None:
        action_frame = ttk.Frame(self.root, padding=(20, 6, 20, 6))
        action_frame.pack(fill="x")

        card = ttk.Frame(action_frame, style="Card.TFrame", padding=12)
        card.pack(fill="x")

        btn_container = ttk.Frame(card, style="Card.TFrame")
        btn_container.pack(fill="x")

        self.encrypt_btn = tk.Button(
            btn_container,
            text="🔒 ENCRYPT FILE (AES)",
            command=self._on_encrypt_clicked,
            bg=self.ACCENT_GREEN,
            fg="#052e16",
            activebackground="#059669",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padx=22,
            pady=7,
            cursor="hand2",
        )
        self.encrypt_btn.pack(side="left", padx=(0, 12))

        self.decrypt_btn = tk.Button(
            btn_container,
            text="🔓 DECRYPT FILE (AES)",
            command=self._on_decrypt_clicked,
            bg=self.ACCENT_AMBER,
            fg="#451a03",
            activebackground="#d97706",
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padx=22,
            pady=7,
            cursor="hand2",
        )
        self.decrypt_btn.pack(side="left", padx=(0, 16))

        ttk.Label(
            btn_container,
            textvariable=self.status_banner_var,
            style="CardText.TLabel",
        ).pack(side="left", fill="x", expand=True)

        # Progress bar
        self.progress_bar = ttk.Progressbar(
            card,
            variable=self.progress_var,
            maximum=100.0,
            mode="determinate",
        )
        self.progress_bar.pack(fill="x", pady=(10, 0))

    def _build_output_notebook(self) -> None:
        notebook_frame = ttk.Frame(self.root, padding=(20, 6, 20, 16))
        notebook_frame.pack(fill="both", expand=True)

        self.notebook = ttk.Notebook(notebook_frame)
        self.notebook.pack(fill="both", expand=True)

        # Tab 1: Output Module Status Console (Section 10 Expected Output)
        console_tab = ttk.Frame(self.notebook, style="Card.TFrame", padding=10)
        self.notebook.add(console_tab, text=" 🖥️ Output Module (Operation Status & Logs) ")

        self.console_text = tk.Text(
            console_tab,
            bg=self.BG_INPUT,
            fg="#a7f3d0",
            insertbackground=self.FG_PRIMARY,
            relief="flat",
            font=("Consolas", 10),
            wrap="word",
            height=12,
        )
        self.console_text.pack(fill="both", expand=True)
        self._append_console(
            "=== SECURE FILE ENCRYPTION AND DECRYPTION SYSTEM USING AES ===\n"
            "Supported Formats: .txt, .pdf, .docx, .jpg, .png, .xlsx, and all binary files.\n"
            "Select a file and enter a password or generate a cryptographic key to begin.\n"
        )

        # Tab 2: Encrypted File Database (Level 2 DFD)
        db_tab = ttk.Frame(self.notebook, style="Card.TFrame", padding=10)
        self.notebook.add(db_tab, text=" 🗄️ Encrypted File Database (Audit History) ")

        db_toolbar = ttk.Frame(db_tab, style="Card.TFrame")
        db_toolbar.pack(fill="x", pady=(0, 6))

        ttk.Label(
            db_toolbar,
            text="SQLite Audit Log of Encryption & Decryption Operations (Level 2 DFD)",
            style="CardMuted.TLabel",
        ).pack(side="left")

        tk.Button(
            db_toolbar,
            text="🗑️ Clear History",
            command=self._on_clear_history,
            bg="#334155",
            fg=self.FG_PRIMARY,
            relief="flat",
            font=("Segoe UI", 8),
            padx=8,
            pady=2,
            cursor="hand2",
        ).pack(side="right", padx=(6, 0))

        tk.Button(
            db_toolbar,
            text="🔄 Refresh",
            command=self._refresh_database_table,
            bg="#334155",
            fg=self.FG_PRIMARY,
            relief="flat",
            font=("Segoe UI", 8),
            padx=8,
            pady=2,
            cursor="hand2",
        ).pack(side="right")

        columns = ("id", "timestamp", "operation", "file_name", "algorithm", "size", "status", "elapsed")
        self.db_tree = ttk.Treeview(db_tab, columns=columns, show="headings", height=10)
        headings = [
            ("id", "ID", 45),
            ("timestamp", "Timestamp", 135),
            ("operation", "Operation", 95),
            ("file_name", "File Name", 190),
            ("algorithm", "Algorithm", 120),
            ("size", "Output Size", 95),
            ("status", "Status", 110),
            ("elapsed", "Time (ms)", 80),
        ]
        for col_id, col_title, width in headings:
            self.db_tree.heading(col_id, text=col_title)
            self.db_tree.column(col_id, width=width, anchor="w")

        self.db_tree.pack(fill="both", expand=True)

    # ------------------------------------------------------------------
    # Event Handlers
    # ------------------------------------------------------------------

    def _toggle_password_visibility(self) -> None:
        self.pw_entry.configure(show="" if self.show_password_var.get() else "•")

    def _on_browse_file(self) -> None:
        filetypes = [
            (
                "All Supported Files",
                "*.txt *.pdf *.docx *.doc *.jpg *.jpeg *.png *.xlsx *.xls *.csv *.aes *",
            ),
            ("AES Encrypted Files (*.aes)", "*.aes"),
            ("Text Files (*.txt)", "*.txt"),
            ("PDF Files (*.pdf)", "*.pdf"),
            ("Word Documents (*.docx)", "*.docx"),
            ("Images (*.jpg, *.png)", "*.jpg *.jpeg *.png"),
            ("Spreadsheets (*.xlsx, *.csv)", "*.xlsx *.csv"),
            ("All Files (*.*)", "*.*"),
        ]
        chosen = filedialog.askopenfilename(
            title="Select File for Encryption or Decryption",
            filetypes=filetypes,
        )
        if not chosen:
            return

        self.selected_file_var.set(chosen)
        self._inspect_selected_file(chosen)

    def _inspect_selected_file(self, file_path: str) -> None:
        try:
            meta = InputModule.validate_and_inspect(file_path, compute_hash=True)
            self.current_file_meta = meta
            self.meta_name_var.set(meta.file_name)
            self.meta_type_var.set(meta.category)
            self.meta_size_var.set(f"{meta.size_formatted} ({meta.size_bytes:,} bytes)")
            self.meta_hash_var.set(f"{meta.sha256_hash[:40]}...")

            if meta.is_encrypted_file:
                try:
                    hdr = DecryptionModule.inspect_encrypted_header(file_path)
                    self.key_bits_var.set(hdr["key_bits"])
                    orig_name = hdr["metadata"].get("orig_name", "Unknown")
                    self.status_banner_var.set(
                        f"File Selected Successfully — Detected AES-{hdr['key_bits']} encrypted file (Original: {orig_name})"
                    )
                except Exception:
                    self.status_banner_var.set("File Selected Successfully (Encrypted .aes file)")
            else:
                self.status_banner_var.set(
                    f"File Selected Successfully — Ready to encrypt '{meta.file_name}'"
                )

            self._append_console(
                f"\n[Input Module] File Selected Successfully\n"
                f"  • File Name : {meta.file_name}\n"
                f"  • Category  : {meta.category}\n"
                f"  • Size      : {meta.size_formatted} ({meta.size_bytes:,} bytes)\n"
                f"  • SHA-256   : {meta.sha256_hash}\n"
            )
        except InputValidationError as exc:
            messagebox.showerror("Input Validation Error", str(exc))

    def _on_generate_random_key(self) -> None:
        bits = self.key_bits_var.get()
        random_key = KeyGenerationModule.generate_random_passkey(bits)
        self.password_var.set(random_key)
        self.show_password_var.set(True)
        self._toggle_password_visibility()
        self.status_banner_var.set(f"Encryption Key Generated (Random {bits}-bit High-Entropy Key)")
        self._append_console(
            f"\n[Key Generation Module] Encryption Key Generated (AES-{bits})\n"
            f"  • Generated Secret Key: {random_key}\n"
            f"  • Tip: Click 'Save .key File' to store this key safely for future decryption.\n"
        )

    def _on_save_key_file(self) -> None:
        key_str = self.password_var.get().strip()
        if not key_str:
            messagebox.showwarning(
                "Missing Key",
                "Please enter a password or click 'Generate Random Key' before saving a .key file.",
            )
            return

        save_path = filedialog.asksaveasfilename(
            title="Save Cryptographic Key File",
            defaultextension=".key",
            filetypes=[("AES Key Files (*.key)", "*.key"), ("All Files (*.*)", "*.*")],
        )
        if not save_path:
            return

        try:
            bits = self.key_bits_var.get()
            KeyGenerationModule.save_key_file(save_path, key_str, bits)
            self.status_banner_var.set(f"Key saved to {Path(save_path).name}")
            self._append_console(f"[Key Generation Module] Saved AES-{bits} key to: {save_path}\n")
            messagebox.showinfo("Key File Saved", f"Cryptographic key saved successfully:\n{save_path}")
        except KeyManagementError as exc:
            messagebox.showerror("Key Save Error", str(exc))

    def _on_load_key_file(self) -> None:
        load_path = filedialog.askopenfilename(
            title="Load Cryptographic Key File (.key)",
            filetypes=[("AES Key Files (*.key)", "*.key"), ("All Files (*.*)", "*.*")],
        )
        if not load_path:
            return

        try:
            secret, bits = KeyGenerationModule.load_key_file(load_path)
            self.password_var.set(secret)
            self.key_bits_var.set(bits)
            self.status_banner_var.set(f"Loaded AES-{bits} key from {Path(load_path).name}")
            self._append_console(
                f"[Key Generation Module] Loaded AES-{bits} key from: {load_path}\n"
            )
        except KeyManagementError as exc:
            messagebox.showerror("Key Load Error", str(exc))

    def _update_progress(self, processed: int, total: int) -> None:
        pct = min(100.0, (processed / max(total, 1)) * 100.0)
        self.root.after(0, lambda: self.progress_var.set(pct))

    def _on_encrypt_clicked(self) -> None:
        file_path = self.selected_file_var.get().strip()
        password = self.password_var.get().strip()
        key_bits = self.key_bits_var.get()

        if not file_path:
            messagebox.showwarning("No File Selected", "Please select a file to encrypt first.")
            return
        if not password:
            messagebox.showwarning(
                "Password / Key Required",
                "Please enter a password or generate a random cryptographic key.",
            )
            return

        default_out = f"{file_path}.aes"
        output_path = filedialog.asksaveasfilename(
            title="Save Encrypted File As",
            initialfile=Path(default_out).name,
            initialdir=str(Path(file_path).parent),
            defaultextension=".aes",
            filetypes=[("AES Encrypted File (*.aes)", "*.aes"), ("All Files (*.*)", "*.*")],
        )
        if not output_path:
            return

        self.progress_var.set(0.0)
        self.status_banner_var.set(f"Encrypting with AES-{key_bits}...")

        def worker():
            try:
                result = EncryptionModule.encrypt_file(
                    input_path=file_path,
                    password=password,
                    key_bits=key_bits,
                    output_path=output_path,
                    progress_callback=self._update_progress,
                )
                self.output_module.record_operation(
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
                    details="Encrypted File Saved",
                )
                summary = [
                    f"Algorithm Used     : AES-{result.key_bits} (CBC Mode + PKCS7 + HMAC-SHA256)",
                    f"Original File      : {result.input_path} ({result.original_size_bytes:,} bytes)",
                    f"Encrypted File     : {result.output_path} ({result.encrypted_size_bytes:,} bytes)",
                    f"Original SHA-256   : {result.original_sha256}",
                    f"Encrypted SHA-256  : {result.encrypted_sha256}",
                    f"Processing Time    : {result.elapsed_seconds * 1000:.2f} ms",
                ]
                formatted_log = OutputModule.format_expected_output_log(
                    result.status_messages, summary
                )
                self.root.after(0, lambda: self._on_operation_complete(
                    title="Encryption Completed",
                    banner="Encryption Completed — Encrypted File Saved",
                    console_block=f"\n=== AES ENCRYPTION OPERATION ===\n{formatted_log}\n",
                    popup_msg=(
                        "File Encrypted Successfully!\n\n"
                        + "\n".join(f"• {m}" for m in result.status_messages)
                        + f"\n\nSaved to:\n{result.output_path}"
                    ),
                    next_file_path=result.output_path,
                ))
            except (InputValidationError, KeyManagementError, EncryptionError) as exc:
                self.output_module.record_operation(
                    operation="ENCRYPT",
                    file_name=Path(file_path).name,
                    source_path=file_path,
                    output_path=output_path,
                    algorithm=f"AES-{key_bits}-CBC",
                    status="FAILED",
                    details=str(exc),
                )
                self.root.after(0, lambda: self._on_operation_error("Encryption Error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_decrypt_clicked(self) -> None:
        file_path = self.selected_file_var.get().strip()
        password = self.password_var.get().strip()

        if not file_path:
            messagebox.showwarning("No File Selected", "Please select an encrypted (.aes) file to decrypt.")
            return
        if not password:
            messagebox.showwarning(
                "Password / Key Required",
                "Please enter the decryption password or load the .key file.",
            )
            return

        # If the user still has the original unencrypted file selected, check if file_path + ".aes" exists
        if not file_path.lower().endswith(".aes") and os.path.exists(f"{file_path}.aes"):
            file_path = f"{file_path}.aes"
            self.selected_file_var.set(file_path)

        # Determine suggested restored filename from header if valid
        suggested_name = Path(file_path).stem
        try:
            hdr = DecryptionModule.inspect_encrypted_header(file_path)
            suggested_name = hdr["metadata"].get("orig_name", suggested_name)
        except Exception:
            pass

        output_path = filedialog.asksaveasfilename(
            title="Save Restored File As",
            initialfile=f"restored_{suggested_name}",
            initialdir=str(Path(file_path).parent),
            filetypes=[("All Files (*.*)", "*.*")],
        )
        if not output_path:
            return

        self.progress_var.set(0.0)
        self.status_banner_var.set("Verifying key & decrypting file...")

        def worker():
            try:
                result = DecryptionModule.decrypt_file(
                    input_path=file_path,
                    password=password,
                    output_path=output_path,
                    progress_callback=self._update_progress,
                )
                self.output_module.record_operation(
                    operation="DECRYPT",
                    file_name=result.restored_name,
                    source_path=result.input_path,
                    output_path=result.output_path,
                    algorithm=f"AES-{result.key_bits}-CBC",
                    original_size=os.path.getsize(file_path),
                    result_size=result.restored_size_bytes,
                    sha256_hash=result.restored_sha256,
                    elapsed_seconds=result.elapsed_seconds,
                    status="SUCCESS",
                    details="Original Content Restored",
                )
                summary = [
                    f"Algorithm Used     : AES-{result.key_bits} (CBC Mode + HMAC-SHA256 Verified)",
                    f"Encrypted Source   : {result.input_path}",
                    f"Restored File      : {result.output_path} ({result.restored_size_bytes:,} bytes)",
                    f"Restored SHA-256   : {result.restored_sha256}",
                    f"SHA-256 Integrity  : {'MATCHED ORIGINAL (100% Verified)' if result.integrity_verified else 'Unverified'}",
                    f"Processing Time    : {result.elapsed_seconds * 1000:.2f} ms",
                ]
                formatted_log = OutputModule.format_expected_output_log(
                    result.status_messages, summary
                )
                self.root.after(0, lambda: self._on_operation_complete(
                    title="Decryption Completed",
                    banner="Decryption Completed — Original Content Restored",
                    console_block=f"\n=== AES DECRYPTION OPERATION ===\n{formatted_log}\n",
                    popup_msg=(
                        "File Decrypted Successfully!\n\n"
                        + "\n".join(f"• {m}" for m in result.status_messages)
                        + f"\n\nRestored to:\n{result.output_path}"
                    ),
                ))
            except AccessDeniedError as exc:
                self.output_module.record_operation(
                    operation="DECRYPT",
                    file_name=Path(file_path).name,
                    source_path=file_path,
                    output_path=output_path,
                    algorithm=f"AES-{self.key_bits_var.get()}-CBC",
                    status="ACCESS DENIED",
                    details=str(exc),
                )
                self.root.after(0, lambda: self._on_operation_error("Access Denied", str(exc)))
            except (InputValidationError, DecryptionError) as exc:
                self.output_module.record_operation(
                    operation="DECRYPT",
                    file_name=Path(file_path).name,
                    source_path=file_path,
                    output_path=output_path,
                    algorithm=f"AES-{self.key_bits_var.get()}-CBC",
                    status="FAILED",
                    details=str(exc),
                )
                self.root.after(0, lambda: self._on_operation_error("Decryption Error", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_operation_complete(
        self,
        title: str,
        banner: str,
        console_block: str,
        popup_msg: str,
        next_file_path: Optional[str] = None,
    ) -> None:
        self.progress_var.set(100.0)
        self.status_banner_var.set(banner)
        self._append_console(console_block)
        if next_file_path and os.path.exists(next_file_path):
            self.selected_file_var.set(next_file_path)
            self._inspect_selected_file(next_file_path)
        self._refresh_database_table()
        messagebox.showinfo(title, popup_msg)

    def _on_operation_error(self, title: str, err_msg: str) -> None:
        self.progress_var.set(0.0)
        self.status_banner_var.set(f"Error: {err_msg}")
        self._append_console(f"\n[✖] {title}: {err_msg}\n")
        self._refresh_database_table()
        messagebox.showerror(title, err_msg)

    def _append_console(self, text: str) -> None:
        self.console_text.insert("end", text)
        self.console_text.see("end")

    def _refresh_database_table(self) -> None:
        for item in self.db_tree.get_children():
            self.db_tree.delete(item)

        records = self.output_module.get_recent_operations(limit=100)
        for row in records:
            size_str = InputModule.format_size(row["result_size"] or 0)
            self.db_tree.insert(
                "",
                "end",
                values=(
                    row["id"],
                    row["timestamp"],
                    row["operation"],
                    row["file_name"],
                    row["algorithm"],
                    size_str,
                    row["status"],
                    f"{row['elapsed_ms']:.1f}",
                ),
            )

    def _on_clear_history(self) -> None:
        if messagebox.askyesno(
            "Clear Database History",
            "Are you sure you want to clear all operation logs from the Encrypted File Database?",
        ):
            self.output_module.clear_history()
            self._refresh_database_table()


def launch_gui() -> None:
    """Initializes and starts the Tkinter GUI main loop."""
    root = tk.Tk()
    AESFileSecurityGUI(root)
    root.mainloop()
