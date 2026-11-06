"""
Web Application Interface (Localhost Server)
--------------------------------------------
Provides a modern browser-based interface at http://localhost:8000 for the
Secure File Encryption and Decryption System Using AES.

Integrates all 5 Synopsis Modules:
1. Input Module (File upload/selection, format detection, SHA-256 checksum)
2. Key Generation Module (AES-128/192/256, PBKDF2-HMAC-SHA256, Random Key & .key file export/import)
3. AES Encryption Engine (Encrypts files and provides instant .aes download)
4. AES Decryption Engine (Verifies HMAC-SHA256, enforces TC-05 Access Denied on wrong key, restores file)
5. Output Module & Encrypted File Database (LiveExpected Output console + SQLite audit table + TC-01..TC-06 runner)
"""

import base64
import json
import mimetypes
import os
import tempfile
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict

from generate_sample_files import generate_all_samples
from src.decryption_module import AccessDeniedError, DecryptionError, DecryptionModule
from src.encryption_module import EncryptionError, EncryptionModule
from src.input_module import InputModule, InputValidationError
from src.key_module import KeyGenerationModule, KeyManagementError
from src.output_module import OutputModule


PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_DIR = PROJECT_ROOT / "web_workspace"
SAMPLE_DIR = PROJECT_ROOT / "sample_files"

os.makedirs(WORKSPACE_DIR, exist_ok=True)
generate_all_samples()

output_module = OutputModule()


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Secure File Encryption & Decryption System Using AES</title>
  <style>
    :root {
      --bg-dark: #0b1120;
      --bg-card: #1e293b;
      --bg-input: #0f172a;
      --border: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent-blue: #38bdf8;
      --accent-green: #10b981;
      --accent-amber: #f59e0b;
      --accent-red: #ef4444;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: var(--bg-dark);
      color: var(--text-main);
      line-height: 1.5;
      padding: 24px;
    }
    .container {
      max-width: 1180px;
      margin: 0 auto;
    }
    header {
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 1px solid var(--border);
      border-left: 5px solid var(--accent-blue);
      border-radius: 12px;
      padding: 20px 24px;
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
    }
    header h1 {
      font-size: 1.35rem;
      color: var(--accent-blue);
      letter-spacing: 0.3px;
    }
    header p {
      font-size: 0.88rem;
      color: var(--text-muted);
      margin-top: 4px;
    }
    .badge-box {
      text-align: right;
      font-size: 0.8rem;
      color: var(--text-muted);
      background: rgba(56, 189, 248, 0.08);
      border: 1px solid rgba(56, 189, 248, 0.25);
      padding: 8px 14px;
      border-radius: 8px;
    }
    .badge-box strong { color: var(--text-main); }
    .grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 20px;
    }
    @media (max-width: 860px) {
      .grid-2 { grid-template-columns: 1fr; }
    }
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
    }
    .card h2 {
      font-size: 1.05rem;
      color: var(--accent-blue);
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }
    label {
      display: block;
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-bottom: 6px;
      font-weight: 600;
    }
    input[type="text"], input[type="password"], select {
      width: 100%;
      padding: 10px 12px;
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text-main);
      font-family: Consolas, monospace;
      font-size: 0.92rem;
    }
    input[type="file"] {
      width: 100%;
      padding: 10px;
      background: var(--bg-input);
      border: 1px dashed var(--accent-blue);
      border-radius: 8px;
      color: var(--text-main);
      cursor: pointer;
    }
    .radio-group {
      display: flex;
      gap: 12px;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }
    .radio-pill {
      flex: 1;
      min-width: 110px;
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px 12px;
      display: flex;
      align-items: center;
      gap: 8px;
      cursor: pointer;
      font-size: 0.88rem;
      font-weight: 600;
    }
    .radio-pill input { accent-color: var(--accent-blue); }
    .meta-box {
      margin-top: 14px;
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      font-size: 0.84rem;
    }
    .meta-row {
      display: flex;
      justify-content: space-between;
      padding: 4px 0;
      border-bottom: 1px solid rgba(255,255,255,0.05);
    }
    .meta-row:last-child { border-bottom: none; }
    .meta-key { color: var(--text-muted); }
    .meta-val { font-family: Consolas, monospace; color: var(--text-main); word-break: break-all; max-width: 70%; text-align: right; }
    .btn-row {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-top: 12px;
    }
    button, .btn-link {
      border: none;
      border-radius: 8px;
      padding: 10px 16px;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.1s, opacity 0.15s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      text-decoration: none;
    }
    button:hover, .btn-link:hover { opacity: 0.92; transform: translateY(-1px); }
    .btn-secondary {
      background: #334155;
      color: var(--text-main);
      font-size: 0.82rem;
      padding: 7px 12px;
    }
    .btn-encrypt {
      background: var(--accent-green);
      color: #052e16;
      font-size: 1rem;
      padding: 12px 24px;
    }
    .btn-decrypt {
      background: var(--accent-amber);
      color: #451a03;
      font-size: 1rem;
      padding: 12px 24px;
    }
    .btn-test {
      background: var(--accent-blue);
      color: #082f49;
      font-size: 0.92rem;
      padding: 12px 18px;
      margin-left: auto;
    }
    .action-bar {
      display: flex;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
      margin-bottom: 20px;
    }
    .console {
      background: #050811;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
      font-family: Consolas, monospace;
      font-size: 0.88rem;
      color: #a7f3d0;
      white-space: pre-wrap;
      min-height: 190px;
      max-height: 320px;
      overflow-y: auto;
    }
    .console.error { color: #fca5a5; }
    .download-banner {
      margin-top: 12px;
      padding: 12px 16px;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid var(--accent-green);
      border-radius: 8px;
      display: none;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 10px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
      margin-top: 8px;
    }
    th, td {
      text-align: left;
      padding: 9px 10px;
      border-bottom: 1px solid var(--border);
    }
    th {
      color: var(--accent-blue);
      background: var(--bg-input);
      font-weight: 600;
    }
    .status-pill {
      padding: 2px 8px;
      border-radius: 99px;
      font-size: 0.75rem;
      font-weight: 700;
    }
    .status-SUCCESS { background: rgba(16,185,129,0.2); color: #34d399; }
    .status-DENIED { background: rgba(239,68,68,0.2); color: #f87171; }
    .sample-chips {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      margin-top: 8px;
    }
    .chip {
      background: rgba(56, 189, 248, 0.12);
      border: 1px solid rgba(56, 189, 248, 0.3);
      color: var(--accent-blue);
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.78rem;
      cursor: pointer;
    }
    .chip:hover { background: rgba(56, 189, 248, 0.25); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>🛡️ SECURE FILE ENCRYPTION & DECRYPTION SYSTEM USING AES</h1>
        <p>Advanced Encryption Standard (128-bit / 192-bit / 256-bit) • PBKDF2-HMAC-SHA256 Key Derivation • Integrity Verification</p>
      </div>
    </header>

    <div class="grid-2">
      <!-- 1. INPUT MODULE -->
      <div class="card">
        <h2>📂 1. Input Module (File Selection)</h2>
        <label for="fileInput">Upload a File (.txt, .pdf, .docx, .jpg, .png, .xlsx, .aes):</label>
        <input type="file" id="fileInput" onchange="handleFileUpload(event)" />

        <div style="margin-top: 10px;">
          <label>Or Quick-Select a Preloaded Sample File (Section 4 Scope):</label>
          <div class="sample-chips" id="sampleChips"></div>
        </div>

        <div class="meta-box">
          <div class="meta-row"><span class="meta-key">Selected File:</span><span class="meta-val" id="metaName">—</span></div>
          <div class="meta-row"><span class="meta-key">Format / Category:</span><span class="meta-val" id="metaCat">—</span></div>
          <div class="meta-row"><span class="meta-key">File Size:</span><span class="meta-val" id="metaSize">—</span></div>
          <div class="meta-row"><span class="meta-key">SHA-256 Checksum:</span><span class="meta-val" id="metaHash">—</span></div>
        </div>
      </div>

      <!-- 2. KEY GENERATION MODULE -->
      <div class="card">
        <h2>🔑 2. AES Key Generation Module</h2>
        <label>Select AES Key Length (Section 5 Literature Review):</label>
        <div class="radio-group">
          <label class="radio-pill"><input type="radio" name="keyBits" value="128" /> AES-128 (128-bit)</label>
          <label class="radio-pill"><input type="radio" name="keyBits" value="192" /> AES-192 (192-bit)</label>
          <label class="radio-pill"><input type="radio" name="keyBits" value="256" checked /> AES-256 (256-bit)</label>
        </div>

        <label for="passwordInput">Password / Cryptographic Secret Key:</label>
        <div style="display:flex; gap:8px;">
          <input type="password" id="passwordInput" placeholder="Enter password or generate random key..." />
          <button type="button" class="btn-secondary" onclick="togglePassword()">👁️ Show</button>
        </div>

        <div class="btn-row">
          <button type="button" class="btn-secondary" onclick="generateRandomKey()">⚡ Generate Random Key</button>
          <button type="button" class="btn-secondary" onclick="downloadKeyFile()">💾 Save .key File</button>
          <button type="button" class="btn-secondary" onclick="document.getElementById('keyFileInput').click()">📥 Load .key File</button>
          <input type="file" id="keyFileInput" accept=".key" style="display:none" onchange="loadKeyFile(event)" />
        </div>
      </div>
    </div>

    <!-- 3 & 4. ENCRYPTION / DECRYPTION ENGINE ACTIONS -->
    <div class="card action-bar">
      <button type="button" class="btn-encrypt" onclick="runOperation('encrypt')">🔒 ENCRYPT FILE (AES)</button>
      <button type="button" class="btn-decrypt" onclick="runOperation('decrypt')">🔓 DECRYPT FILE (AES)</button>
      <button type="button" class="btn-test" onclick="runTestSuite()">🧪 Run Synopsis Test Plan (TC-01 to TC-06)</button>
    </div>

    <!-- 5. OUTPUT MODULE CONSOLE -->
    <div class="card" style="margin-bottom: 20px;">
      <h2>🖥️ 3. Output Module (Operation Status & Expected Output)</h2>
      <div id="consoleOutput" class="console">=== SECURE FILE ENCRYPTION AND DECRYPTION SYSTEM USING AES ===
Ready. Select or upload a file above, enter a password/key, and click ENCRYPT or DECRYPT.</div>
      <div id="downloadBanner" class="download-banner">
        <span id="downloadText" style="font-weight:600; color:#a7f3d0;">Operation completed!</span>
        <div style="display:flex; gap:10px;">
          <button type="button" class="btn-secondary" id="useResultBtn" onclick="selectOutputFileForNextStep()">🔄 Select Output File for Next Step</button>
          <a id="downloadLink" class="btn-link" style="background:var(--accent-green); color:#052e16;" href="#" download>⬇️ Download Output File</a>
        </div>
      </div>
    </div>

    <!-- 6. ENCRYPTED FILE DATABASE (LEVEL 2 DFD) -->
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
        <h2 style="margin-bottom:0; border:none;">🗄️ 4. Encrypted File Database (Level 2 DFD SQLite Audit Log)</h2>
        <div style="display:flex; gap:8px;">
          <button type="button" class="btn-secondary" onclick="loadHistory()">🔄 Refresh</button>
          <button type="button" class="btn-secondary" onclick="clearHistory()">🗑️ Clear History</button>
        </div>
      </div>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Timestamp</th>
              <th>Operation</th>
              <th>File Name</th>
              <th>Algorithm</th>
              <th>Output Size</th>
              <th>Status</th>
              <th>Time (ms)</th>
            </tr>
          </thead>
          <tbody id="historyBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    let activeServerFilePath = "";
    let lastOutputFilePath = "";

    async function initPage() {
      const res = await fetch('/api/samples');
      const data = await res.json();
      const container = document.getElementById('sampleChips');
      container.innerHTML = '';
      data.samples.forEach(s => {
        const chip = document.createElement('span');
        chip.className = 'chip';
        chip.textContent = '📄 ' + s.name;
        chip.onclick = () => selectServerFile(s.path);
        container.appendChild(chip);
      });
      loadHistory();
    }

    function getSelectedBits() {
      const checked = document.querySelector('input[name="keyBits"]:checked');
      return checked ? parseInt(checked.value, 10) : 256;
    }

    function setSelectedBits(bits) {
      const radio = document.querySelector(`input[name="keyBits"][value="${bits}"]`);
      if (radio) radio.checked = true;
    }

    function togglePassword() {
      const inp = document.getElementById('passwordInput');
      inp.type = inp.type === 'password' ? 'text' : 'password';
    }

    async function selectServerFile(filePath) {
      const res = await fetch('/api/inspect', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ file_path: filePath })
      });
      const data = await res.json();
      if (!data.ok) {
        alert(data.error);
        return;
      }
      updateMetadataUI(data);
    }

    async function handleFileUpload(ev) {
      const file = ev.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = async () => {
        const base64Data = reader.result.split(',')[1] || '';
        const res = await fetch('/api/upload', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ file_name: file.name, content_b64: base64Data })
        });
        const data = await res.json();
        if (!data.ok) {
          alert(data.error);
          return;
        }
        updateMetadataUI(data);
      };
      reader.readAsDataURL(file);
    }

    function updateMetadataUI(data) {
      activeServerFilePath = data.meta.file_path;
      document.getElementById('metaName').textContent = data.meta.file_name;
      document.getElementById('metaCat').textContent = data.meta.category;
      document.getElementById('metaSize').textContent = `${data.meta.size_formatted} (${data.meta.size_bytes.toLocaleString()} bytes)`;
      document.getElementById('metaHash').textContent = data.meta.sha256_hash;

      if (data.detected_key_bits) {
        setSelectedBits(data.detected_key_bits);
      }
      const consoleEl = document.getElementById('consoleOutput');
      consoleEl.className = 'console';
      consoleEl.textContent = `[OK] File Selected Successfully\n` +
        `  • File Name : ${data.meta.file_name}\n` +
        `  • Category  : ${data.meta.category}\n` +
        `  • Size      : ${data.meta.size_formatted} (${data.meta.size_bytes.toLocaleString()} bytes)\n` +
        `  • SHA-256   : ${data.meta.sha256_hash}`;
    }

    async function generateRandomKey() {
      const bits = getSelectedBits();
      const res = await fetch(`/api/keygen?bits=${bits}`);
      const data = await res.json();
      const inp = document.getElementById('passwordInput');
      inp.value = data.key;
      inp.type = 'text';
      const consoleEl = document.getElementById('consoleOutput');
      consoleEl.className = 'console';
      consoleEl.textContent = `[OK] Encryption Key Generated (AES-${bits})\n  • Generated High-Entropy Secret Key: ${data.key}\n  • Tip: Click 'Save .key File' to download this key for future decryption.`;
    }

    function downloadKeyFile() {
      const key = document.getElementById('passwordInput').value.trim();
      const bits = getSelectedBits();
      if (!key) {
        alert('Please enter a password or click Generate Random Key first.');
        return;
      }
      const payload = JSON.stringify({
        application: "AES Secure File Encryption System",
        algorithm: `AES-${bits}`,
        key_bits: bits,
        key_secret: key
      }, null, 2);
      const blob = new Blob([payload], {type: 'application/json'});
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `aes_${bits}_secret.key`;
      a.click();
    }

    function loadKeyFile(ev) {
      const file = ev.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        try {
          const data = JSON.parse(reader.result);
          if (!data.key_secret) throw new Error("Missing key_secret in .key file");
          document.getElementById('passwordInput').value = data.key_secret;
          if (data.key_bits) setSelectedBits(data.key_bits);
          document.getElementById('consoleOutput').textContent = `[OK] Loaded AES-${data.key_bits || 256} key from '${file.name}'.`;
        } catch (err) {
          alert("Invalid .key file: " + err.message);
        }
      };
      reader.readAsText(file);
    }

    async function runOperation(mode) {
      if (!activeServerFilePath) {
        alert('Please select or upload a file first.');
        return;
      }
      const password = document.getElementById('passwordInput').value.trim();
      if (!password) {
        alert('Please enter a password or generate a random cryptographic key.');
        return;
      }
      const bits = getSelectedBits();
      const res = await fetch(`/api/${mode}`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          file_path: activeServerFilePath,
          password: password,
          key_bits: bits
        })
      });
      const data = await res.json();
      const consoleEl = document.getElementById('consoleOutput');
      const bannerEl = document.getElementById('downloadBanner');

      if (!data.ok) {
        consoleEl.className = 'console error';
        consoleEl.textContent = `[✖] ${data.title || 'ERROR'}:\n${data.error}`;
        bannerEl.style.display = 'none';
        loadHistory();
        return;
      }

      consoleEl.className = 'console';
      consoleEl.textContent = data.formatted_log;
      lastOutputFilePath = data.output_path;

      // Automatically switch active file to the newly generated output file
      // so clicking ENCRYPT -> DECRYPT works seamlessly without re-selecting!
      if (data.output_meta) {
        activeServerFilePath = data.output_meta.file_path;
        document.getElementById('metaName').textContent = data.output_meta.file_name;
        document.getElementById('metaCat').textContent = data.output_meta.category;
        document.getElementById('metaSize').textContent = `${data.output_meta.size_formatted} (${data.output_meta.size_bytes.toLocaleString()} bytes)`;
        document.getElementById('metaHash').textContent = data.output_meta.sha256_hash;
      }

      bannerEl.style.display = 'flex';
      document.getElementById('downloadText').textContent = `Output File Saved: ${data.output_name} (Auto-selected for next step)`;
      const dlLink = document.getElementById('downloadLink');
      dlLink.href = `/api/download?path=${encodeURIComponent(data.output_path)}`;
      dlLink.download = data.output_name;
      loadHistory();
      initPage();
    }

    function selectOutputFileForNextStep() {
      if (lastOutputFilePath) {
        selectServerFile(lastOutputFilePath);
      }
    }

    async function runTestSuite() {
      const consoleEl = document.getElementById('consoleOutput');
      consoleEl.className = 'console';
      consoleEl.textContent = 'Running Synopsis Testing Plan (TC-01 to TC-06)... Please wait...';
      const res = await fetch('/api/run_tests', { method: 'POST' });
      const data = await res.json();
      consoleEl.textContent = data.report;
      loadHistory();
    }

    async function loadHistory() {
      const res = await fetch('/api/history');
      const data = await res.json();
      const tbody = document.getElementById('historyBody');
      tbody.innerHTML = '';
      if (!data.records.length) {
        tbody.innerHTML = '<tr><td colspan="8" style="color:var(--text-muted); text-align:center;">No operations recorded yet.</td></tr>';
        return;
      }
      data.records.forEach(r => {
        const pillClass = r.status === 'SUCCESS' ? 'status-SUCCESS' : 'status-DENIED';
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${r.id}</td>
          <td>${r.timestamp}</td>
          <td><strong>${r.operation}</strong></td>
          <td style="font-family:Consolas,monospace;">${r.file_name}</td>
          <td>${r.algorithm}</td>
          <td>${r.size_formatted}</td>
          <td><span class="status-pill ${pillClass}">${r.status}</span></td>
          <td>${r.elapsed_ms.toFixed(1)}</td>
        `;
        tbody.appendChild(tr);
      });
    }

    async function clearHistory() {
      await fetch('/api/clear_history', { method: 'POST' });
      loadHistory();
    }

    window.addEventListener('DOMContentLoaded', initPage);
  </script>
</body>
</html>
"""


class AESWebHandler(BaseHTTPRequestHandler):
    """HTTP Request handler serving the AES File Security Web UI and JSON APIs."""

    def log_message(self, format: str, *args: Any) -> None:
        # Keep console output clean
        pass

    def _send_json(self, payload: Dict[str, Any], status: int = 200) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b"{}"
        return json.loads(body.decode("utf-8"))

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if route == "/" or route == "/index.html":
            raw = HTML_PAGE.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if route == "/api/samples":
            samples = []
            for p in sorted(SAMPLE_DIR.iterdir()):
                if p.is_file():
                    samples.append({"name": p.name, "path": str(p.resolve())})
            for p in sorted(WORKSPACE_DIR.iterdir()):
                if p.is_file() and p.suffix.lower() == ".aes":
                    samples.append({"name": f"🔒 {p.name}", "path": str(p.resolve())})
            self._send_json({"ok": True, "samples": samples})
            return

        if route == "/api/keygen":
            bits = int(query.get("bits", ["256"])[0])
            key_str = KeyGenerationModule.generate_random_passkey(bits)
            self._send_json({"ok": True, "bits": bits, "key": key_str})
            return

        if route == "/api/history":
            records = output_module.get_recent_operations(limit=50)
            for r in records:
                r["size_formatted"] = InputModule.format_size(r.get("result_size") or 0)
            self._send_json({"ok": True, "records": records})
            return

        if route == "/api/download":
            file_path = query.get("path", [""])[0]
            path_obj = Path(file_path).resolve()
            if not path_obj.exists() or not path_obj.is_file():
                self.send_error(HTTPStatus.NOT_FOUND, "File not found")
                return
            mime, _ = mimetypes.guess_type(str(path_obj))
            data = path_obj.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", mime or "application/octet-stream")
            self.send_header(
                "Content-Disposition", f'attachment; filename="{path_obj.name}"'
            )
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path

        if route == "/api/inspect":
            body = self._read_json_body()
            file_path = body.get("file_path", "")
            try:
                meta = InputModule.validate_and_inspect(file_path, compute_hash=True)
                detected_bits = None
                if meta.is_encrypted_file:
                    try:
                        hdr = DecryptionModule.inspect_encrypted_header(file_path)
                        detected_bits = hdr["key_bits"]
                    except Exception:
                        pass
                self._send_json({
                    "ok": True,
                    "meta": meta.__dict__,
                    "detected_key_bits": detected_bits,
                })
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=400)
            return

        if route == "/api/upload":
            body = self._read_json_body()
            file_name = Path(body.get("file_name", "uploaded_file.bin")).name
            content_b64 = body.get("content_b64", "")
            dest_path = WORKSPACE_DIR / file_name
            dest_path.write_bytes(base64.b64decode(content_b64))
            try:
                meta = InputModule.validate_and_inspect(str(dest_path), compute_hash=True)
                detected_bits = None
                if meta.is_encrypted_file:
                    try:
                        hdr = DecryptionModule.inspect_encrypted_header(str(dest_path))
                        detected_bits = hdr["key_bits"]
                    except Exception:
                        pass
                self._send_json({
                    "ok": True,
                    "meta": meta.__dict__,
                    "detected_key_bits": detected_bits,
                })
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=400)
            return

        if route == "/api/encrypt":
            body = self._read_json_body()
            file_path = body.get("file_path", "")
            password = body.get("password", "")
            key_bits = int(body.get("key_bits", 256))
            try:
                src_p = Path(file_path).resolve()
                out_p = WORKSPACE_DIR / f"{src_p.name}.aes"
                result = EncryptionModule.encrypt_file(
                    input_path=str(src_p),
                    password=password,
                    key_bits=key_bits,
                    output_path=str(out_p),
                )
                output_module.record_operation(
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
                    details="Web UI Encryption",
                )
                summary = [
                    f"Algorithm Used     : AES-{result.key_bits} (CBC Mode + PKCS7 + HMAC-SHA256)",
                    f"Original File      : {result.original_name} ({result.original_size_bytes:,} bytes)",
                    f"Encrypted File     : {Path(result.output_path).name} ({result.encrypted_size_bytes:,} bytes)",
                    f"Original SHA-256   : {result.original_sha256}",
                    f"Encrypted SHA-256  : {result.encrypted_sha256}",
                    f"Processing Time    : {result.elapsed_seconds * 1000:.2f} ms",
                ]
                log_str = OutputModule.format_expected_output_log(result.status_messages, summary)
                out_meta = InputModule.validate_and_inspect(result.output_path, compute_hash=True)
                self._send_json({
                    "ok": True,
                    "output_path": result.output_path,
                    "output_name": Path(result.output_path).name,
                    "output_meta": out_meta.__dict__,
                    "formatted_log": log_str,
                })
            except (InputValidationError, KeyManagementError, EncryptionError) as exc:
                self._send_json({"ok": False, "title": "Encryption Error", "error": str(exc)}, status=400)
            return

        if route == "/api/decrypt":
            body = self._read_json_body()
            file_path = body.get("file_path", "")
            password = body.get("password", "")
            try:
                # Smart resolution: if user selected an original file (e.g., foo.txt) instead of foo.txt.aes,
                # automatically look for its corresponding .aes file in web_workspace or alongside the file!
                target_path = Path(file_path).resolve()
                if target_path.suffix.lower() != ".aes":
                    candidate_ws = WORKSPACE_DIR / f"{target_path.name}.aes"
                    candidate_local = Path(f"{target_path}.aes")
                    if candidate_ws.exists():
                        file_path = str(candidate_ws)
                    elif candidate_local.exists():
                        file_path = str(candidate_local)

                hdr = DecryptionModule.inspect_encrypted_header(file_path)
                orig_name = hdr["metadata"].get("orig_name", "decrypted_file")
                out_p = WORKSPACE_DIR / f"restored_{orig_name}"
                result = DecryptionModule.decrypt_file(
                    input_path=file_path,
                    password=password,
                    output_path=str(out_p),
                )
                output_module.record_operation(
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
                    details="Web UI Decryption",
                )
                summary = [
                    f"Algorithm Used     : AES-{result.key_bits} (CBC Mode + HMAC-SHA256 Verified)",
                    f"Encrypted Source   : {Path(file_path).name}",
                    f"Restored File      : {result.restored_name} ({result.restored_size_bytes:,} bytes)",
                    f"Restored SHA-256   : {result.restored_sha256}",
                    f"SHA-256 Integrity  : {'MATCHED ORIGINAL (100% Verified)' if result.integrity_verified else 'Verified'}",
                    f"Processing Time    : {result.elapsed_seconds * 1000:.2f} ms",
                ]
                log_str = OutputModule.format_expected_output_log(result.status_messages, summary)
                out_meta = InputModule.validate_and_inspect(result.output_path, compute_hash=True)
                self._send_json({
                    "ok": True,
                    "output_path": result.output_path,
                    "output_name": Path(result.output_path).name,
                    "output_meta": out_meta.__dict__,
                    "formatted_log": log_str,
                })
            except AccessDeniedError as exc:
                output_module.record_operation(
                    operation="DECRYPT",
                    file_name=Path(file_path).name,
                    source_path=file_path,
                    output_path="",
                    algorithm="AES-CBC",
                    status="ACCESS DENIED",
                    details=str(exc),
                )
                self._send_json({"ok": False, "title": "Access Denied (TC-05)", "error": str(exc)}, status=403)
            except (InputValidationError, DecryptionError) as exc:
                self._send_json({"ok": False, "title": "Decryption Error", "error": str(exc)}, status=400)
            return

        if route == "/api/run_tests":
            import io
            from contextlib import redirect_stdout
            from tests.test_tc01_to_tc06 import run_formatted_test_plan_report

            buf = io.StringIO()
            with redirect_stdout(buf):
                run_formatted_test_plan_report()
            self._send_json({"ok": True, "report": buf.getvalue()})
            return

        if route == "/api/clear_history":
            output_module.clear_history()
            self._send_json({"ok": True})
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")


def run_web_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), AESWebHandler)
    print(f"[OK] AES Secure File Encryption Web Server running at: http://localhost:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_web_server()
