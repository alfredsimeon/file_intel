# FILE-INTEL: Military-Grade File Type Identifier
**Advanced Threat Hunting & Malware Analysis Tool**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

---

## 📋 Overview

**FILE-INTEL** is a high-precision digital forensics and incident response (DFIR) tool designed for red teams, malware analysts, and security engineers. Unlike standard file identification tools that rely on extensions, FILE-INTEL performs deep binary analysis to reveal true file types, detect spoofing attempts, and identify hidden threats.

**Developer**: Fred ([@alfredsimeon](https://github.com/alfredsimeon))

### 🚀 Key Capabilities
*   **True Type Detection**: Identifies **200+ file formats** via magic number signatures (binary headers).
*   **Threat Scoring**: Calculates a risk score (0-100) based on entropy, spoofing, and heuristics.
*   **Extension Spoofing Detection**: Catches double extensions (`malware.pdf.exe`), RTLO attacks, and mismatches.
*   **Deep Inspection**:
    *   **Entropy Analysis**: Detects packed, encrypted, or obfuscated malware.
    *   **Hash Fingerprinting**: MD5, SHA1, SHA256, Import Hash (imphash).
    *   **Polyglot Detection**: Identifies files valid as multiple formats (e.g., GIF+JS).
*   **User Control**: Stop scan capability, read-only secure results, and visual drop feedback.
*   **Threat Intelligence**:
    *   **YARA Scanning**: Integrates 1000+ community rules for malware signatures.
    *   **VirusTotal API**: Automated hash reputation lookups.
    *   **URLhaus**: Checks files against 98,000+ known malicious URLs.
*   **Vintage GUI**: A distinct, distraction-free "hacker-style" interface with drag-and-drop.

---

## 🛠️ Installation & Setup

### Option A: Standalone Executable (Windows)
No Python installation required. Best for portability.

1.  Download `FILE-INTEL.exe` from the [Releases](https://github.com/alfredsimeon/file_intel/releases) page.
2.  Double-click to launch the GUI.

### Option B: Run from Source (Windows/Linux/macOS)
Best for developers and modifying the code.

#### Prerequisites
*   Python 3.8 or higher
*   Git

#### 1. Clone the Repository
```bash
git clone https://github.com/alfredsimeon/file_intel.git
cd file_intel
```

#### 2. Install Dependencies
```bash
# Create virtual environment (Recommended)
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install requirements
pip install -r requirements.txt

# Install YARA bindings (optional but recommended)
pip install yara-python
```

#### 3. Configuration (Optional)
Edit `config.yaml` to add your API keys:
```yaml
api_keys:
  virustotal: "YOUR_VT_API_KEY"
  malwarebazaar: "YOUR_MB_API_KEY"
```

---

## 🖥️ Usage Guide

### 1. Graphical Interface (GUI)
The recommended way to use FILE-INTEL.

**Windows**:
Double-click `FILE-INTEL.exe` or run:
```powershell
python FILE-INTEL.py --gui
```

**Linux (Kali)**:
```bash
python3 FILE-INTEL.py --gui
```

**How to Use**:
1.  **Drag & Drop** files or folders onto the target zone.
2.  Review **Thread Level**, **Score**, and **Detected Type**.
3.  Click rows to see deep analysis details (entropy, hashes, YARA matches).
4.  Export reports to **JSON**, **HTML**, or **CSV**.

### 2. Command Line Interface (CLI)
Ideal for automation and batch processing.

**Scan a single file**:
```bash
python FILE-INTEL.py -f suspicious_document.pdf
```

**Scan an entire directory recursively**:
```bash
# Output results to JSON for processing
python FILE-INTEL.py -d /path/to/evidence --json > results.json
```

**Enable Online Lookups (VirusTotal)**:
```bash
python FILE-INTEL.py -f unlikely_safe.exe --online
```

**Command Arguments**:
| Argument | Description |
| :--- | :--- |
| `-f <file>` | Scan a single file |
| `-d <dir>` | Scan a directory |
| `--gui` | Launch graphical interface |
| `--online` | Enable VirusTotal lookups |
| `--json` | Output detection results as JSON |
| `--deep` | Force deep content analysis (slower) |

---

## 🔍 Understanding Results

### Threat Indicators
*   **CRITICAL (80-100)**: Known malware signature, executable disguise, or confirmed malicious hash.
*   **HIGH (60-79)**: Extension mismatch (e.g., `exe` renamed to `png`), high entropy (packed), or dangerous script.
*   **MEDIUM (40-59)**: Suspicious characteristics, macros in documents, or unknown binary data.
*   **LOW/SAFE (0-39)**: Standard verified file formats.

### Common Alerts
*   **Extension Mismatch**: "File claims to be .jpg but is actually Windows Executable (MZ)".
*   **High Entropy**: "Entropy > 7.2: Likely packed, encrypted, or compressed code."
*   **Double Extension**: "Suspicious name pattern: `report.pdf.exe`"

---

## 👨‍💻 Developer Guide

### Project Structure
```text
file-intel/
├── FILE-INTEL.py            # Entry point
├── config.yaml              # Configuration
├── file_intel/
│   ├── core/                # Analysis Engine
│   │   ├── magic_detector.py    # 201+ File Signatures
│   │   ├── entropy_analyzer.py  # Shannon Entropy Logic
│   │   └── file_scanner.py      # Orchestrator
│   ├── detection/           # Heuristics
│   │   ├── yara_scanner.py      # YARA integration
│   │   └── mismatch_detector.py # Spoofing logic
│   ├── gui/                 # PyQt6 Interface
│   └── reports/             # Report Generators
└── requirements.txt         # Dependencies
```

### Building Standalone Executable
You can compile FILE-INTEL into a single `.exe` (Windows) or binary (Linux) that works without Python installed.

**Windows**:
```powershell
# Run the build script
build.bat
# Output will be in dist\FILE-INTEL.exe
```

**Linux/Kali**:
```bash
chmod +x build.sh
./build.sh
# Output will be in dist/FILE-INTEL
```

---

## ⚠️ Disclaimer
This tool is for educational and defensive purposes only. Use it to analyze files you own or have permission to test. The authors are not responsible for misuse.

---

*(c) 2026 Fred. All rights reserved.*
