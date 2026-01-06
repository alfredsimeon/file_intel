# -*- mode: python ; coding: utf-8 -*-
"""
FILE-INTEL PyInstaller Spec File
Builds standalone executable with all dependencies
"""

import os
import sys
from pathlib import Path

block_cipher = None

# Get the project root
PROJECT_ROOT = os.path.dirname(os.path.abspath(SPEC))

# Determine Icon based on platform
icon_file = None
if sys.platform == 'darwin':
    icon_file = 'assets/icon.icns'
elif sys.platform == 'win32':
    icon_file = 'assets/icon.ico'

# Collect all data files
datas = [
    # Configuration
    (os.path.join(PROJECT_ROOT, 'config.yaml'), '.'),
    
    # YARA rules (optional - comment out if too large)
    # (os.path.join(PROJECT_ROOT, 'rules-master'), 'rules-master'),
    # (os.path.join(PROJECT_ROOT, 'signature-base-master'), 'signature-base-master'),
    
    # TrID definitions (optional)
    # (os.path.join(PROJECT_ROOT, 'TrIDGUI2-master', 'triddefs.trd'), 'trid'),
    
    # URLhaus database (optional)
    # (os.path.join(PROJECT_ROOT, 'plain-text-url-list.txt'), '.'),
]

# Filter out non-existent paths
datas = [(src, dst) for src, dst in datas if os.path.exists(src)]

# Hidden imports for dynamic loading
hiddenimports = [
    'file_intel',
    'file_intel.config',
    'file_intel.main',
    'file_intel.core',
    'file_intel.core.magic_detector',
    'file_intel.core.entropy_analyzer',
    'file_intel.core.hash_generator',
    'file_intel.core.file_scanner',
    'file_intel.detection',
    'file_intel.detection.yara_scanner',
    'file_intel.detection.mismatch_detector',
    'file_intel.detection.polyglot_detector',
    'file_intel.detection.anomaly_scorer',
    'file_intel.intel',
    'file_intel.intel.virustotal',
    'file_intel.intel.urlhaus',
    'file_intel.gui',
    'file_intel.gui.app',
    'file_intel.reports',
    'file_intel.reports.json_report',
    'file_intel.reports.html_report',
    'file_intel.reports.csv_report',
    # PyQt6
    'PyQt6',
    'PyQt6.QtWidgets',
    'PyQt6.QtCore',
    'PyQt6.QtGui',
    # Other dependencies
    'yaml',
    'colorama',
    'requests',
    'pefile',
    'hashlib',
    'json',
    'csv',
]

a = Analysis(
    ['FILE-INTEL.py'],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'scipy',
        'pandas',
        'PIL',
        'tkinter',
        'unittest',
        'test',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='FILE-INTEL',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Set to True for CLI-only mode
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    entitlements_file=None,
    icon=icon_file,
)

# Build .app bundle for macOS
if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='FILE-INTEL.app',
        icon=icon_file,
        bundle_identifier='com.fred.fileintel',
        info_plist={
            'NSHighResolutionCapable': 'True'
        }
    )
