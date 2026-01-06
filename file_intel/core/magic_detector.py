"""
FILE-INTEL: Magic Number Detection Engine
Comprehensive file type identification using magic numbers/file signatures
EXPANDED VERSION: 200+ signatures for military-grade detection
"""

import os
import struct
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum


class ThreatLevel(Enum):
    """Threat level classification"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FileCategory(Enum):
    """File category classification"""
    EXECUTABLE = "executable"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    SCRIPT = "script"
    DATA = "data"
    FIRMWARE = "firmware"
    FONT = "font"
    CAD = "cad"
    DATABASE = "database"
    VIRTUAL = "virtual"
    CRYPTO = "crypto"
    UNKNOWN = "unknown"


@dataclass
class MagicSignature:
    """Definition of a magic number signature"""
    name: str
    extension: str
    category: FileCategory
    magic_bytes: bytes
    offset: int = 0
    description: str = ""
    mime_type: str = ""
    threat_level: ThreatLevel = ThreatLevel.SAFE


@dataclass
class FileTypeResult:
    """Result of file type detection"""
    detected_type: str
    extension: str
    category: FileCategory
    mime_type: str
    confidence: float
    threat_level: ThreatLevel
    description: str
    signature_offset: int
    raw_magic: bytes
    additional_info: Dict[str, Any] = field(default_factory=dict)


class MagicDetector:
    """
    Advanced magic number detection engine
    Identifies true file types regardless of extension
    EXPANDED: 200+ file type signatures
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.signatures: List[MagicSignature] = []
        self._build_signature_database()
    
    def _build_signature_database(self) -> None:
        """Build comprehensive magic signature database - 200+ signatures"""
        
        # ============================================================
        # EXECUTABLE FORMATS - HIGH PRIORITY FOR SECURITY
        # ============================================================
        
        # Windows PE Family
        self._add("PE Executable", "exe", FileCategory.EXECUTABLE, b'MZ', 0, "Windows Portable Executable", "application/x-dosexec", ThreatLevel.HIGH)
        self._add("Windows DLL", "dll", FileCategory.EXECUTABLE, b'MZ', 0, "Windows Dynamic Link Library", "application/x-msdownload", ThreatLevel.HIGH)
        self._add("Windows Screensaver", "scr", FileCategory.EXECUTABLE, b'MZ', 0, "Windows Screensaver (Executable)", "application/x-dosexec", ThreatLevel.CRITICAL)
        self._add("Windows SYS Driver", "sys", FileCategory.EXECUTABLE, b'MZ', 0, "Windows Kernel Driver", "application/x-dosexec", ThreatLevel.CRITICAL)
        self._add("Windows OCX Control", "ocx", FileCategory.EXECUTABLE, b'MZ', 0, "ActiveX Control", "application/x-dosexec", ThreatLevel.HIGH)
        self._add("Windows CPL Applet", "cpl", FileCategory.EXECUTABLE, b'MZ', 0, "Control Panel Applet", "application/x-dosexec", ThreatLevel.HIGH)
        self._add("Windows Installer", "msi", FileCategory.EXECUTABLE, b'\xd0\xcf\x11\xe0', 0, "Windows Installer Package", "application/x-msi", ThreatLevel.HIGH)
        
        # Linux ELF Family
        self._add("ELF Executable", "elf", FileCategory.EXECUTABLE, b'\x7fELF', 0, "Linux/Unix Executable", "application/x-elf", ThreatLevel.HIGH)
        self._add("ELF 32-bit", "so", FileCategory.EXECUTABLE, b'\x7fELF\x01', 0, "ELF 32-bit", "application/x-elf", ThreatLevel.HIGH)
        self._add("ELF 64-bit", "so", FileCategory.EXECUTABLE, b'\x7fELF\x02', 0, "ELF 64-bit", "application/x-elf", ThreatLevel.HIGH)
        
        # macOS Mach-O Family
        self._add("Mach-O 32-bit LE", "macho", FileCategory.EXECUTABLE, b'\xce\xfa\xed\xfe', 0, "Mach-O 32-bit Little Endian", "application/x-mach-binary", ThreatLevel.HIGH)
        self._add("Mach-O 64-bit LE", "macho", FileCategory.EXECUTABLE, b'\xcf\xfa\xed\xfe', 0, "Mach-O 64-bit Little Endian", "application/x-mach-binary", ThreatLevel.HIGH)
        self._add("Mach-O 32-bit BE", "macho", FileCategory.EXECUTABLE, b'\xfe\xed\xfa\xce', 0, "Mach-O 32-bit Big Endian", "application/x-mach-binary", ThreatLevel.HIGH)
        self._add("Mach-O 64-bit BE", "macho", FileCategory.EXECUTABLE, b'\xfe\xed\xfa\xcf', 0, "Mach-O 64-bit Big Endian", "application/x-mach-binary", ThreatLevel.HIGH)
        self._add("Mach-O Universal", "macho", FileCategory.EXECUTABLE, b'\xca\xfe\xba\xbe', 0, "macOS Universal Binary", "application/x-mach-binary", ThreatLevel.HIGH)
        self._add("macOS App Bundle", "app", FileCategory.EXECUTABLE, b'\xca\xfe\xba\xbe', 0, "macOS Application", "application/x-mach-binary", ThreatLevel.HIGH)
        
        # Mobile Executables
        self._add("Android DEX", "dex", FileCategory.EXECUTABLE, b'dex\n', 0, "Android Dalvik Executable", "application/vnd.android.dex", ThreatLevel.HIGH)
        self._add("Android ODEX", "odex", FileCategory.EXECUTABLE, b'dey\n', 0, "Android Optimized DEX", "application/vnd.android.dex", ThreatLevel.HIGH)
        self._add("Android APK", "apk", FileCategory.EXECUTABLE, b'PK\x03\x04', 0, "Android Package", "application/vnd.android.package-archive", ThreatLevel.HIGH)
        self._add("iOS IPA", "ipa", FileCategory.EXECUTABLE, b'PK\x03\x04', 0, "iOS Application Package", "application/octet-stream", ThreatLevel.HIGH)
        
        # Java/JVM
        self._add("Java Class", "class", FileCategory.EXECUTABLE, b'\xca\xfe\xba\xbe', 0, "Java Compiled Class", "application/java-vm", ThreatLevel.MEDIUM)
        self._add("Java JAR", "jar", FileCategory.EXECUTABLE, b'PK\x03\x04', 0, "Java Archive", "application/java-archive", ThreatLevel.MEDIUM)
        self._add("Java WAR", "war", FileCategory.EXECUTABLE, b'PK\x03\x04', 0, "Java Web Archive", "application/java-archive", ThreatLevel.MEDIUM)
        
        # .NET/CLR
        self._add(".NET Assembly", "dll", FileCategory.EXECUTABLE, b'MZ', 0, ".NET Managed Assembly", "application/x-msdownload", ThreatLevel.HIGH)
        
        # WebAssembly
        self._add("WebAssembly", "wasm", FileCategory.EXECUTABLE, b'\x00asm', 0, "WebAssembly Binary", "application/wasm", ThreatLevel.MEDIUM)
        
        # DOS
        self._add("DOS COM", "com", FileCategory.EXECUTABLE, b'\xe9', 0, "DOS COM Executable", "application/x-dosexec", ThreatLevel.HIGH)
        self._add("DOS MZ", "exe", FileCategory.EXECUTABLE, b'MZ', 0, "DOS MZ Executable", "application/x-dosexec", ThreatLevel.HIGH)
        
        # ============================================================
        # SCRIPT FORMATS - SECURITY RELEVANT
        # ============================================================
        
        # Windows Scripts
        self._add("Windows Batch", "bat", FileCategory.SCRIPT, b'@echo', 0, "Windows Batch Script", "application/x-bat", ThreatLevel.MEDIUM)
        self._add("Windows CMD", "cmd", FileCategory.SCRIPT, b'@echo', 0, "Windows CMD Script", "application/x-bat", ThreatLevel.MEDIUM)
        self._add("PowerShell", "ps1", FileCategory.SCRIPT, b'#Requires', 0, "PowerShell Script", "application/x-powershell", ThreatLevel.HIGH)
        self._add("PowerShell", "ps1", FileCategory.SCRIPT, b'param(', 0, "PowerShell Script", "application/x-powershell", ThreatLevel.HIGH)
        self._add("PowerShell", "ps1", FileCategory.SCRIPT, b'function ', 0, "PowerShell Script", "application/x-powershell", ThreatLevel.HIGH)
        self._add("VBScript", "vbs", FileCategory.SCRIPT, b'CreateObject', 0, "Visual Basic Script", "text/vbscript", ThreatLevel.HIGH)
        self._add("VBScript", "vbs", FileCategory.SCRIPT, b'WScript', 0, "Visual Basic Script", "text/vbscript", ThreatLevel.HIGH)
        self._add("JScript", "js", FileCategory.SCRIPT, b'WScript', 0, "Windows JScript", "application/javascript", ThreatLevel.HIGH)
        self._add("HTA Application", "hta", FileCategory.SCRIPT, b'<HTA:', 0, "HTML Application", "application/hta", ThreatLevel.CRITICAL)
        self._add("Windows Script", "wsf", FileCategory.SCRIPT, b'<job', 0, "Windows Script File", "application/x-wsf", ThreatLevel.HIGH)
        
        # Unix Scripts
        self._add("Bash Script", "sh", FileCategory.SCRIPT, b'#!/bin/bash', 0, "Bash Shell Script", "application/x-sh", ThreatLevel.MEDIUM)
        self._add("Shell Script", "sh", FileCategory.SCRIPT, b'#!/bin/sh', 0, "POSIX Shell Script", "application/x-sh", ThreatLevel.MEDIUM)
        self._add("Zsh Script", "zsh", FileCategory.SCRIPT, b'#!/bin/zsh', 0, "Zsh Shell Script", "application/x-zsh", ThreatLevel.MEDIUM)
        self._add("Ksh Script", "ksh", FileCategory.SCRIPT, b'#!/bin/ksh', 0, "Korn Shell Script", "application/x-ksh", ThreatLevel.MEDIUM)
        self._add("Unix Script", "sh", FileCategory.SCRIPT, b'#!', 0, "Unix Script (Shebang)", "application/x-sh", ThreatLevel.MEDIUM)
        
        # Python
        self._add("Python Script", "py", FileCategory.SCRIPT, b'#!/usr/bin/python', 0, "Python Script", "text/x-python", ThreatLevel.MEDIUM)
        self._add("Python Script", "py", FileCategory.SCRIPT, b'#!/usr/bin/env python', 0, "Python Script", "text/x-python", ThreatLevel.MEDIUM)
        self._add("Python Bytecode 3.8", "pyc", FileCategory.SCRIPT, b'\x55\x0d\x0d\x0a', 0, "Python 3.8 Bytecode", "application/x-python-code", ThreatLevel.MEDIUM)
        self._add("Python Bytecode 3.9", "pyc", FileCategory.SCRIPT, b'\x61\x0d\x0d\x0a', 0, "Python 3.9 Bytecode", "application/x-python-code", ThreatLevel.MEDIUM)
        self._add("Python Bytecode 3.10", "pyc", FileCategory.SCRIPT, b'\x6f\x0d\x0d\x0a', 0, "Python 3.10 Bytecode", "application/x-python-code", ThreatLevel.MEDIUM)
        self._add("Python Bytecode 3.11", "pyc", FileCategory.SCRIPT, b'\xa7\x0d\x0d\x0a', 0, "Python 3.11 Bytecode", "application/x-python-code", ThreatLevel.MEDIUM)
        
        # Other Scripts
        self._add("Perl Script", "pl", FileCategory.SCRIPT, b'#!/usr/bin/perl', 0, "Perl Script", "text/x-perl", ThreatLevel.MEDIUM)
        self._add("Ruby Script", "rb", FileCategory.SCRIPT, b'#!/usr/bin/ruby', 0, "Ruby Script", "text/x-ruby", ThreatLevel.MEDIUM)
        self._add("Node.js Script", "js", FileCategory.SCRIPT, b'#!/usr/bin/env node', 0, "Node.js Script", "application/javascript", ThreatLevel.MEDIUM)
        self._add("PHP Script", "php", FileCategory.SCRIPT, b'<?php', 0, "PHP Script", "application/x-php", ThreatLevel.MEDIUM)
        self._add("Lua Script", "lua", FileCategory.SCRIPT, b'#!/usr/bin/lua', 0, "Lua Script", "text/x-lua", ThreatLevel.MEDIUM)
        self._add("Lua Bytecode", "luac", FileCategory.SCRIPT, b'\x1bLua', 0, "Lua Compiled Bytecode", "application/x-lua-bytecode", ThreatLevel.MEDIUM)
        
        # ============================================================
        # DOCUMENT FORMATS
        # ============================================================
        
        # PDF
        self._add("PDF Document", "pdf", FileCategory.DOCUMENT, b'%PDF-1.', 0, "PDF Document", "application/pdf", ThreatLevel.MEDIUM)
        self._add("PDF Document", "pdf", FileCategory.DOCUMENT, b'%PDF-2.', 0, "PDF 2.0 Document", "application/pdf", ThreatLevel.MEDIUM)
        
        # Microsoft Office OLE
        self._add("MS Office OLE", "doc", FileCategory.DOCUMENT, b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0, "Microsoft Office Document (OLE)", "application/msword", ThreatLevel.MEDIUM)
        
        # Microsoft Office OOXML (all are ZIP-based)
        self._add("MS Word OOXML", "docx", FileCategory.DOCUMENT, b'PK\x03\x04', 0, "Microsoft Word Document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ThreatLevel.MEDIUM)
        self._add("MS Excel OOXML", "xlsx", FileCategory.DOCUMENT, b'PK\x03\x04', 0, "Microsoft Excel Spreadsheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ThreatLevel.MEDIUM)
        self._add("MS PowerPoint OOXML", "pptx", FileCategory.DOCUMENT, b'PK\x03\x04', 0, "Microsoft PowerPoint Presentation", "application/vnd.openxmlformats-officedocument.presentationml.presentation", ThreatLevel.MEDIUM)
        
        # OpenDocument
        self._add("OpenDocument Text", "odt", FileCategory.DOCUMENT, b'PK\x03\x04', 0, "OpenDocument Text", "application/vnd.oasis.opendocument.text", ThreatLevel.LOW)
        self._add("OpenDocument Spreadsheet", "ods", FileCategory.DOCUMENT, b'PK\x03\x04', 0, "OpenDocument Spreadsheet", "application/vnd.oasis.opendocument.spreadsheet", ThreatLevel.LOW)
        self._add("OpenDocument Presentation", "odp", FileCategory.DOCUMENT, b'PK\x03\x04', 0, "OpenDocument Presentation", "application/vnd.oasis.opendocument.presentation", ThreatLevel.LOW)
        
        # Other Documents
        self._add("RTF Document", "rtf", FileCategory.DOCUMENT, b'{\\rtf', 0, "Rich Text Format", "application/rtf", ThreatLevel.MEDIUM)
        self._add("LaTeX Document", "tex", FileCategory.DOCUMENT, b'\\documentclass', 0, "LaTeX Document", "application/x-latex", ThreatLevel.SAFE)
        self._add("EPUB", "epub", FileCategory.DOCUMENT, b'PK\x03\x04', 0, "EPUB eBook", "application/epub+zip", ThreatLevel.LOW)
        self._add("MOBI eBook", "mobi", FileCategory.DOCUMENT, b'BOOKMOBI', 0, "Kindle eBook", "application/x-mobipocket-ebook", ThreatLevel.SAFE)
        self._add("FictionBook", "fb2", FileCategory.DOCUMENT, b'<?xml', 0, "FictionBook", "application/x-fictionbook+xml", ThreatLevel.SAFE)
        self._add("DjVu Document", "djvu", FileCategory.DOCUMENT, b'AT&TFORM', 0, "DjVu Document", "image/vnd.djvu", ThreatLevel.SAFE)
        self._add("PostScript", "ps", FileCategory.DOCUMENT, b'%!PS', 0, "PostScript", "application/postscript", ThreatLevel.LOW)
        self._add("Encapsulated PS", "eps", FileCategory.DOCUMENT, b'%!PS-Adobe', 0, "Encapsulated PostScript", "application/postscript", ThreatLevel.LOW)
        
        # Markup
        self._add("HTML", "html", FileCategory.DOCUMENT, b'<!DOCTYPE html', 0, "HTML Document", "text/html", ThreatLevel.LOW)
        self._add("HTML", "html", FileCategory.DOCUMENT, b'<html', 0, "HTML Document", "text/html", ThreatLevel.LOW)
        self._add("HTML", "html", FileCategory.DOCUMENT, b'<HTML', 0, "HTML Document", "text/html", ThreatLevel.LOW)
        self._add("XHTML", "xhtml", FileCategory.DOCUMENT, b'<?xml', 0, "XHTML Document", "application/xhtml+xml", ThreatLevel.LOW)
        self._add("XML", "xml", FileCategory.DOCUMENT, b'<?xml', 0, "XML Document", "application/xml", ThreatLevel.LOW)
        self._add("Markdown", "md", FileCategory.DOCUMENT, b'# ', 0, "Markdown Document", "text/markdown", ThreatLevel.SAFE)
        
        # ============================================================
        # ARCHIVE FORMATS
        # ============================================================
        
        # ZIP Family
        self._add("ZIP Archive", "zip", FileCategory.ARCHIVE, b'PK\x03\x04', 0, "ZIP Archive", "application/zip", ThreatLevel.LOW)
        self._add("ZIP Empty", "zip", FileCategory.ARCHIVE, b'PK\x05\x06', 0, "Empty ZIP Archive", "application/zip", ThreatLevel.LOW)
        self._add("ZIP Spanned", "zip", FileCategory.ARCHIVE, b'PK\x07\x08', 0, "Spanned ZIP Archive", "application/zip", ThreatLevel.LOW)
        
        # RAR Family
        self._add("RAR 5+", "rar", FileCategory.ARCHIVE, b'Rar!\x1a\x07\x01\x00', 0, "RAR Archive v5+", "application/x-rar-compressed", ThreatLevel.LOW)
        self._add("RAR 1.5-4", "rar", FileCategory.ARCHIVE, b'Rar!\x1a\x07\x00', 0, "RAR Archive v1.5-4", "application/x-rar-compressed", ThreatLevel.LOW)
        
        # 7-Zip
        self._add("7-Zip", "7z", FileCategory.ARCHIVE, b'7z\xbc\xaf\x27\x1c', 0, "7-Zip Archive", "application/x-7z-compressed", ThreatLevel.LOW)
        
        # Compression
        self._add("GZIP", "gz", FileCategory.ARCHIVE, b'\x1f\x8b', 0, "GZIP Compressed", "application/gzip", ThreatLevel.LOW)
        self._add("BZIP2", "bz2", FileCategory.ARCHIVE, b'BZh', 0, "BZIP2 Compressed", "application/x-bzip2", ThreatLevel.LOW)
        self._add("XZ", "xz", FileCategory.ARCHIVE, b'\xfd7zXZ\x00', 0, "XZ Compressed", "application/x-xz", ThreatLevel.LOW)
        self._add("LZMA", "lzma", FileCategory.ARCHIVE, b'\x5d\x00\x00', 0, "LZMA Compressed", "application/x-lzma", ThreatLevel.LOW)
        self._add("LZ4", "lz4", FileCategory.ARCHIVE, b'\x04\x22\x4d\x18', 0, "LZ4 Compressed", "application/x-lz4", ThreatLevel.LOW)
        self._add("Zstandard", "zst", FileCategory.ARCHIVE, b'\x28\xb5\x2f\xfd', 0, "Zstandard Compressed", "application/zstd", ThreatLevel.LOW)
        self._add("Snappy", "sz", FileCategory.ARCHIVE, b'\xff\x06\x00\x00', 0, "Snappy Compressed", "application/x-snappy-framed", ThreatLevel.LOW)
        
        # TAR Family
        self._add("TAR (ustar)", "tar", FileCategory.ARCHIVE, b'ustar', 257, "TAR Archive (USTAR)", "application/x-tar", ThreatLevel.LOW)
        self._add("TAR (GNU)", "tar", FileCategory.ARCHIVE, b'ustar  \x00', 257, "TAR Archive (GNU)", "application/x-tar", ThreatLevel.LOW)
        
        # Other Archives
        self._add("CAB", "cab", FileCategory.ARCHIVE, b'MSCF', 0, "Microsoft Cabinet", "application/vnd.ms-cab-compressed", ThreatLevel.LOW)
        self._add("ARJ", "arj", FileCategory.ARCHIVE, b'\x60\xea', 0, "ARJ Archive", "application/x-arj", ThreatLevel.LOW)
        self._add("LHA/LZH", "lzh", FileCategory.ARCHIVE, b'-lh', 2, "LHA Archive", "application/x-lzh-compressed", ThreatLevel.LOW)
        self._add("ACE", "ace", FileCategory.ARCHIVE, b'**ACE**', 7, "ACE Archive", "application/x-ace-compressed", ThreatLevel.LOW)
        self._add("ARC", "arc", FileCategory.ARCHIVE, b'\x1a', 0, "ARC Archive", "application/x-arc", ThreatLevel.LOW)
        self._add("CPIO", "cpio", FileCategory.ARCHIVE, b'\xc7\x71', 0, "CPIO Archive", "application/x-cpio", ThreatLevel.LOW)
        self._add("CPIO ASCII", "cpio", FileCategory.ARCHIVE, b'070701', 0, "CPIO Archive (New ASCII)", "application/x-cpio", ThreatLevel.LOW)
        self._add("RPM Package", "rpm", FileCategory.ARCHIVE, b'\xed\xab\xee\xdb', 0, "RPM Package", "application/x-rpm", ThreatLevel.LOW)
        self._add("DEB Package", "deb", FileCategory.ARCHIVE, b'!<arch>\ndebian', 0, "Debian Package", "application/x-deb", ThreatLevel.LOW)
        
        # Disk Images
        self._add("ISO 9660", "iso", FileCategory.ARCHIVE, b'CD001', 32769, "ISO 9660 CD/DVD Image", "application/x-iso9660-image", ThreatLevel.MEDIUM)
        self._add("ISO 9660", "iso", FileCategory.ARCHIVE, b'CD001', 34817, "ISO 9660 CD/DVD Image (alt)", "application/x-iso9660-image", ThreatLevel.MEDIUM)
        self._add("Apple DMG", "dmg", FileCategory.ARCHIVE, b'koly', -512, "Apple Disk Image", "application/x-apple-diskimage", ThreatLevel.MEDIUM)
        self._add("VHD", "vhd", FileCategory.VIRTUAL, b'conectix', 0, "Virtual Hard Disk", "application/x-vhd", ThreatLevel.MEDIUM)
        self._add("VHDX", "vhdx", FileCategory.VIRTUAL, b'vhdxfile', 0, "Virtual Hard Disk v2", "application/x-vhdx", ThreatLevel.MEDIUM)
        self._add("VMDK", "vmdk", FileCategory.VIRTUAL, b'KDMV', 0, "VMware Disk", "application/x-vmdk", ThreatLevel.MEDIUM)
        self._add("VDI", "vdi", FileCategory.VIRTUAL, b'<<< Oracle VM VirtualBox', 0, "VirtualBox Disk Image", "application/x-virtualbox-vdi", ThreatLevel.MEDIUM)
        self._add("QCOW2", "qcow2", FileCategory.VIRTUAL, b'QFI\xfb', 0, "QEMU Copy-on-Write v2", "application/x-qemu-disk", ThreatLevel.MEDIUM)
        
        # ============================================================
        # IMAGE FORMATS
        # ============================================================
        
        # Raster Images
        self._add("JPEG", "jpg", FileCategory.IMAGE, b'\xff\xd8\xff\xe0', 0, "JPEG Image (JFIF)", "image/jpeg", ThreatLevel.SAFE)
        self._add("JPEG EXIF", "jpg", FileCategory.IMAGE, b'\xff\xd8\xff\xe1', 0, "JPEG Image (EXIF)", "image/jpeg", ThreatLevel.SAFE)
        self._add("JPEG", "jpg", FileCategory.IMAGE, b'\xff\xd8\xff', 0, "JPEG Image", "image/jpeg", ThreatLevel.SAFE)
        self._add("PNG", "png", FileCategory.IMAGE, b'\x89PNG\r\n\x1a\n', 0, "PNG Image", "image/png", ThreatLevel.SAFE)
        self._add("GIF 87a", "gif", FileCategory.IMAGE, b'GIF87a', 0, "GIF Image (87a)", "image/gif", ThreatLevel.SAFE)
        self._add("GIF 89a", "gif", FileCategory.IMAGE, b'GIF89a', 0, "GIF Image (89a)", "image/gif", ThreatLevel.SAFE)
        self._add("BMP", "bmp", FileCategory.IMAGE, b'BM', 0, "Bitmap Image", "image/bmp", ThreatLevel.SAFE)
        self._add("TIFF LE", "tiff", FileCategory.IMAGE, b'II*\x00', 0, "TIFF Image (Little Endian)", "image/tiff", ThreatLevel.SAFE)
        self._add("TIFF BE", "tiff", FileCategory.IMAGE, b'MM\x00*', 0, "TIFF Image (Big Endian)", "image/tiff", ThreatLevel.SAFE)
        self._add("WebP", "webp", FileCategory.IMAGE, b'RIFF', 0, "WebP Image", "image/webp", ThreatLevel.SAFE)
        self._add("AVIF", "avif", FileCategory.IMAGE, b'\x00\x00\x00\x1cftypavif', 0, "AVIF Image", "image/avif", ThreatLevel.SAFE)
        self._add("HEIC", "heic", FileCategory.IMAGE, b'\x00\x00\x00\x18ftypheic', 0, "HEIC Image", "image/heic", ThreatLevel.SAFE)
        self._add("HEIF", "heif", FileCategory.IMAGE, b'\x00\x00\x00\x18ftypmif1', 0, "HEIF Image", "image/heif", ThreatLevel.SAFE)
        self._add("JPEG 2000", "jp2", FileCategory.IMAGE, b'\x00\x00\x00\x0cjP  ', 0, "JPEG 2000", "image/jp2", ThreatLevel.SAFE)
        self._add("JPEG XL", "jxl", FileCategory.IMAGE, b'\xff\x0a', 0, "JPEG XL", "image/jxl", ThreatLevel.SAFE)
        self._add("JPEG XL", "jxl", FileCategory.IMAGE, b'\x00\x00\x00\x0cJXL \x0d\x0a\x87\x0a', 0, "JPEG XL (Container)", "image/jxl", ThreatLevel.SAFE)
        
        # Icons
        self._add("ICO", "ico", FileCategory.IMAGE, b'\x00\x00\x01\x00', 0, "Windows Icon", "image/x-icon", ThreatLevel.SAFE)
        self._add("CUR", "cur", FileCategory.IMAGE, b'\x00\x00\x02\x00', 0, "Windows Cursor", "image/x-icon", ThreatLevel.SAFE)
        self._add("ICNS", "icns", FileCategory.IMAGE, b'icns', 0, "macOS Icon", "image/x-icns", ThreatLevel.SAFE)
        
        # Vector Graphics
        self._add("SVG", "svg", FileCategory.IMAGE, b'<svg', 0, "SVG Vector Image", "image/svg+xml", ThreatLevel.LOW)
        self._add("SVG", "svg", FileCategory.IMAGE, b'<?xml', 0, "SVG Vector Image", "image/svg+xml", ThreatLevel.LOW)
        
        # Raw/Professional
        self._add("PSD", "psd", FileCategory.IMAGE, b'8BPS', 0, "Adobe Photoshop Document", "image/vnd.adobe.photoshop", ThreatLevel.SAFE)
        self._add("XCF", "xcf", FileCategory.IMAGE, b'gimp xcf', 0, "GIMP Image", "image/x-xcf", ThreatLevel.SAFE)
        self._add("Canon CR2", "cr2", FileCategory.IMAGE, b'II*\x00\x10\x00\x00\x00CR', 0, "Canon Raw Image", "image/x-canon-cr2", ThreatLevel.SAFE)
        self._add("Nikon NEF", "nef", FileCategory.IMAGE, b'MM\x00*', 0, "Nikon Raw Image", "image/x-nikon-nef", ThreatLevel.SAFE)
        self._add("Adobe DNG", "dng", FileCategory.IMAGE, b'II*\x00', 0, "Digital Negative", "image/x-adobe-dng", ThreatLevel.SAFE)
        
        # ============================================================
        # AUDIO FORMATS
        # ============================================================
        
        self._add("MP3", "mp3", FileCategory.AUDIO, b'\xff\xfb', 0, "MP3 Audio", "audio/mpeg", ThreatLevel.SAFE)
        self._add("MP3", "mp3", FileCategory.AUDIO, b'\xff\xfa', 0, "MP3 Audio", "audio/mpeg", ThreatLevel.SAFE)
        self._add("MP3 ID3v2", "mp3", FileCategory.AUDIO, b'ID3', 0, "MP3 Audio (ID3v2)", "audio/mpeg", ThreatLevel.SAFE)
        self._add("FLAC", "flac", FileCategory.AUDIO, b'fLaC', 0, "FLAC Audio", "audio/flac", ThreatLevel.SAFE)
        self._add("OGG Vorbis", "ogg", FileCategory.AUDIO, b'OggS', 0, "OGG Audio", "audio/ogg", ThreatLevel.SAFE)
        self._add("WAV", "wav", FileCategory.AUDIO, b'RIFF', 0, "WAV Audio", "audio/wav", ThreatLevel.SAFE)
        self._add("AIFF", "aiff", FileCategory.AUDIO, b'FORM', 0, "AIFF Audio", "audio/aiff", ThreatLevel.SAFE)
        self._add("M4A/AAC", "m4a", FileCategory.AUDIO, b'ftyp', 4, "M4A Audio", "audio/mp4", ThreatLevel.SAFE)
        self._add("MIDI", "mid", FileCategory.AUDIO, b'MThd', 0, "MIDI Audio", "audio/midi", ThreatLevel.SAFE)
        self._add("Opus", "opus", FileCategory.AUDIO, b'OggS', 0, "Opus Audio", "audio/opus", ThreatLevel.SAFE)
        self._add("WMA", "wma", FileCategory.AUDIO, b'\x30\x26\xb2\x75', 0, "Windows Media Audio", "audio/x-ms-wma", ThreatLevel.SAFE)
        self._add("APE", "ape", FileCategory.AUDIO, b'MAC ', 0, "Monkey's Audio", "audio/ape", ThreatLevel.SAFE)
        self._add("WavPack", "wv", FileCategory.AUDIO, b'wvpk', 0, "WavPack Audio", "audio/wavpack", ThreatLevel.SAFE)
        
        # ============================================================
        # VIDEO FORMATS
        # ============================================================
        
        self._add("MP4", "mp4", FileCategory.VIDEO, b'\x00\x00\x00\x18ftypmp4', 0, "MP4 Video", "video/mp4", ThreatLevel.SAFE)
        self._add("MP4", "mp4", FileCategory.VIDEO, b'\x00\x00\x00\x1cftypmp4', 0, "MP4 Video", "video/mp4", ThreatLevel.SAFE)
        self._add("MP4", "mp4", FileCategory.VIDEO, b'ftyp', 4, "MP4 Video", "video/mp4", ThreatLevel.SAFE)
        self._add("MOV", "mov", FileCategory.VIDEO, b'moov', 4, "QuickTime Movie", "video/quicktime", ThreatLevel.SAFE)
        self._add("MOV", "mov", FileCategory.VIDEO, b'\x00\x00\x00\x14ftypqt', 0, "QuickTime Movie", "video/quicktime", ThreatLevel.SAFE)
        self._add("AVI", "avi", FileCategory.VIDEO, b'RIFF', 0, "AVI Video", "video/x-msvideo", ThreatLevel.SAFE)
        self._add("MKV", "mkv", FileCategory.VIDEO, b'\x1a\x45\xdf\xa3', 0, "Matroska Video", "video/x-matroska", ThreatLevel.SAFE)
        self._add("WebM", "webm", FileCategory.VIDEO, b'\x1a\x45\xdf\xa3', 0, "WebM Video", "video/webm", ThreatLevel.SAFE)
        self._add("FLV", "flv", FileCategory.VIDEO, b'FLV\x01', 0, "Flash Video", "video/x-flv", ThreatLevel.LOW)
        self._add("WMV", "wmv", FileCategory.VIDEO, b'\x30\x26\xb2\x75\x8e\x66\xcf\x11', 0, "Windows Media Video", "video/x-ms-wmv", ThreatLevel.SAFE)
        self._add("MPEG", "mpg", FileCategory.VIDEO, b'\x00\x00\x01\xba', 0, "MPEG Video", "video/mpeg", ThreatLevel.SAFE)
        self._add("MPEG-TS", "ts", FileCategory.VIDEO, b'\x47', 0, "MPEG Transport Stream", "video/mp2t", ThreatLevel.SAFE)
        self._add("3GP", "3gp", FileCategory.VIDEO, b'\x00\x00\x00\x14ftyp3gp', 0, "3GP Video", "video/3gpp", ThreatLevel.SAFE)
        self._add("M2TS", "m2ts", FileCategory.VIDEO, b'\x47\x40', 0, "MPEG-2 TS", "video/mp2t", ThreatLevel.SAFE)
        
        # ============================================================
        # FONT FORMATS
        # ============================================================
        
        self._add("TrueType", "ttf", FileCategory.FONT, b'\x00\x01\x00\x00', 0, "TrueType Font", "font/ttf", ThreatLevel.LOW)
        self._add("OpenType", "otf", FileCategory.FONT, b'OTTO', 0, "OpenType Font", "font/otf", ThreatLevel.LOW)
        self._add("WOFF", "woff", FileCategory.FONT, b'wOFF', 0, "Web Open Font", "font/woff", ThreatLevel.LOW)
        self._add("WOFF2", "woff2", FileCategory.FONT, b'wOF2', 0, "Web Open Font 2", "font/woff2", ThreatLevel.LOW)
        self._add("EOT", "eot", FileCategory.FONT, b'\x00\x00', 0, "Embedded OpenType", "application/vnd.ms-fontobject", ThreatLevel.LOW)
        
        # ============================================================
        # DATABASE FORMATS
        # ============================================================
        
        self._add("SQLite", "sqlite", FileCategory.DATABASE, b'SQLite format 3', 0, "SQLite Database", "application/x-sqlite3", ThreatLevel.SAFE)
        self._add("Access MDB", "mdb", FileCategory.DATABASE, b'\x00\x01\x00\x00Standard Jet', 0, "Microsoft Access", "application/x-msaccess", ThreatLevel.MEDIUM)
        self._add("Access ACCDB", "accdb", FileCategory.DATABASE, b'\x00\x01\x00\x00Standard ACE', 0, "Microsoft Access", "application/x-msaccess", ThreatLevel.MEDIUM)
        self._add("dBase", "dbf", FileCategory.DATABASE, b'\x03', 0, "dBase Database", "application/x-dbf", ThreatLevel.SAFE)
        
        # ============================================================
        # FIRMWARE/EMBEDDED
        # ============================================================
        
        self._add("UEFI Firmware", "efi", FileCategory.FIRMWARE, b'MZ', 0, "UEFI Executable", "application/octet-stream", ThreatLevel.CRITICAL)
        self._add("Android Boot", "img", FileCategory.FIRMWARE, b'ANDROID!', 0, "Android Boot Image", "application/octet-stream", ThreatLevel.HIGH)
        self._add("Squashfs", "sqsh", FileCategory.FIRMWARE, b'hsqs', 0, "Squashfs Filesystem", "application/octet-stream", ThreatLevel.MEDIUM)
        self._add("Squashfs BE", "sqsh", FileCategory.FIRMWARE, b'sqsh', 0, "Squashfs Filesystem (BE)", "application/octet-stream", ThreatLevel.MEDIUM)
        self._add("JFFS2", "jffs2", FileCategory.FIRMWARE, b'\x85\x19', 0, "JFFS2 Filesystem", "application/octet-stream", ThreatLevel.MEDIUM)
        self._add("CRAMFS", "cramfs", FileCategory.FIRMWARE, b'Compressed ROMFS', 0, "CRAMFS Filesystem", "application/octet-stream", ThreatLevel.MEDIUM)
        self._add("U-Boot", "uboot", FileCategory.FIRMWARE, b'\x27\x05\x19\x56', 0, "U-Boot Image", "application/octet-stream", ThreatLevel.MEDIUM)
        self._add("ARM Firmware", "bin", FileCategory.FIRMWARE, b'\xea\x00\x00\x00', 0, "ARM Firmware", "application/octet-stream", ThreatLevel.MEDIUM)
        
        # ============================================================
        # CRYPTO/SECURITY FORMATS
        # ============================================================
        
        self._add("PGP Public Key", "asc", FileCategory.CRYPTO, b'-----BEGIN PGP PUBLIC', 0, "PGP Public Key", "application/pgp-keys", ThreatLevel.SAFE)
        self._add("PGP Private Key", "asc", FileCategory.CRYPTO, b'-----BEGIN PGP PRIVATE', 0, "PGP Private Key", "application/pgp-keys", ThreatLevel.MEDIUM)
        self._add("PGP Message", "asc", FileCategory.CRYPTO, b'-----BEGIN PGP MESSAGE', 0, "PGP Encrypted Message", "application/pgp-encrypted", ThreatLevel.SAFE)
        self._add("PGP Signature", "asc", FileCategory.CRYPTO, b'-----BEGIN PGP SIGNATURE', 0, "PGP Signature", "application/pgp-signature", ThreatLevel.SAFE)
        self._add("X.509 Certificate", "crt", FileCategory.CRYPTO, b'-----BEGIN CERTIFICATE', 0, "X.509 Certificate (PEM)", "application/x-x509-ca-cert", ThreatLevel.SAFE)
        self._add("Private Key", "key", FileCategory.CRYPTO, b'-----BEGIN PRIVATE KEY', 0, "Private Key (PEM)", "application/x-pem-file", ThreatLevel.MEDIUM)
        self._add("RSA Private Key", "key", FileCategory.CRYPTO, b'-----BEGIN RSA PRIVATE', 0, "RSA Private Key", "application/x-pem-file", ThreatLevel.MEDIUM)
        self._add("SSH Private Key", "key", FileCategory.CRYPTO, b'-----BEGIN OPENSSH PRIVATE', 0, "OpenSSH Private Key", "application/x-pem-file", ThreatLevel.MEDIUM)
        self._add("DER Certificate", "der", FileCategory.CRYPTO, b'\x30\x82', 0, "X.509 Certificate (DER)", "application/x-x509-ca-cert", ThreatLevel.SAFE)
        self._add("PKCS12", "p12", FileCategory.CRYPTO, b'\x30\x82', 0, "PKCS#12 Container", "application/x-pkcs12", ThreatLevel.MEDIUM)
        
        # ============================================================
        # SYSTEM/MALWARE-RELATED SIGNATURES
        # ============================================================
        
        self._add("Windows LNK", "lnk", FileCategory.DATA, b'\x4c\x00\x00\x00\x01\x14\x02\x00', 0, "Windows Shortcut", "application/x-ms-shortcut", ThreatLevel.HIGH)
        self._add("Registry Hive", "reg", FileCategory.DATA, b'regf', 0, "Windows Registry Hive", "application/x-ms-reghive", ThreatLevel.MEDIUM)
        self._add("Windows Event Log", "evtx", FileCategory.DATA, b'ElfFile\x00', 0, "Windows Event Log", "application/x-ms-evtx", ThreatLevel.SAFE)
        self._add("Windows Prefetch", "pf", FileCategory.DATA, b'\x11\x00\x00\x00SCCA', 0, "Windows Prefetch", "application/octet-stream", ThreatLevel.SAFE)
        self._add("Chrome Extension", "crx", FileCategory.DATA, b'Cr24', 0, "Chrome Extension", "application/x-chrome-extension", ThreatLevel.MEDIUM)
        self._add("Firefox XPI", "xpi", FileCategory.DATA, b'PK\x03\x04', 0, "Firefox Extension", "application/x-xpinstall", ThreatLevel.MEDIUM)
        
        # ============================================================
        # DATA/CONFIG FORMATS
        # ============================================================
        
        self._add("JSON", "json", FileCategory.DATA, b'{', 0, "JSON Data", "application/json", ThreatLevel.SAFE)
        self._add("JSON Array", "json", FileCategory.DATA, b'[', 0, "JSON Array", "application/json", ThreatLevel.SAFE)
        self._add("YAML", "yaml", FileCategory.DATA, b'---', 0, "YAML Data", "application/x-yaml", ThreatLevel.SAFE)
        self._add("TOML", "toml", FileCategory.DATA, b'[', 0, "TOML Config", "application/toml", ThreatLevel.SAFE)
        self._add("INI Config", "ini", FileCategory.DATA, b'[', 0, "INI Config", "text/plain", ThreatLevel.SAFE)
        self._add("Windows INF", "inf", FileCategory.DATA, b'[Version]', 0, "Windows INF Driver", "application/x-setupscript", ThreatLevel.MEDIUM)
        
        # Sort by signature length (longest first) for accurate matching
        self.signatures.sort(key=lambda s: len(s.magic_bytes), reverse=True)
        
        self.logger.info(f"Loaded {len(self.signatures)} magic signatures")
    
    def _add(self, name: str, ext: str, cat: FileCategory, magic: bytes, 
             offset: int, desc: str, mime: str, threat: ThreatLevel) -> None:
        """Helper to add signature"""
        self.signatures.append(MagicSignature(
            name=name, extension=ext, category=cat, magic_bytes=magic,
            offset=offset, description=desc, mime_type=mime, threat_level=threat
        ))
    
    def detect(self, file_path: str, deep_scan: bool = False) -> Optional[FileTypeResult]:
        """
        Detect file type using multi-engine approach:
        1. Custom Signatures (High Precision for Malware/Obscure formats)
        2. Google Magika (AI-based, High Accuracy)
        3. LibMagic (Standard 'file' command)
        4. FileType (Header fallback)
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            self.logger.error(f"File not found: {file_path}")
            return None
        
        try:
            # Read header for custom signatures
            read_size = 65536 if deep_scan else 8192
            with open(file_path, 'rb') as f:
                header = f.read(read_size)
            
            if not header:
                return None
            
            # 1. Check Custom Signatures (Priority)
            best_match = None
            for sig in self.signatures:
                if self._match_signature(header, sig):
                    confidence = self._calculate_confidence(header, sig)
                    if best_match is None or confidence > best_match[1]:
                        best_match = (sig, confidence)
            
            # If high confidence custom match, return it
            if best_match and best_match[1] >= 0.8:
                return self._build_result(best_match[0], best_match[1], header)
            
            # 2. Try Magika (AI)
            try:
                from magika import Magika
                magika = Magika()
                res = magika.identify_path(Path(file_path))
                if res.output.score >= 0.80:  # High confidence
                    # Map Magika output to our format
                    cat = self._map_category(res.output.group)
                    return FileTypeResult(
                        detected_type=res.output.label,
                        extension=res.output.ct_label or "",
                        category=cat,
                        mime_type=res.output.mime_type,
                        confidence=res.output.score,
                        threat_level=ThreatLevel.SAFE, # Magika doesn't judge threat
                        description=f"Detected by Magika AI: {res.output.description}",
                        signature_offset=0,
                        raw_magic=header[:16]
                    )
            except ImportError:
                pass
            except Exception as e:
                self.logger.warning(f"Magika detection failed: {e}")

            # 3. Try LibMagic (python-magic)
            try:
                import magic
                # Mime type
                mime = magic.from_file(str(file_path), mime=True)
                # Description
                desc = magic.from_file(str(file_path))
                
                # If we have a custom match (low confidence), reuse its category/threat
                # Otherwise default
                return FileTypeResult(
                    detected_type=desc.split(',')[0],
                    extension="", # Magic doesn't give ext
                    category=FileCategory.UNKNOWN, 
                    mime_type=mime,
                    confidence=0.7,
                    threat_level=ThreatLevel.MEDIUM if "executable" in mime else ThreatLevel.SAFE,
                    description=f"LibMagic: {desc}",
                    signature_offset=0,
                    raw_magic=header[:16]
                )
            except ImportError:
                pass
            except Exception as e:
                self.logger.warning(f"LibMagic failed: {e}")

            # 4. Fallback: Return best custom match (even if low confidence)
            if best_match:
                return self._build_result(best_match[0], best_match[1], header)
            
            # 5. Unknown
            return FileTypeResult(
                detected_type="Unknown",
                extension="",
                category=FileCategory.UNKNOWN,
                mime_type="application/octet-stream",
                confidence=0.0,
                threat_level=ThreatLevel.MEDIUM,
                description="Unknown file type",
                signature_offset=0,
                raw_magic=header[:min(32, len(header))]
            )
            
        except PermissionError:
            self.logger.error(f"Permission denied: {file_path}")
            return None
        except Exception as e:
            self.logger.error(f"Error detecting file type: {e}")
            return None

    def _build_result(self, sig: MagicSignature, confidence: float, header: bytes) -> FileTypeResult:
        """Helper to build result from signature"""
        additional_info = {}
        if sig.category == FileCategory.EXECUTABLE:
            additional_info = self._analyze_executable(header, sig)
        
        return FileTypeResult(
            detected_type=sig.name,
            extension=sig.extension,
            category=sig.category,
            mime_type=sig.mime_type,
            confidence=confidence,
            threat_level=sig.threat_level,
            description=sig.description,
            signature_offset=sig.offset,
            raw_magic=header[:min(32, len(header))],
            additional_info=additional_info
        )

    def _map_category(self, group: str) -> FileCategory:
        """Map Magika group to FileCategory"""
        group = group.lower()
        if "executable" in group or "code" in group: return FileCategory.EXECUTABLE
        if "document" in group or "text" in group: return FileCategory.DOCUMENT
        if "archive" in group: return FileCategory.ARCHIVE
        if "image" in group: return FileCategory.IMAGE
        if "audio" in group: return FileCategory.AUDIO
        if "video" in group: return FileCategory.VIDEO
        return FileCategory.DATA

    
    def _match_signature(self, header: bytes, sig: MagicSignature) -> bool:
        """Check if file header matches a signature"""
        offset = sig.offset
        if offset < 0:
            # Negative offset means from end - not supported in header check
            return False
        if offset + len(sig.magic_bytes) > len(header):
            return False
        return header[offset:offset + len(sig.magic_bytes)] == sig.magic_bytes
    
    def _calculate_confidence(self, header: bytes, sig: MagicSignature) -> float:
        """Calculate confidence score"""
        base_confidence = min(1.0, len(sig.magic_bytes) / 8.0)
        if sig.offset == 0:
            base_confidence *= 1.1
        return min(1.0, base_confidence)
    
    def _analyze_executable(self, header: bytes, sig: MagicSignature) -> Dict[str, Any]:
        """Analyze executable files"""
        info = {}
        if sig.extension in ('exe', 'dll', 'scr', 'sys') and header[:2] == b'MZ':
            try:
                pe_offset = struct.unpack('<I', header[0x3C:0x40])[0]
                if pe_offset + 4 <= len(header):
                    if header[pe_offset:pe_offset+4] == b'PE\x00\x00':
                        info['is_valid_pe'] = True
                        if pe_offset + 6 <= len(header):
                            machine = struct.unpack('<H', header[pe_offset+4:pe_offset+6])[0]
                            machine_types = {0x014c: 'x86', 0x8664: 'x64', 0x01c0: 'ARM', 0xaa64: 'ARM64'}
                            info['architecture'] = machine_types.get(machine, f'0x{machine:04x}')
                        if pe_offset + 8 <= len(header):
                            info['num_sections'] = struct.unpack('<H', header[pe_offset+6:pe_offset+8])[0]
            except Exception:
                pass
        return info
    
    def get_extension_mismatch(self, file_path: str, result: FileTypeResult) -> Optional[Dict[str, Any]]:
        """Check if extension matches detected type"""
        file_path = Path(file_path)
        actual_ext = file_path.suffix.lower().lstrip('.')
        expected_ext = result.extension.lower()
        
        extension_groups = {
            'jpeg': ['jpg', 'jpeg'], 'tiff': ['tif', 'tiff'], 'htm': ['htm', 'html'],
            'exe': ['exe', 'dll', 'scr', 'com', 'sys'], 'docx': ['docx', 'xlsx', 'pptx', 'zip'],
            'mp4': ['mp4', 'm4v', 'm4a'], 'tar': ['tar', 'tgz', 'tar.gz']
        }
        
        for group in extension_groups.values():
            if expected_ext in group and actual_ext in group:
                return None
        
        if actual_ext != expected_ext and expected_ext:
            return {
                'actual_extension': actual_ext,
                'detected_type': result.detected_type,
                'expected_extension': expected_ext,
                'severity': 'CRITICAL' if result.category == FileCategory.EXECUTABLE else 'WARNING',
                'message': f"File claims to be .{actual_ext} but is actually {result.detected_type} (.{expected_ext})"
            }
        return None
