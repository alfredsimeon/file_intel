"""
FILE-INTEL: Military-Grade File Type Identifier
Main Package Initialization
"""

__version__ = "1.0.0"
__author__ = "FILE-INTEL Team"
__description__ = "Military-Grade File Type Identifier for Red Team Operations"

from .config import Config
from .core.file_scanner import FileScanner

__all__ = ["Config", "FileScanner", "__version__"]
