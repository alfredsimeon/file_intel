"""
FILE-INTEL: Military-Grade File Type Identifier
Entry point script for quick launching
"""

import sys
import os

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from file_intel.main import main

if __name__ == "__main__":
    main()
