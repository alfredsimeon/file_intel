#!/bin/bash
# FILE-INTEL Build Script for Linux/macOS
# Builds standalone executable using PyInstaller

echo "========================================"
echo "FILE-INTEL Build Script"
echo "========================================"
echo

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 not found"
    exit 1
fi

# Check PyInstaller
python3 -c "import PyInstaller" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing PyInstaller..."
    pip3 install pyinstaller
fi

echo
echo "Building FILE-INTEL standalone executable..."
echo

# Clean previous builds
rm -rf dist build

# Build using spec file
pyinstaller FILE-INTEL.spec --clean

if [ $? -ne 0 ]; then
    echo
    echo "ERROR: Build failed!"
    exit 1
fi

echo
echo "========================================"
echo "BUILD COMPLETE!"
echo "========================================"
echo
echo "Executable location: dist/FILE-INTEL"
echo
echo "To run: ./dist/FILE-INTEL --gui"
echo
