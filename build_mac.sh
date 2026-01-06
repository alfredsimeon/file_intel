#!/bin/bash
# FILE-INTEL Build Script for macOS
# Handles icon creation and app bundling

echo "========================================"
echo "FILE-INTEL Build Script (macOS)"
echo "========================================"
echo

# 1. Dependency Check
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 not found"
    exit 1
fi

# Check PyInstaller
python3 -c "import PyInstaller" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing PyInstaller..."
    pip3 install pyinstaller Pillow
fi

# 2. Icon Generation (needs sips and iconutil)
echo "Generating macOS icon..."
if command -v sips &> /dev/null && command -v iconutil &> /dev/null; then
    mkdir -p assets/icon.iconset
    
    # Generate sizes
    sips -z 16 16     assets/logo.png --out assets/icon.iconset/icon_16x16.png
    sips -z 32 32     assets/logo.png --out assets/icon.iconset/icon_16x16@2x.png
    sips -z 32 32     assets/logo.png --out assets/icon.iconset/icon_32x32.png
    sips -z 64 64     assets/logo.png --out assets/icon.iconset/icon_32x32@2x.png
    sips -z 128 128   assets/logo.png --out assets/icon.iconset/icon_128x128.png
    sips -z 256 256   assets/logo.png --out assets/icon.iconset/icon_128x128@2x.png
    sips -z 256 256   assets/logo.png --out assets/icon.iconset/icon_256x256.png
    sips -z 512 512   assets/logo.png --out assets/icon.iconset/icon_256x256@2x.png
    sips -z 512 512   assets/logo.png --out assets/icon.iconset/icon_512x512.png
    
    # Convert to icns
    iconutil -c icns assets/icon.iconset
    rm -rf assets/icon.iconset
    
    echo "Icon created: assets/icon.icns"
else
    echo "WARNING: sips/iconutil not found (linux?). Skipping icon generation."
    echo "App will use default icon."
fi

# 3. Build
echo
echo "Building FILE-INTEL.app..."
echo

rm -rf dist build
pyinstaller FILE-INTEL.spec --clean --noconfirm

if [ $? -eq 0 ]; then
    echo
    echo "========================================"
    echo "BUILD COMPLETE!"
    echo "========================================"
    echo
    echo "App Bundle: dist/FILE-INTEL.app"
    echo
    echo "To run:"
    echo "open dist/FILE-INTEL.app"
    echo
else
    echo "ERROR: Build failed"
    exit 1
fi
