@echo off
REM FILE-INTEL Build Script for Windows
REM Builds standalone executable using PyInstaller

echo ========================================
echo FILE-INTEL Build Script
echo ========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH
    exit /b 1
)

REM Check PyInstaller
python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo.
echo Building FILE-INTEL standalone executable...
echo.

REM Clean previous builds
if exist "dist" rmdir /s /q dist
if exist "build" rmdir /s /q build

REM Build using spec file
python -m PyInstaller FILE-INTEL.spec --clean

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    exit /b 1
)

echo.
echo ========================================
echo BUILD COMPLETE!
echo ========================================
echo.
echo Executable location: dist\FILE-INTEL.exe
echo.
echo To run: dist\FILE-INTEL.exe --gui
echo.

pause
