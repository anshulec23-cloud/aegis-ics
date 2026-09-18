#!/bin/sh
# Aegis ICS v2.5.2 — Linux Build Script for Debian & MX Linux
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

echo "================================================================="
echo " Aegis ICS v2.5.2 — Automated Linux Build Launcher"
echo "================================================================="

# Detect Python interpreter
if which python3 >/dev/null 2>&1; then
    PYTHON=python3
elif which python >/dev/null 2>&1; then
    PYTHON=python
else
    echo "[ERROR] Python 3 not found in PATH."
    exit 1
fi

echo "Using Python: $($PYTHON --version)"

# Check for PyInstaller
if ! $PYTHON -m PyInstaller --version >/dev/null 2>&1; then
    echo "PyInstaller not found. Attempting to install PyInstaller..."
    $PYTHON -m pip install pyinstaller || pip3 install pyinstaller || true
fi

# Execute Linux build pipeline
$PYTHON "$SCRIPT_DIR/build_linux.py"
