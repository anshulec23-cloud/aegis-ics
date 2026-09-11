"""
Aegis ICS v2.5.0 — Python Automated Build Runner
================================================
Cross-platform build script to compile the Aegis ICS standalone executable
using PyInstaller.

Usage:
    python build_scripts/build.py
"""

import os
import sys
import shutil
import subprocess

def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root_dir)

    print("=" * 50)
    print(" Aegis ICS v2.5.0 — Automated Executable Compiler")
    print("=" * 50)

    # 1. Clean previous builds
    print("[1/3] Purging build and dist directories...")
    for folder in ["build", "dist"]:
        folder_path = os.path.join(root_dir, folder)
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path, ignore_errors=True)

    # 2. Run PyInstaller
    spec_file = os.path.join(root_dir, "build_scripts", "AegisICS.spec")
    if not os.path.exists(spec_file):
        print(f"[ERROR] Specification file not found: {spec_file}")
        sys.exit(1)

    print(f"[2/3] Compiling standalone executable with PyInstaller...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        spec_file,
        "--noconfirm",
        "--clean"
    ]
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"\n[ERROR] PyInstaller compilation failed with code {result.returncode}")
        sys.exit(result.returncode)

    # 3. Verify output
    target_exe = os.path.join(root_dir, "dist", "AegisICS.exe")
    if os.path.exists(target_exe):
        size_mb = os.path.getsize(target_exe) / (1024 * 1024)
        print("=" * 50)
        print(" BUILD SUCCESSFUL!")
        print(f" Executable: {target_exe}")
        print(f" Size: {size_mb:.2f} MB")
        print("=" * 50)
    else:
        print("=" * 50)
        print(f"[ERROR] Expected binary not found: {target_exe}")
        print("=" * 50)
        sys.exit(1)

if __name__ == "__main__":
    main()
