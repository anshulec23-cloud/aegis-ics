"""
Aegis ICS v2.5.0 — Automated Standalone Executable Build Runner
==============================================================
Rebuilt from scratch. Cleans prior build artifacts, compiles the standalone
AegisICS.exe binary using PyInstaller, and verifies the generated executable.

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

    print("=" * 60)
    print(" Aegis ICS v2.5.0 — Standalone Executable Build Pipeline")
    print("=" * 60)

    # 1. Clean previous build artifacts & release file locks
    if sys.platform == "win32":
        subprocess.run(["powershell", "-Command", "Stop-Process -Name AegisICS -Force -ErrorAction SilentlyContinue"], capture_output=True)

    print("\n[1/3] Purging build/ and dist/ directories...")
    for folder in ["build", "dist"]:
        folder_path = os.path.join(root_dir, folder)
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path, ignore_errors=True)
            print(f"      Removed {folder}/")

    # 2. Verify spec file exists
    spec_file = os.path.join(root_dir, "build_scripts", "AegisICS.spec")
    if not os.path.exists(spec_file):
        print(f"[ERROR] PyInstaller specification file not found: {spec_file}")
        sys.exit(1)

    # 3. Execute PyInstaller compilation
    print("\n[2/3] Compiling standalone executable with PyInstaller...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        spec_file,
        "--noconfirm",
        "--clean"
    ]
    print(f"      Command: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"\n[ERROR] PyInstaller compilation failed with exit code {result.returncode}")
        sys.exit(result.returncode)

    # 4. Verify output binary
    print("\n[3/3] Verifying generated executable binary...")
    target_exe = os.path.join(root_dir, "dist", "AegisICS.exe")
    if os.path.exists(target_exe):
        size_bytes = os.path.getsize(target_exe)
        size_mb = size_bytes / (1024 * 1024)
        print("=" * 60)
        print(" BUILD COMPLETED SUCCESSFULLY!")
        print(f" Executable: {target_exe}")
        print(f" File Size:  {size_mb:.2f} MB ({size_bytes:,} bytes)")
        print("=" * 60)
    else:
        print("=" * 60)
        print(f"[ERROR] Target binary not found: {target_exe}")
        print("=" * 60)
        sys.exit(1)

if __name__ == "__main__":
    main()
