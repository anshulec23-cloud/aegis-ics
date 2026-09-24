"""
Aegis ICS v2.5.2 — Automated Windows Standalone Executable Builder
==================================================================
Compiles the self-contained, air-gapped AegisICS.exe binary using PyInstaller.
Bundles Python runtime, embedded PyWebView, Flask backend, SQLite schema,
ReportLab PDF engine, Random Forest ML pipeline, reference firmware, and vendor assets.

Usage:
    python build_scripts/build_windows.py
"""

import os
import sys
import shutil
import subprocess

def build_windows():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    os.chdir(project_root)

    print("=" * 65)
    print(" Aegis ICS v2.5.2 — Production Windows Executable Build Pipeline")
    print("=" * 65)

    # 1. Kill any running AegisICS.exe processes to unlock binary file
    if sys.platform == "win32":
        print("\n[1/4] Terminating any active AegisICS processes...")
        subprocess.run(
            ["powershell", "-Command", "Stop-Process -Name AegisICS -Force -ErrorAction SilentlyContinue"],
            capture_output=True
        )

    # 2. Purge previous build staging and binary
    print("\n[2/4] Purging build/ staging directory and previous binary...")
    build_dir = os.path.join(project_root, "build")
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir, ignore_errors=True)
        print("      Purged build/")

    dist_dir = os.path.join(project_root, "dist")
    os.makedirs(dist_dir, exist_ok=True)
    target_exe = os.path.join(dist_dir, "AegisICS.exe")
    if os.path.exists(target_exe):
        try:
            os.remove(target_exe)
            print("      Removed previous dist/AegisICS.exe")
        except Exception as e:
            print(f"      [WARN] Could not remove previous binary: {e}")

    # 3. Check specification file
    spec_file = os.path.join(script_dir, "AegisICS.spec")
    if not os.path.exists(spec_file):
        print(f"[ERROR] Specification file not found at: {spec_file}")
        sys.exit(1)

    # 4. Compile with PyInstaller
    print("\n[3/4] Compiling AegisICS.exe with PyInstaller...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        spec_file,
        "--noconfirm",
        "--clean"
    ]
    print(f"      Command: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print(f"\n[ERROR] PyInstaller compilation failed with exit code: {result.returncode}")
        sys.exit(result.returncode)

    # 5. Verify generated binary
    print("\n[4/4] Verifying generated executable binary...")
    if os.path.exists(target_exe):
        size_bytes = os.path.getsize(target_exe)
        size_mb = size_bytes / (1024 * 1024)
        print("=" * 65)
        print(" WINDOWS BUILD COMPLETED SUCCESSFULLY!")
        print(f" Executable: {target_exe}")
        print(f" File Size:  {size_mb:.2f} MB ({size_bytes:,} bytes)")
        print("=" * 65)
        return True
    else:
        print("=" * 65)
        print(f"[ERROR] Target binary was not generated: {target_exe}")
        print("=" * 65)
        sys.exit(1)

if __name__ == "__main__":
    build_windows()
