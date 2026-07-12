"""
Aegis ICS — Automated Windows Build Script
=============================================
Chains: Source → (Optional: PyArmor obfuscation) → PyInstaller freeze → Inno Setup installer.

Usage:
    python build/build_windows.py                # Full build
    python build/build_windows.py --skip-obf     # Skip PyArmor (dev builds)
    python build/build_windows.py --skip-inno    # Skip Inno Setup (test builds)

Requirements:
    pip install pyinstaller pyarmor
    Inno Setup 6.x installed (iscc.exe on PATH or in default location)

Output:
    dist/AegisICS/                         — Frozen application folder
    installer_output/Aegis_ICS_Setup_v3.0.0.exe  — Windows installer
"""

import os
import sys
import shutil
import subprocess
import argparse
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
VERSION = "3.0.0"
APP_NAME = "AegisICS"

# Resolve directories relative to this script
SCRIPT_DIR = Path(__file__).resolve().parent          # build/
PROJECT_ROOT = SCRIPT_DIR.parent                       # aegis-ics/
SOURCE_DIR = PROJECT_ROOT / "version-two"
SPEC_FILE = SCRIPT_DIR / "aegis_ics.spec"
ISS_FILE = SCRIPT_DIR / "aegis_installer.iss"
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build_temp"
OBF_DIR = PROJECT_ROOT / "obfuscated"
INSTALLER_OUTPUT = PROJECT_ROOT / "installer_output"

# Files to obfuscate (YOUR code only — not third-party libraries)
OBFUSCATE_FILES = [
    "app.py",
    "database.py",
    "safety_enforcer.py",
    "serial_gateway.py",
    "security.py",
    "updater.py",
    "tray.py",
    "launcher.py",
]

# Files to EXCLUDE from obfuscation (ML model loading uses pickle)
OBFUSCATE_EXCLUDE = [
    "train_model.py",
    "simulator.py",
    "test_v2.py",
    "gunicorn.conf.py",
]


def step(msg: str):
    """Print a formatted build step header."""
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")


def clean_previous_builds():
    """Remove old build artifacts."""
    step("Step 0: Cleaning previous builds")
    for d in [DIST_DIR, BUILD_DIR, OBF_DIR, INSTALLER_OUTPUT]:
        if d.exists():
            print(f"  Removing: {d}")
            shutil.rmtree(d, ignore_errors=True)
    print("  Clean complete.")


def run_pyarmor():
    """Obfuscate Python source files using PyArmor."""
    step("Step 1: PyArmor Obfuscation")

    # Create obfuscated output directory
    OBF_DIR.mkdir(parents=True, exist_ok=True)

    # Copy entire source directory first
    obf_source = OBF_DIR / "version-two"
    if obf_source.exists():
        shutil.rmtree(obf_source)
    shutil.copytree(SOURCE_DIR, obf_source)

    # Obfuscate only the specified files
    files_to_obf = [str(obf_source / f) for f in OBFUSCATE_FILES if (obf_source / f).exists()]

    if not files_to_obf:
        print("  WARNING: No files found to obfuscate. Skipping.")
        return obf_source

    pyarmor_exe = str(Path(sys.executable).parent / "pyarmor.exe")
    cmd = [
        pyarmor_exe, "gen",
        "--output", str(obf_source),
        "--platform", "windows.x86_64",
        "--mix-str",
    ] + files_to_obf

    print(f"  Running: {' '.join(cmd[:6])} ... ({len(files_to_obf)} files)")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"  ERROR: PyArmor failed:\n{result.stderr}")
        print("  Falling back to unobfuscated source.")
        return SOURCE_DIR

    print("  Obfuscation complete.")
    return obf_source


def run_pyinstaller(source_dir: Path):
    """Freeze the application using PyInstaller."""
    step("Step 2: PyInstaller Build")

    # Set SOURCE_DIR environment variable for the spec file
    os.environ["AEGIS_SOURCE_DIR"] = str(source_dir)

    pyinstaller_exe = str(Path(sys.executable).parent / "pyinstaller.exe")
    cmd = [
        pyinstaller_exe,
        "--clean",
        "--noconfirm",
        "--distpath", str(DIST_DIR),
        "--workpath", str(BUILD_DIR),
        str(SPEC_FILE),
    ]

    print(f"  Running: {' '.join(cmd[:5])} ...")
    result = subprocess.run(cmd, capture_output=False)

    if result.returncode != 0:
        print("  ERROR: PyInstaller build failed!")
        sys.exit(1)

    # Verify output exists
    app_dir = DIST_DIR / APP_NAME
    if not app_dir.exists():
        print(f"  ERROR: Expected output directory not found: {app_dir}")
        sys.exit(1)

    print(f"  Build complete: {app_dir}")
    return app_dir


def ensure_static_dir():
    """Ensure the static directory exists with at least a placeholder icon."""
    static_dir = SOURCE_DIR / "static"
    static_dir.mkdir(exist_ok=True)

    # Create a minimal icon.ico if none exists
    icon_path = static_dir / "icon.ico"
    if not icon_path.exists():
        print("  NOTE: No icon.ico found. The build will proceed without a custom icon.")


def run_inno_setup():
    """Compile the Inno Setup installer."""
    step("Step 3: Inno Setup Installer")

    # Find iscc.exe (Inno Setup Compiler)
    iscc_paths = [
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
        shutil.which("iscc") or "",
    ]

    iscc = None
    for p in iscc_paths:
        if p and os.path.isfile(p):
            iscc = p
            break

    if iscc is None:
        print("  WARNING: Inno Setup (iscc.exe) not found!")
        print("  Download from: https://jrsoftware.org/isdl.php")
        print("  Skipping installer creation. Your frozen app is in: dist/AegisICS/")
        return

    cmd = [iscc, str(ISS_FILE)]
    print(f"  Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False)

    if result.returncode != 0:
        print("  ERROR: Inno Setup compilation failed!")
        sys.exit(1)

    print(f"  Installer created in: {INSTALLER_OUTPUT}")


def main():
    parser = argparse.ArgumentParser(description="Build Aegis ICS Windows Application")
    parser.add_argument("--skip-obf", action="store_true", help="Skip PyArmor obfuscation")
    parser.add_argument("--skip-inno", action="store_true", help="Skip Inno Setup installer")
    parser.add_argument("--clean-only", action="store_true", help="Only clean build artifacts")
    args = parser.parse_args()

    print(f"Aegis ICS Build System v{VERSION}")
    print(f"Project Root: {PROJECT_ROOT}")

    clean_previous_builds()

    if args.clean_only:
        print("\nClean complete. Exiting.")
        return

    ensure_static_dir()

    # Step 1: Obfuscation
    if args.skip_obf:
        print("\n  [SKIPPED] PyArmor obfuscation (--skip-obf)")
        build_source = SOURCE_DIR
    else:
        build_source = run_pyarmor()

    # Step 2: PyInstaller
    app_dir = run_pyinstaller(build_source)

    # Step 3: Inno Setup
    if args.skip_inno:
        print("\n  [SKIPPED] Inno Setup installer (--skip-inno)")
    else:
        run_inno_setup()

    step("BUILD COMPLETE")
    print(f"  Frozen app:  {DIST_DIR / APP_NAME}")
    if not args.skip_inno:
        print(f"  Installer:   {INSTALLER_OUTPUT}")
    print(f"\n  To test: run  dist\\{APP_NAME}\\{APP_NAME}.exe")


if __name__ == "__main__":
    main()
