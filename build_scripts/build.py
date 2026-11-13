"""
Aegis ICS v2.5.2 — Universal Multi-Platform Build Dispatcher
============================================================
Detects the host operating system and coordinates compilation of standalone
executables and packages for Windows (PyInstaller .exe) or Linux (ELF, .deb, .tar.gz).

Usage:
    python build_scripts/build.py
    python build_scripts/build.py --windows
    python build_scripts/build.py --linux
"""

import os
import sys
import subprocess
import argparse

def main():
    parser = argparse.ArgumentParser(description="Aegis ICS Universal Build Dispatcher")
    parser.add_argument("--windows", action="store_true", help="Force Windows build pipeline")
    parser.add_argument("--linux", action="store_true", help="Force Linux build pipeline")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    os.chdir(project_root)

    print("=" * 65)
    print(" Aegis ICS v2.5.2 — Universal Production Build Pipeline")
    print("=" * 65)

    is_windows = sys.platform == "win32" or args.windows
    is_linux = (not sys.platform == "win32" and not args.windows) or args.linux

    if is_windows and not args.linux:
        print("[Dispatcher] Target OS: Windows (x86_64)")
        win_script = os.path.join(script_dir, "build_windows.py")
        res = subprocess.run([sys.executable, win_script])
        sys.exit(res.returncode)
    elif is_linux:
        print("[Dispatcher] Target OS: Linux (Debian / MX Linux x86_64)")
        linux_script = os.path.join(script_dir, "build_linux.py")
        res = subprocess.run([sys.executable, linux_script])
        sys.exit(res.returncode)
    else:
        print(f"[ERROR] Unsupported target environment: {sys.platform}")
        sys.exit(1)

if __name__ == "__main__":
    main()
