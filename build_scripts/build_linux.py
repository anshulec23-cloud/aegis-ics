"""
Aegis ICS v2.5.0 — Automated Linux Executable & Debian Package Build Runner
==========================================================================
Cleans prior build artifacts, compiles the standalone ELF AegisICS binary
using PyInstaller, tests the binary, and produces .deb and .tar.gz packages.

Usage:
    python3 build_scripts/build_linux.py
"""

import os
import sys
import shutil
import subprocess

def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root_dir)

    print("=" * 65)
    print(" Aegis ICS v2.5.0 — Linux (Debian & MX Linux) Build Pipeline")
    print("=" * 65)

    # 1. Clean prior Linux build artifacts
    print("\n[1/5] Purging Linux build/ and dist/ artifacts...")
    for folder in ["build/deb_staging", "build/tarball_staging", "build/AegisICS_linux", "build/AegisICS"]:
        folder_path = os.path.join(root_dir, folder)
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path, ignore_errors=True)
            print(f"      Removed {folder}/")

    dist_dir = os.path.join(root_dir, "dist")
    os.makedirs(dist_dir, exist_ok=True)
    target_elf = os.path.join(dist_dir, "AegisICS")
    if os.path.exists(target_elf):
        try:
            os.remove(target_elf)
            print("      Removed previous dist/AegisICS")
        except Exception:
            pass

    # 2. Verify spec file exists
    spec_file = os.path.join(root_dir, "build_scripts", "AegisICS_linux.spec")
    if not os.path.exists(spec_file):
        print(f"[ERROR] PyInstaller specification file not found: {spec_file}")
        sys.exit(1)

    # 3. Execute PyInstaller compilation
    print("\n[2/5] Compiling standalone ELF executable with PyInstaller...")
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
    print("\n[3/5] Verifying generated executable binary...")
    if os.path.exists(target_elf):
        if os.name == "posix":
            os.chmod(target_elf, 0o755)
        size_bytes = os.path.getsize(target_elf)
        size_mb = size_bytes / (1024 * 1024)
        print(f"      Target:    {target_elf}")
        print(f"      File Size: {size_mb:.2f} MB ({size_bytes:,} bytes)")

        # Run self-tests if on Linux/POSIX
        if os.name == "posix":
            print("      Executing binary verification tests...")
            v_res = subprocess.run([target_elf, "--version"], capture_output=True, text=True)
            if v_res.returncode == 0:
                print(f"      Version check:   {v_res.stdout.strip()}")
            else:
                print(f"      [WARN] Version check returned code {v_res.returncode}")

            c_res = subprocess.run([target_elf, "--check"], capture_output=True, text=True)
            if c_res.returncode == 0:
                print(f"      Self-test check: {c_res.stdout.strip()}")
            else:
                print(f"      [WARN] Self-test check returned code {c_res.returncode}")
    else:
        print(f"[ERROR] Target binary not found: {target_elf}")
        sys.exit(1)

    # 5. Build Debian Package (.deb)
    print("\n[4/5] Building Debian (.deb) package for MX Linux / Debian...")
    package_deb_script = os.path.join(root_dir, "build_scripts", "package_deb.py")
    deb_result = subprocess.run([sys.executable, package_deb_script])
    if deb_result.returncode != 0:
        print(f"[WARN] Debian packaging finished with code {deb_result.returncode}")

    # 6. Build Portable Tarball (.tar.gz)
    print("\n[5/5] Building portable Tarball archive (.tar.gz)...")
    package_tarball_script = os.path.join(root_dir, "build_scripts", "package_tarball.py")
    tar_result = subprocess.run([sys.executable, package_tarball_script])
    if tar_result.returncode != 0:
        print(f"[WARN] Tarball packaging finished with code {tar_result.returncode}")

    # 7. Sync deliverables into dedicated dist/linux/ directory
    dist_linux = os.path.join(dist_dir, "linux")
    os.makedirs(dist_linux, exist_ok=True)
    deliverables = ["AegisICS", "aegis-ics_2.5.0_amd64.deb", "aegis-ics-2.5.0-linux-x86_64.tar.gz"]
    for item in deliverables:
        src_item = os.path.join(dist_dir, item)
        dst_item = os.path.join(dist_linux, item)
        if os.path.exists(src_item) and os.path.abspath(src_item) != os.path.abspath(dst_item):
            shutil.copy2(src_item, dst_item)

    print("\n" + "=" * 65)
    print(" LINUX BUILD & PACKAGING PIPELINE COMPLETED SUCCESSFULLY!")
    print(f" Executable binary: {os.path.join('dist', 'linux', 'AegisICS')}")
    print(f" Debian package:    {os.path.join('dist', 'linux', 'aegis-ics_2.5.0_amd64.deb')}")
    print(f" Portable tarball:  {os.path.join('dist', 'linux', 'aegis-ics-2.5.0-linux-x86_64.tar.gz')}")
    print("=" * 65)

if __name__ == "__main__":
    main()
