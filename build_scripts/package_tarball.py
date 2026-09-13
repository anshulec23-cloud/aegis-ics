"""
Aegis ICS v2.5.0 — Linux Portable Tarball (.tar.gz) Builder
===========================================================
Bundles the standalone ELF binary with launcher scripts, icons,
and installation utilities into a self-contained tarball archive.

Usage:
    python build_scripts/package_tarball.py
"""

import os
import sys
import shutil
import tarfile

def build_tarball():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    os.chdir(project_root)

    print("=" * 60)
    print(" Aegis ICS v2.5.0 — Linux Tarball (.tar.gz) Packaging Pipeline")
    print("=" * 60)

    dist_dir = os.path.join(project_root, "dist")
    target_binary = os.path.join(dist_dir, "AegisICS")
    tarball_name = "aegis-ics-2.5.0-linux-x86_64.tar.gz"
    output_tarball = os.path.join(dist_dir, tarball_name)

    if not os.path.exists(target_binary):
        print(f"[ERROR] Standalone ELF binary not found at: {target_binary}")
        print("Please compile the binary first using: python build_scripts/build_linux.py")
        sys.exit(1)

    staging_dir = os.path.join(project_root, "build", "tarball_staging", "aegis-ics-2.5.0")
    if os.path.exists(staging_dir):
        shutil.rmtree(staging_dir, ignore_errors=True)
    os.makedirs(staging_dir, exist_ok=True)

    print("\n[1/3] Assembling portable directory structure...")
    
    # 1. Binary
    shutil.copy2(target_binary, staging_dir)
    if os.name == "posix":
        os.chmod(os.path.join(staging_dir, "AegisICS"), 0o755)

    # 2. Desktop file and icons
    shutil.copy2(os.path.join(project_root, "debian", "aegis-ics.desktop"), staging_dir)
    svg_src = os.path.join(project_root, "src", "static", "achilles_icon.svg")
    png_src = os.path.join(project_root, "src", "static", "icon.png")
    if os.path.exists(svg_src):
        shutil.copy2(svg_src, os.path.join(staging_dir, "aegis-ics.svg"))
    if os.path.exists(png_src):
        shutil.copy2(png_src, os.path.join(staging_dir, "aegis-ics.png"))

    # 3. Portable run.sh script
    run_sh = os.path.join(staging_dir, "run.sh")
    with open(run_sh, "w", encoding="utf-8", newline="\n") as f:
        f.write("""#!/bin/sh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export AEGIS_DATA_DIR="$SCRIPT_DIR"
exec "$SCRIPT_DIR/AegisICS" "$@"
""")
    if os.name == "posix":
        os.chmod(run_sh, 0o755)

    # 4. User-local / System install.sh script
    install_sh = os.path.join(staging_dir, "install.sh")
    with open(install_sh, "w", encoding="utf-8", newline="\n") as f:
        f.write("""#!/bin/sh
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Installing Aegis ICS v2.5.0..."

if [ "$(id -u)" -eq 0 ]; then
    # System-wide installation
    INSTALL_DIR="/opt/aegis-ics"
    BIN_DIR="/usr/local/bin"
    APPS_DIR="/usr/share/applications"
    ICONS_DIR="/usr/share/icons/hicolor/scalable/apps"
    PIXMAP_DIR="/usr/share/pixmaps"
    
    mkdir -p "$INSTALL_DIR" "$BIN_DIR" "$APPS_DIR" "$ICONS_DIR" "$PIXMAP_DIR"
    cp -f "$SCRIPT_DIR/AegisICS" "$INSTALL_DIR/AegisICS"
    chmod 755 "$INSTALL_DIR/AegisICS"
    ln -sf "$INSTALL_DIR/AegisICS" "$BIN_DIR/aegis-ics"
    
    cp -f "$SCRIPT_DIR/aegis-ics.desktop" "$APPS_DIR/aegis-ics.desktop"
    if [ -f "$SCRIPT_DIR/aegis-ics.svg" ]; then
        cp -f "$SCRIPT_DIR/aegis-ics.svg" "$ICONS_DIR/aegis-ics.svg"
    fi
    if [ -f "$SCRIPT_DIR/aegis-ics.png" ]; then
        cp -f "$SCRIPT_DIR/aegis-ics.png" "$PIXMAP_DIR/aegis-ics.png"
    fi
    which update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$APPS_DIR" || true
    echo "System-wide installation complete. Launch with 'aegis-ics' or from Application Menu."
else
    # User-local installation
    INSTALL_DIR="$HOME/.local/share/aegis-ics"
    BIN_DIR="$HOME/.local/bin"
    APPS_DIR="$HOME/.local/share/applications"
    ICONS_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
    
    mkdir -p "$INSTALL_DIR" "$BIN_DIR" "$APPS_DIR" "$ICONS_DIR"
    cp -f "$SCRIPT_DIR/AegisICS" "$INSTALL_DIR/AegisICS"
    chmod 755 "$INSTALL_DIR/AegisICS"
    ln -sf "$INSTALL_DIR/AegisICS" "$BIN_DIR/aegis-ics"
    
    sed "s|/usr/local/bin/aegis-ics|$BIN_DIR/aegis-ics|g" "$SCRIPT_DIR/aegis-ics.desktop" > "$APPS_DIR/aegis-ics.desktop"
    if [ -f "$SCRIPT_DIR/aegis-ics.svg" ]; then
        cp -f "$SCRIPT_DIR/aegis-ics.svg" "$ICONS_DIR/aegis-ics.svg"
    fi
    echo "User installation complete. Make sure $BIN_DIR is in your PATH."
    echo "Launch with 'aegis-ics' or run directly from $INSTALL_DIR/AegisICS."
fi
""")
    if os.name == "posix":
        os.chmod(install_sh, 0o755)

    # 5. Readme
    readme = os.path.join(staging_dir, "README.txt")
    with open(readme, "w", encoding="utf-8", newline="\n") as f:
        f.write("""Aegis ICS v2.5.0 — Standalone Linux Release
==================================================

Targeted for MX Linux & Debian distributions.

Quickstart:
1. Portable Run:
   ./run.sh                  (Desktop GUI or Headless Server)
   ./run.sh --server         (Headless Server only on port 5000)

2. Install to system:
   sudo ./install.sh         (Installs to /opt/aegis-ics and /usr/local/bin)
   ./install.sh              (Installs to ~/.local/share/aegis-ics and ~/.local/bin)

3. Hardware Serial Access (ESP32/PLC):
   Ensure your user is part of the 'dialout' group:
   sudo usermod -a -G dialout $USER
""")

    print("\n[2/3] Compressing into tarball archive...")
    with tarfile.open(output_tarball, "w:gz") as tar:
        tar.add(staging_dir, arcname="aegis-ics-2.5.0")

    if os.path.exists(output_tarball):
        size_bytes = os.path.getsize(output_tarball)
        size_mb = size_bytes / (1024 * 1024)
        print("\n[3/3] Verifying generated tarball...")
        print("=" * 60)
        print(" LINUX TARBALL CREATED SUCCESSFULLY!")
        print(f" Tarball:   {output_tarball}")
        print(f" File Size: {size_mb:.2f} MB ({size_bytes:,} bytes)")
        print("=" * 60)
    else:
        print(f"[ERROR] Failed to generate tarball: {output_tarball}")
        sys.exit(1)

if __name__ == "__main__":
    build_tarball()
