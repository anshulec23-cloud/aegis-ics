"""
Aegis ICS v2.5.0 — Debian (.deb) Package Builder
================================================
Assembles a Debian binary package (.deb) targeting MX Linux and Debian.
Packages the standalone ELF executable, desktop entry, application icons,
systemd service unit, and SysVinit script.

Usage:
    python build_scripts/package_deb.py
"""

import os
import sys
import shutil
import subprocess
import tarfile
import io

def build_deb():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    os.chdir(project_root)

    print("=" * 60)
    print(" Aegis ICS v2.5.0 — Debian (.deb) Package Packaging Pipeline")
    print("=" * 60)

    dist_dir = os.path.join(project_root, "dist")
    target_binary = os.path.join(dist_dir, "AegisICS")
    deb_name = "aegis-ics_2.5.0_amd64.deb"
    output_deb = os.path.join(dist_dir, deb_name)

    if not os.path.exists(target_binary):
        print(f"[ERROR] Standalone ELF binary not found at: {target_binary}")
        print("Please compile the binary first using: python build_scripts/build_linux.py")
        sys.exit(1)

    if os.name == "posix" and os.path.exists("/tmp"):
        staging_dir = "/tmp/deb_staging"
    else:
        staging_dir = os.path.join(project_root, "build", "deb_staging")

    if os.path.exists(staging_dir):
        shutil.rmtree(staging_dir, ignore_errors=True)

    print("\n[1/4] Constructing Debian package directory structure...")
    
    # Target structure directories
    debian_control_dir = os.path.join(staging_dir, "DEBIAN")
    opt_dir = os.path.join(staging_dir, "opt", "aegis-ics")
    apps_dir = os.path.join(staging_dir, "usr", "share", "applications")
    svg_icon_dir = os.path.join(staging_dir, "usr", "share", "icons", "hicolor", "scalable", "apps")
    pixmap_dir = os.path.join(staging_dir, "usr", "share", "pixmaps")
    systemd_dir = os.path.join(staging_dir, "lib", "systemd", "system")

    for d in [debian_control_dir, opt_dir, apps_dir, svg_icon_dir, pixmap_dir, systemd_dir]:
        os.makedirs(d, exist_ok=True)
        if os.name == "posix":
            os.chmod(d, 0o755)

    # 1. DEBIAN metadata files
    debian_src = os.path.join(project_root, "debian")
    shutil.copy2(os.path.join(debian_src, "control"), debian_control_dir)
    shutil.copy2(os.path.join(debian_src, "postinst"), debian_control_dir)
    shutil.copy2(os.path.join(debian_src, "prerm"), debian_control_dir)
    shutil.copy2(os.path.join(debian_src, "postrm"), debian_control_dir)

    # Set execute permissions on scripts if on POSIX
    if os.name == "posix":
        os.chmod(debian_control_dir, 0o755)
        os.chmod(os.path.join(debian_control_dir, "control"), 0o644)
        for script in ["postinst", "prerm", "postrm"]:
            os.chmod(os.path.join(debian_control_dir, script), 0o755)

    # 2. Binary and SysVinit script in /opt/aegis-ics
    shutil.copy2(target_binary, opt_dir)
    shutil.copy2(os.path.join(debian_src, "aegis-ics.init"), opt_dir)
    if os.name == "posix":
        os.chmod(os.path.join(opt_dir, "AegisICS"), 0o755)
        os.chmod(os.path.join(opt_dir, "aegis-ics.init"), 0o755)

    # 3. Desktop file & Icons
    shutil.copy2(os.path.join(debian_src, "aegis-ics.desktop"), apps_dir)
    
    svg_src = os.path.join(project_root, "src", "static", "achilles_icon.svg")
    png_src = os.path.join(project_root, "src", "static", "icon.png")

    if os.path.exists(svg_src):
        shutil.copy2(svg_src, os.path.join(svg_icon_dir, "aegis-ics.svg"))
    if os.path.exists(png_src):
        shutil.copy2(png_src, os.path.join(pixmap_dir, "aegis-ics.png"))

    # 4. Systemd unit
    shutil.copy2(os.path.join(debian_src, "aegis-ics.service"), systemd_dir)

    print("\n[2/4] Assembling .deb package...")
    
    # Try dpkg-deb first
    dpkg_built = False
    dpkg_deb_cmd = shutil.which("dpkg-deb")
    if dpkg_deb_cmd:
        cmd = [dpkg_deb_cmd, "--build", "--root-owner-group", staging_dir, output_deb]
        print(f"      Running: {' '.join(cmd)}")
        res = subprocess.run(cmd)
        if res.returncode == 0:
            dpkg_built = True

    # Fallback to pure Python .deb builder if dpkg-deb is not installed
    if not dpkg_built:
        print("      dpkg-deb not found in PATH — building .deb with pure Python ar packaging...")
        build_deb_pure_python(staging_dir, output_deb)

    # Verify output
    if os.path.exists(output_deb):
        size_bytes = os.path.getsize(output_deb)
        size_mb = size_bytes / (1024 * 1024)
        print("\n[3/4] Verifying generated Debian package...")
        print("=" * 60)
        print(" DEBIAN PACKAGE CREATED SUCCESSFULLY!")
        print(f" Package:   {output_deb}")
        print(f" File Size: {size_mb:.2f} MB ({size_bytes:,} bytes)")
        print("=" * 60)
    else:
        print(f"[ERROR] Failed to generate .deb package: {output_deb}")
        sys.exit(1)


def build_deb_pure_python(staging_dir: str, output_deb: str):
    """
    Constructs a standard Debian binary package archive using Python.
    Debian package format consists of an ar archive with:
      1. debian-binary (contains '2.0\\n')
      2. control.tar.gz (contains DEBIAN/* files)
      3. data.tar.gz (contains filesystem payload)
    """
    import gzip

    # 1. debian-binary
    deb_binary_content = b"2.0\n"

    # 2. control.tar.gz
    control_buf = io.BytesIO()
    with tarfile.open(fileobj=control_buf, mode="w:gz") as tar:
        deb_dir = os.path.join(staging_dir, "DEBIAN")
        for item in sorted(os.listdir(deb_dir)):
            full_path = os.path.join(deb_dir, item)
            ti = tar.gettarinfo(full_path, arcname=f"./{item}")
            ti.uid = 0
            ti.gid = 0
            ti.uname = "root"
            ti.gname = "root"
            if item in ["postinst", "prerm", "postrm"]:
                ti.mode = 0o755
            else:
                ti.mode = 0o644
            if os.path.isfile(full_path):
                with open(full_path, "rb") as f:
                    tar.addfile(ti, f)
            else:
                tar.addfile(ti)
    control_data = control_buf.getvalue()

    # 3. data.tar.gz
    data_buf = io.BytesIO()
    with tarfile.open(fileobj=data_buf, mode="w:gz") as tar:
        for root, dirs, files in os.walk(staging_dir):
            rel_dir = os.path.relpath(root, staging_dir)
            if rel_dir == "DEBIAN" or rel_dir.startswith("DEBIAN" + os.sep):
                continue
            arc_dir = "." if rel_dir == "." else f"./{rel_dir.replace(os.sep, '/')}"
            if arc_dir != ".":
                ti = tar.gettarinfo(root, arcname=arc_dir)
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                ti.mode = 0o755
                tar.addfile(ti)
            for f in files:
                full_path = os.path.join(root, f)
                arc_path = f"{arc_dir}/{f}"
                ti = tar.gettarinfo(full_path, arcname=arc_path)
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                if f in ["AegisICS", "aegis-ics.init"]:
                    ti.mode = 0o755
                else:
                    ti.mode = 0o644
                with open(full_path, "rb") as file_obj:
                    tar.addfile(ti, file_obj)
    data_bytes = data_buf.getvalue()

    # Write ar archive (Unix standard ar)
    with open(output_deb, "wb") as ar:
        # ar magic header
        ar.write(b"!<arch>\n")

        def write_ar_entry(filename, data):
            # Filename: 16 bytes
            fn = f"{filename:<16}".encode("ascii")
            # Timestamp: 12 bytes
            ts = f"{0:<12}".encode("ascii")
            # Owner: 6 bytes
            owner = f"{0:<6}".encode("ascii")
            # Group: 6 bytes
            group = f"{0:<6}".encode("ascii")
            # Mode: 8 bytes
            mode = f"{100644:<8}".encode("ascii")
            # Size: 10 bytes
            size = f"{len(data):<10}".encode("ascii")
            # Magic: 2 bytes
            fmag = b"`\n"

            ar.write(fn + ts + owner + group + mode + size + fmag)
            ar.write(data)
            if len(data) % 2 != 0:
                ar.write(b"\n")

        write_ar_entry("debian-binary", deb_binary_content)
        write_ar_entry("control.tar.gz", control_data)
        write_ar_entry("data.tar.gz", data_bytes)

if __name__ == "__main__":
    build_deb()
