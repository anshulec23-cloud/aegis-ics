from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def generate_root(out_dir: Path, common_name: str) -> None:
    run([
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", str(out_dir / "root-ca.key"),
        "-out", str(out_dir / "root-ca.crt"),
        "-days", "3650", "-nodes", "-subj", f"/CN={common_name}",
    ])


def generate_signed_cert(out_dir: Path, name: str, common_name: str, days: int = 365) -> None:
    csr = out_dir / f"{name}.csr"
    key = out_dir / f"{name}.key"
    crt = out_dir / f"{name}.crt"
    run([
        "openssl", "req", "-newkey", "rsa:2048",
        "-keyout", str(key), "-out", str(csr),
        "-nodes", "-subj", f"/CN={common_name}",
    ])
    run([
        "openssl", "x509", "-req", "-in", str(csr),
        "-CA", str(out_dir / "root-ca.crt"),
        "-CAkey", str(out_dir / "root-ca.key"),
        "-CAcreateserial", "-out", str(crt),
        "-days", str(days),
    ])
    csr.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate Zero Trust ICS TLS certificates")
    parser.add_argument("--out-dir", default=".")
    parser.add_argument("--device-id", action="append", default=None, help="Repeat for each device")
    parser.add_argument("--root-cn", default="ZeroTrust-ICS-Root")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    device_ids = args.device_id or ["ESP32_001"]

    generate_root(out_dir, args.root_cn)
    generate_signed_cert(out_dir, "server", "server.example", days=365)
    for device_id in device_ids:
        generate_signed_cert(out_dir, device_id, device_id, days=365)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
