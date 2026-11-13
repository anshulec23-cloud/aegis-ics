"""First-run account bootstrap (replaces the default ``noodles`` password removed in v2.6).

Rules:
* ``ADMIN_PASSWORD`` set  -> used for the ``admin`` account when it is first created.
* not set               -> a random password is generated, printed once to the console and
                           written to ``initial_admin_password.txt`` (mode 0600) in the data
                           directory. Delete that file after the first login.
* Legacy installs: an ``admin`` account still using the old default password is rotated the
  same way, and the legacy ``noodles`` account is removed if it still has the default password.
"""

from __future__ import annotations

import os
import secrets
from typing import Mapping, Optional, Tuple

LEGACY_DEFAULT_PASSWORD = "noodles"
PASSWORD_FILE_NAME = "initial_admin_password.txt"
MIN_PASSWORD_LENGTH = 12


def data_dir_from_url(database_url: str) -> str:
    if database_url.startswith("sqlite:///"):
        return os.path.dirname(os.path.abspath(database_url[len("sqlite:///") :]))
    return os.getcwd()


def resolve_admin_password(
    env: Optional[Mapping[str, str]] = None, data_dir: str = "."
) -> Tuple[str, bool]:
    """Return ``(password, generated)``. Writes the password file when it had to generate one."""
    env = os.environ if env is None else env
    configured = env.get("ADMIN_PASSWORD")
    if configured:
        if configured == LEGACY_DEFAULT_PASSWORD or len(configured) < MIN_PASSWORD_LENGTH:
            print(
                f"[SECURITY] ADMIN_PASSWORD is too weak (minimum {MIN_PASSWORD_LENGTH} characters, "
                "not the legacy default). Generating a random password instead."
            )
        else:
            return configured, False

    password = secrets.token_urlsafe(18)
    os.makedirs(data_dir, exist_ok=True)
    path = os.path.join(data_dir, PASSWORD_FILE_NAME)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(
            "Aegis ICS initial administrator credentials\n"
            f"username: admin\npassword: {password}\n"
            "Log in, then delete this file. Set ADMIN_PASSWORD to choose your own.\n"
        )
    print("=" * 72)
    print(" Aegis ICS generated an administrator password (shown once):")
    print(f"   username: admin   password: {password}")
    print(f"   also saved to: {path}")
    print("=" * 72)
    return password, True
