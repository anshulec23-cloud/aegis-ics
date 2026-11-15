"""First-run account bootstrap.

There is no default password. On first start the administrator account is created in
one of two ways:

* ``ADMIN_PASSWORD`` is set (>= 12 characters): the ``admin`` account is created with it.
  Suited to scripted/headless installs.
* Otherwise the app enters **setup mode**: every page redirects to ``/setup``, which asks
  for the new admin password. The page needs a one-time setup token:
    - the desktop app opens ``/setup?token=...`` automatically, so the user just types a password;
    - headless installs print the setup URL to the log and write it to
      ``<data dir>/setup_token.txt`` (mode 0600).
  The token is deleted once the account is created.

Upgrades from <= 2.5.x: an ``admin`` account still using the old default password is
locked (unusable hash) and setup mode is entered; the legacy ``noodles`` account is
removed if it still uses its default password.
"""

from __future__ import annotations

import os
import secrets
from typing import Mapping, Optional

LEGACY_DEFAULT_PASSWORD = "noodles"
MIN_PASSWORD_LENGTH = 12
SETUP_TOKEN_FILE = "setup_token.txt"
LOCKED_HASH_PREFIX = "!locked:"


def configured_admin_password(env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """Return ``ADMIN_PASSWORD`` if it is set and strong enough, else ``None``."""
    env = os.environ if env is None else env
    configured = env.get("ADMIN_PASSWORD")
    if not configured:
        return None
    problem = password_problem(configured)
    if problem:
        print(
            f"[SECURITY] Ignoring ADMIN_PASSWORD: {problem}. Use the first-run setup page instead."
        )
        return None
    return configured


def password_problem(password: str) -> Optional[str]:
    """Human-readable reason a password is unacceptable, or ``None`` if it is fine."""
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return f"must be at least {MIN_PASSWORD_LENGTH} characters"
    if password == LEGACY_DEFAULT_PASSWORD:
        return "the legacy default password is not allowed"
    return None


def locked_password_hash() -> str:
    """A value that can never match any password (used until setup completes)."""
    return LOCKED_HASH_PREFIX + secrets.token_hex(16)


def is_locked_hash(password_hash: str) -> bool:
    return bool(password_hash) and password_hash.startswith(LOCKED_HASH_PREFIX)


def _token_path(data_dir: str) -> str:
    return os.path.join(data_dir, SETUP_TOKEN_FILE)


def ensure_setup_token(data_dir: str) -> str:
    """Return the current one-time setup token, creating (and announcing) it if needed."""
    path = _token_path(data_dir)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("token: "):
                    return line.split(": ", 1)[1].strip()
    except OSError:
        pass
    token = secrets.token_urlsafe(24)
    os.makedirs(data_dir, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(
            "Aegis ICS first-run setup\n"
            "Open /setup?token=<token> in the dashboard to create the administrator account.\n"
            f"token: {token}\n"
        )
    print("=" * 72)
    print(" Aegis ICS first-run setup: create the administrator account at")
    print(f"   /setup?token={token}")
    print(f" (also saved to {path}; the desktop app opens it automatically)")
    print("=" * 72)
    return token


def check_setup_token(data_dir: str, candidate: Optional[str]) -> bool:
    if not candidate:
        return False
    path = _token_path(data_dir)
    if not os.path.exists(path):
        return False
    return secrets.compare_digest(ensure_setup_token(data_dir), str(candidate))


def clear_setup_token(data_dir: str) -> None:
    try:
        os.remove(_token_path(data_dir))
    except FileNotFoundError:
        pass
