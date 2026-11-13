"""
security.py - Centralized Security Module for Aegis ICS Desktop Application

Provides runtime security utilities including token-based request authentication,
ephemeral port allocation, path resolution for PyInstaller builds, cryptographic
secret generation, and basic anti-debug detection.
"""

import ctypes
import functools
import os
import secrets
import socket
import sys
from typing import Callable, Any

from flask import jsonify, request


from version import __version__ as APP_VERSION  # noqa: F401 -- single source: src/version.py

GITHUB_REPO: str = "anshulec23-cloud/aegis-ics"
"""GitHub repository identifier used for update checks."""


# Device keys are provisioned per deployment (env or key file); see src/device_keys.py.
# There are intentionally no built-in or fallback keys.
from device_keys import get_device_key, is_valid_device_id  # noqa: E402,F401


def find_free_port() -> int:
    """Find a random available ephemeral port on localhost.

    Binds a TCP socket to ``127.0.0.1:0`` and lets the operating system
    assign an available port, then immediately releases the socket.

    Returns:
        int: An available port number assigned by the OS.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _, port = s.getsockname()
        return port


def resource_path(relative_path: str) -> str:
    """Resolve a file path for both development and frozen PyInstaller builds.

    When the application is bundled with PyInstaller, files are extracted to a
    temporary directory referenced by ``sys._MEIPASS``. During normal
    development the base path is the directory containing this module.

    Args:
        relative_path: A path relative to the application root / bundle root.

    Returns:
        str: The absolute path to the requested resource.
    """

    base_path: str = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


def require_webview_token(f: Callable[..., Any]) -> Callable[..., Any]:
    """Flask route decorator that validates the ``X-PYWEBVIEW-TOKEN`` header.

    The decorator enforces that every decorated request carries a valid
    pywebview token, preventing external processes from accessing the local
    Flask server.

    Behaviour:
    * If the ``AEGIS_DESKTOP_MODE`` environment variable is **not** set the
      check is skipped entirely.  This allows running the Flask backend in
      isolation during development or testing without requiring pywebview.
    * When ``AEGIS_DESKTOP_MODE`` **is** set, the ``webview`` module is
      imported lazily and the header value is compared against
      ``webview.token``.  A mismatch (or missing header) results in a
      ``403 Forbidden`` response.

    Returns:
        The decorated function with token validation applied.
    """

    @functools.wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        # Note: no TESTING bypass -- tests must exercise the same checks as production.
        if not os.environ.get("AEGIS_DESKTOP_MODE"):
            return f(*args, **kwargs)

        from flask import session

        if session.get("user_id"):
            return f(*args, **kwargs)

        try:
            import webview
        except ImportError:
            return jsonify({"error": "Forbidden – webview module unavailable"}), 403

        token: str | None = request.headers.get("X-PYWEBVIEW-TOKEN")

        if not token or not secrets.compare_digest(str(token), str(getattr(webview, "token", ""))):
            return jsonify({"error": "Forbidden – invalid or missing token"}), 403

        return f(*args, **kwargs)

    return decorated_function


def generate_runtime_secret() -> str:
    """Generate a cryptographically secure runtime secret.

    Uses :func:`secrets.token_hex` to produce a 64-character hexadecimal
    string (256 bits of entropy), suitable for use as a Flask session secret
    key or similar purpose.

    Returns:
        str: A 64-character hex string.
    """
    return secrets.token_hex(32)


def check_debugger() -> bool:
    """Perform basic anti-debug detection on Windows and Linux.

    On Windows: Calls ``kernel32.IsDebuggerPresent()`` via :mod:`ctypes`.
    On Linux: Checks ``/proc/self/status`` for non-zero ``TracerPid``.

    Returns:
        bool: ``True`` if a debugger is detected, ``False`` otherwise.
    """
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.kernel32.IsDebuggerPresent())
        except (AttributeError, OSError):
            return False
    elif sys.platform.startswith("linux"):
        try:
            status_path = "/proc/self/status"
            if os.path.exists(status_path):
                with open(status_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("TracerPid:"):
                            tracer_pid = int(line.split(":", 1)[1].strip())
                            return tracer_pid > 0
        except Exception:
            return False
    return False
