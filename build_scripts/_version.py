"""Reads the application version from src/version.py (the single source of truth)."""
import os
import re

_VERSION_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "version.py")

with open(_VERSION_FILE, encoding="utf-8") as _f:
    VERSION = re.search(r'__version__\s*=\s*"([^"]+)"', _f.read()).group(1)
