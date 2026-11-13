"""Single source of truth for the Aegis ICS version.

Everything that needs the version (``/api/version``, the updater, PDF reports,
packaging scripts, ``pyproject.toml``) reads it from here.
"""

__version__ = "2.6.0.dev0"
