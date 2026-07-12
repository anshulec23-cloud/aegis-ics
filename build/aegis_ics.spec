# -*- mode: python ; coding: utf-8 -*-
"""
Aegis ICS — PyInstaller Spec File
===================================
Builds the frozen Windows binary from the version-two source.

Usage:
    pyinstaller build/aegis_ics.spec

Output:
    dist/AegisICS/  (onedir bundle)
"""

import os
import sys

# Resolve paths relative to the spec file location
SPEC_DIR = os.path.abspath(SPECPATH)
PROJECT_ROOT = os.path.dirname(SPEC_DIR)  # aegis-ics/
SOURCE_DIR = os.environ.get("AEGIS_SOURCE_DIR", os.path.join(PROJECT_ROOT, "version-two"))

a = Analysis(
    [os.path.join(SOURCE_DIR, "launcher.py")],
    pathex=[SOURCE_DIR],
    binaries=[],
    datas=[
        # Templates (Jinja2 HTML files)
        (os.path.join(SOURCE_DIR, "templates"), "templates"),
        # Static assets (icons, etc.)
        (os.path.join(SOURCE_DIR, "static"), "static"),
        # Trained ML model binary
        (os.path.join(SOURCE_DIR, "model"), "model"),
        # Alembic migrations (for DB schema updates)
        (os.path.join(SOURCE_DIR, "alembic"), "alembic"),
        (os.path.join(SOURCE_DIR, "alembic.ini"), "."),
    ],
    hiddenimports=[
        # --- scikit-learn (dynamic C extension imports) ---
        "sklearn",
        "sklearn.utils._cython_blas",
        "sklearn.neighbors._typedefs",
        "sklearn.neighbors._quad_tree",
        "sklearn.tree._utils",
        "sklearn.utils._weight_vector",
        "sklearn.ensemble._forest",
        "sklearn.tree._classes",
        # --- SQLAlchemy ---
        "sqlalchemy.dialects.sqlite",
        # --- ReportLab ---
        "reportlab.graphics.barcode.common",
        "reportlab.graphics.barcode.code128",
        # --- pyserial ---
        "serial",
        "serial.tools",
        "serial.tools.list_ports_windows",
        # --- paho-mqtt ---
        "paho.mqtt.client",
        # --- pywebview (WebView2 backend on Windows) ---
        "webview",
        # --- pystray ---
        "pystray",
        "pystray._win32",
        # --- Pillow ---
        "PIL",
        "PIL.Image",
        "PIL.ImageDraw",
        # --- Application modules ---
        "app",
        "database",
        "safety_enforcer",
        "serial_gateway",
        "security",
        "updater",
        "tray",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude unnecessary GUI frameworks to reduce bundle size
        "tkinter",
        "PyQt5",
        "PyQt6",
        "PySide2",
        "PySide6",
        # Exclude test frameworks
        "pytest",
        "unittest",
        # Exclude heavy unused packages
        "matplotlib",
        "matplotlib.tests",
        "IPython",
        "jupyter",
        "notebook",
    ],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AegisICS",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # NO terminal window — pure GUI application
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(SOURCE_DIR, "static", "icon.ico")
    if os.path.exists(os.path.join(SOURCE_DIR, "static", "icon.ico"))
    else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="AegisICS",
)
