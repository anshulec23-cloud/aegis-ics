# -*- mode: python ; coding: utf-8 -*-
"""
Aegis ICS v2.3.0 — Standalone Desktop Executable Specification
==============================================================
Builds the hardened, self-contained Aegis ICS operational binary.
Bundles local templates, static assets, pre-trained Random Forest ML model,
and baseline production database.
"""

import os
import sys

block_cipher = None

# 1. Resolve Python runtime DLL dynamically across environments
base_prefix = getattr(sys, 'base_prefix', sys.prefix)
py_ver_str = f"{sys.version_info.major}{sys.version_info.minor}"
possible_dll_paths = [
    os.path.join(base_prefix, f"python{py_ver_str}.dll"),
    os.path.join(sys.prefix, f"python{py_ver_str}.dll"),
    f"C:\\Python{py_ver_str}\\python{py_ver_str}.dll",
]
python_dll = next((p for p in possible_dll_paths if os.path.exists(p)), None)
binaries = [(python_dll, '.')] if python_dll else []

# 2. Bundle UI templates, static assets, ML model, and SQLite database
datas = [
    ('..\\src\\templates', 'templates'),
    ('..\\src\\static', 'static'),
    ('..\\src\\model', 'model'),
    ('..\\aegis_v2.db', '.'),
]

# 3. Explicit hidden imports for dynamic imports across dependencies
hiddenimports = [
    'flask',
    'sqlalchemy',
    'sqlalchemy.orm',
    'sqlalchemy.sql.default_comparator',
    'serial',
    'serial.tools',
    'serial.tools.list_ports',
    'bleach',
    'sklearn',
    'sklearn.ensemble',
    'sklearn.tree',
    'sklearn.utils._typedefs',
    'flask_limiter',
    'reportlab',
    'reportlab.lib',
    'reportlab.lib.colors',
    'reportlab.lib.pagesizes',
    'reportlab.lib.units',
    'reportlab.platypus',
    'reportlab.graphics',
    'reportlab.graphics.shapes',
    'reportlab.pdfgen.canvas',
    'webview',
    'pystray',
    'PIL',
    'PIL.Image',
    'PIL.ImageDraw',
    'werkzeug',
    'werkzeug.serving',
    'jinja2',
]

a = Analysis(
    ['..\\src\\main.py'],
    pathex=['..\\src'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='AegisICS',
    icon='..\\src\\static\\Achilles.ico',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
