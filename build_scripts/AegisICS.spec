# -*- mode: python ; coding: utf-8 -*-
"""
Aegis ICS v2.5.2 — Standalone Executable Specification
======================================================
Rebuilt from scratch for self-contained, air-gapped ICS deployment.
Packages Python runtime, embedded PyWebView, Flask backend, SQLite database,
ReportLab PDF engine, Random Forest ML pipeline, and offline vendor assets.
"""

import os
import sys

spec_dir = os.path.dirname(os.path.abspath(SPEC))
project_root = os.path.dirname(spec_dir)
src_dir = os.path.join(project_root, "src")

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

# 2. Bundle UI templates, offline static vendor assets, ML model, and database
datas = [
    (os.path.join(src_dir, 'templates'), 'templates'),
    (os.path.join(src_dir, 'static'), 'static'),
    (os.path.join(src_dir, 'model'), 'model'),
    (os.path.join(project_root, 'aegis_v2.db'), '.'),
]

# 3. Explicit hidden imports for dynamic imports and runtime dependencies
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
    'joblib',
    'numpy',
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
    'analytics',
    'reporting',
    'security',
    'database',
    'safety_enforcer',
    'neural_policy',
    'serial_gateway',
    'updater',
    'tray',
    'trust_engine',
    'train_model',
]

a = Analysis(
    [os.path.join(src_dir, 'main.py')],
    pathex=[src_dir, project_root],
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
    icon=os.path.join(src_dir, 'static', 'Achilles.ico'),
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
