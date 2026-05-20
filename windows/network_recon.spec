# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Network Recon."""

import os
from pathlib import Path

try:
    SPEC_DIR = Path(SPEC).resolve().parent
except NameError:  # pragma: no cover
    SPEC_DIR = Path(__file__).resolve().parent

ROOT = SPEC_DIR.parent
SRC = ROOT / "src"
SCRIPT = SRC / "network_recon.py"
ICON = ROOT / "assets" / "app.ico"
EXE_NAME = os.environ.get("NETWORK_RECON_EXE_NAME", "network_recon")

a = Analysis(
    [str(SCRIPT)],
    pathex=[str(SRC), str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

_common = dict(
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

if ICON.is_file():
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name=EXE_NAME,
        **_common,
        icon=[str(ICON)],
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name=EXE_NAME,
        **_common,
    )
