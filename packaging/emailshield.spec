# -*- mode: python ; coding: utf-8 -*-
# Build:  pyinstaller --noconfirm --clean packaging\emailshield.spec     (see build_windows.bat)
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent
WIN = sys.platform == "win32"
hidden = collect_submodules("uvicorn") + collect_submodules("emailshield") + ["webview", "emailshield.worker", "emailshield.providers", "emailshield.yara_opt", "keyring.backends"]
a = Analysis([str(ROOT / "scripts" / "desktop_entry.py")], pathex=[str(ROOT)],
             datas=[(str(ROOT / "emailshield" / "static"), "emailshield/static")],
             hiddenimports=hidden, excludes=["pytest", "httpx", "PySide6", "PyQt5", "PyQt6", "matplotlib", "numpy"])
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="EmailShield", console=False,
          icon=str(ROOT / "packaging" / "emailshield.ico") if WIN else None,
          version=str(ROOT / "packaging" / "version_info.txt") if WIN else None)
coll = COLLECT(exe, a.binaries, a.datas, name="EmailShield")
