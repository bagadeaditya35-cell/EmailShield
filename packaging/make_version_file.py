"""Writes packaging/version_info.txt (Windows file properties) from emailshield.__version__."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from emailshield import __version__  # noqa: E402

v = tuple(int(x) for x in __version__.split(".")) + (0,) * (4 - len(__version__.split(".")))
(Path(__file__).parent / "version_info.txt").write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={v}, prodvers={v}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('040904B0', [
    StringStruct('CompanyName', 'EmailShield student project'),
    StringStruct('FileDescription', 'EmailShield email threat investigation'),
    StringStruct('FileVersion', '{__version__}.0'),
    StringStruct('InternalName', 'EmailShield'),
    StringStruct('LegalCopyright', 'For education and authorized security work'),
    StringStruct('OriginalFilename', 'EmailShield.exe'),
    StringStruct('ProductName', 'EmailShield'),
    StringStruct('ProductVersion', '{__version__}.0')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])])
""")
print("wrote version_info.txt for", __version__)
