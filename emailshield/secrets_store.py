"""Secret storage. Order: environment variable > OS keyring (if `keyring` is installed) > protected file fallback.
File fallback: on Windows every value is encrypted with DPAPI for the CURRENT USER (CryptProtectData, no extra dependency), so the
file is useless to other accounts and other machines. On other systems the file is plain text with owner-only permissions (0600).
Secrets are write-only through the API and are never logged or returned."""
import base64
import json
import os
import sys

from . import config, redact

SERVICE = "EmailShield"
_PREFIX = "dpapi1:"


def _env_name(name):
    return name.upper()


def _file():
    return config.DATA_DIR / "secrets.json"


def _keyring():
    try:
        import keyring  # type: ignore
        return keyring
    except ImportError:
        return None


def _dpapi():
    """(protect, unprotect) using the Windows DPAPI via ctypes. UNVERIFIED outside Windows."""
    import ctypes
    import ctypes.wintypes as wt

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32

    def blob(b):
        buf = ctypes.create_string_buffer(b, len(b))
        return BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    def protect(data):
        inb, keep = blob(data)
        out = BLOB()
        if not crypt32.CryptProtectData(ctypes.byref(inb), "EmailShield", None, None, None, 0, ctypes.byref(out)):
            raise OSError("DPAPI protect failed")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            kernel32.LocalFree(out.pbData)

    def unprotect(data):
        inb, keep = blob(data)
        out = BLOB()
        if not crypt32.CryptUnprotectData(ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(out)):
            raise OSError("DPAPI unprotect failed")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            kernel32.LocalFree(out.pbData)
    return protect, unprotect


def _get_protector():
    """None where no OS protection is available (tests may monkeypatch this)."""
    if not sys.platform.startswith("win"):
        return None
    try:
        return _dpapi()
    except Exception:
        return None


def backend():
    if _keyring():
        return "OS keyring"
    return "Windows DPAPI-protected file (current user only)" if _get_protector() else "plain file with owner-only permissions (install `keyring` for OS-level storage)"


def _encode(value):
    p = _get_protector()
    return _PREFIX + base64.b64encode(p[0](value.encode())).decode() if p else value


def _decode(stored):
    if stored.startswith(_PREFIX):
        p = _get_protector()
        if not p:
            return ""  # protected on another system/user: unreadable here, treated as not set
        try:
            return p[1](base64.b64decode(stored[len(_PREFIX):])).decode()
        except Exception:
            return ""
    return stored  # legacy plain value


def _read_file():
    try:
        return json.loads(_file().read_text())
    except (OSError, ValueError):
        return {}


def get(name):
    if os.environ.get(_env_name(name)):
        return os.environ[_env_name(name)]
    kr = _keyring()
    if kr:
        try:
            v = kr.get_password(SERVICE, name)
            if v:
                redact.register(v)
                return v
        except Exception:
            pass
    v = _decode(_read_file().get(name, ""))
    if v:
        redact.register(v)
    return v


def set(name, value):  # noqa: A001
    kr = _keyring()
    if kr:
        try:
            kr.set_password(SERVICE, name, value)
            return "keyring"
        except Exception:
            pass
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    data = _read_file()
    data[name] = _encode(value)
    f = _file()
    f.write_text(json.dumps(data))
    try:
        os.chmod(f, 0o600)
    except OSError:
        pass
    return "file"


def delete(name):
    kr = _keyring()
    if kr:
        try:
            kr.delete_password(SERVICE, name)
        except Exception:
            pass
    data = _read_file()
    if name in data:
        data.pop(name)
        _file().write_text(json.dumps(data))


def has(name):
    return bool(get(name))
