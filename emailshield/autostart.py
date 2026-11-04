"""Optional 'start EmailShield when I sign in to Windows' using the visible per-user Run registry key (no hidden tasks,
no admin rights, no service). The user can see and remove the entry in Task Manager > Startup apps or by switching it off here."""
import sys

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE = "EmailShield"


def supported():
    return sys.platform.startswith("win")


def command():
    """At sign-in only the background engine starts (no window); open the app from the Start menu when you want the dashboard."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --background'
    return f'"{sys.executable}" -m emailshield.desktop --background'


def _wr(winreg):
    if winreg is not None:
        return winreg
    import winreg as real  # type: ignore
    return real


def is_enabled(winreg=None):
    if winreg is None and not supported():
        return False
    w = _wr(winreg)
    try:
        with w.OpenKey(w.HKEY_CURRENT_USER, RUN_KEY, 0, w.KEY_READ) as k:
            return bool(w.QueryValueEx(k, VALUE)[0])
    except OSError:
        return False


def enable(winreg=None):
    w = _wr(winreg)
    with w.OpenKey(w.HKEY_CURRENT_USER, RUN_KEY, 0, w.KEY_SET_VALUE) as k:
        w.SetValueEx(k, VALUE, 0, w.REG_SZ, command())


def disable(winreg=None):
    w = _wr(winreg)
    try:
        with w.OpenKey(w.HKEY_CURRENT_USER, RUN_KEY, 0, w.KEY_SET_VALUE) as k:
            w.DeleteValue(k, VALUE)
    except OSError:
        pass
