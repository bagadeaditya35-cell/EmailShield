import pytest

from emailshield import autostart


class FakeWinreg:
    HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_SZ = "HKCU", 1, 2, 1

    def __init__(self):
        self.values = {}

    def OpenKey(self, root, path, res, access):
        assert root == "HKCU" and path == autostart.RUN_KEY  # per-user key only: no admin, no HKLM
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def QueryValueEx(self, k, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        return self.values[name], 1

    def SetValueEx(self, k, name, res, typ, value):
        self.values[name] = value

    def DeleteValue(self, k, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        del self.values[name]


def test_autostart_is_off_by_default_and_toggles_a_visible_per_user_entry():
    w = FakeWinreg()
    assert autostart.is_enabled(w) is False
    autostart.enable(w)
    assert autostart.is_enabled(w) is True and "emailshield" in w.values["EmailShield"].lower() or "EmailShield" in w.values
    autostart.disable(w)
    assert autostart.is_enabled(w) is False
    autostart.disable(w)  # disabling twice is harmless


def test_autostart_command_is_quoted_and_starts_only_the_background_engine(monkeypatch):
    monkeypatch.setattr(autostart.sys, "frozen", True, raising=False)
    monkeypatch.setattr(autostart.sys, "executable", r"C:\Program Files\EmailShield\EmailShield.exe")
    assert autostart.command() == '"C:\\Program Files\\EmailShield\\EmailShield.exe" --background'  # engine only, no window at sign-in


def test_autostart_reports_unsupported_off_windows(monkeypatch):
    monkeypatch.setattr(autostart.sys, "platform", "linux")
    assert autostart.supported() is False and autostart.is_enabled() is False
