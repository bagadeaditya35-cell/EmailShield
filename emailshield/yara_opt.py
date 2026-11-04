"""Optional YARA scanning. Active only if `yara-python` is installed AND *.yar files exist in data/yara_rules.
Attachment bytes are scanned in memory and never written to disk or executed."""
from . import config


def get_scanner():
    try:
        import yara  # type: ignore
    except ImportError:
        return None
    files = sorted(config.YARA_RULES_DIR.glob("*.yar")) if config.YARA_RULES_DIR.exists() else []
    if not files:
        return None
    rules = yara.compile(filepaths={f.stem: str(f) for f in files})
    return lambda filename, data: [m.rule for m in rules.match(data=data, timeout=10)]
