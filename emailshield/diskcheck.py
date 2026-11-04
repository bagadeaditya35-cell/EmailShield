import shutil

from . import config


def free_mb(path=None):
    p = path or config.DATA_DIR
    p.mkdir(parents=True, exist_ok=True)
    return shutil.disk_usage(p).free / (1024 * 1024)


def low(path=None):
    return free_mb(path) < config.MIN_FREE_MB
