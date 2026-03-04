"""
selene/core/config.py
Konfigurasi terpusat untuk semua tools Selene.
"""

from pathlib import Path
from selene.core.common import CONFIG_FILE, save_json, load_json, log

DEFAULT = {
    "version":    "3.0.0",
    "setup_done": False,
    "network": {
        "scan_range":   "auto",
        "scan_timeout": 0.8,
        "trusted_ips":  [],
        "gateway":      "auto",
    },
    "monitor": {
        "auto_block":       True,
        "block_minutes":    30,
        "check_interval":   60,
        "alert_threshold":  70,
    },
    "backup": {
        "directories":  [],
        "destination":  "",
        "keep_days":    30,
        "max_file_mb":  100,
        "schedule_h":   24,
    },
    "integrity": {
        "watch_paths":  [],
        "excludes":     ["*.log","*.tmp","__pycache__",".git"],
        "interval_sec": 300,
    },
    "notifications": {
        "telegram_token":   "",
        "telegram_chat_id": "",
        "discord_webhook":  "",
        "email_to":         "",
        "enabled":          [],
    },
    "dashboard": {
        "host": "127.0.0.1",
        "port": 8765,
        "refresh_sec": 5,
    },
    "honeypot": {
        "ports": [2222,8080,2121,13306],
    },
}

class Config:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._data   = {}
            cls._instance._loaded = False
        return cls._instance

    def load(self) -> None:
        saved = load_json(CONFIG_FILE, {}) if CONFIG_FILE.exists() else {}
        self._data   = self._merge(dict(DEFAULT), saved)
        self._loaded = True

    def save(self) -> bool:
        if not self._loaded: self.load()
        return save_json(CONFIG_FILE, self._data)

    def get(self, *keys, default=None):
        if not self._loaded: self.load()
        node = self._data
        for k in keys:
            if isinstance(node, dict): node = node.get(k)
            else: return default
        return node if node is not None else default

    def set(self, *args) -> None:
        if not self._loaded: self.load()
        *keys, value = args
        node = self._data
        for k in keys[:-1]:
            if k not in node or not isinstance(node[k], dict):
                node[k] = {}
            node = node[k]
        node[keys[-1]] = value

    def is_setup_done(self) -> bool:
        return bool(self.get("setup_done", default=False))

    def mark_setup_done(self) -> None:
        self.set("setup_done", True)
        self.save()

    def _merge(self, base: dict, over: dict) -> dict:
        result = dict(base)
        for k, v in over.items():
            if k in result and isinstance(result[k], dict) and isinstance(v, dict):
                result[k] = self._merge(result[k], v)
            else:
                result[k] = v
        return result

config = Config()

def get_config() -> Config:
    if not config._loaded:
        config.load()
    return config
