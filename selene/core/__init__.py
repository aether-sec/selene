"""selene/core — Fondasi semua Selene tools."""
from selene.core.common import (
    log, log_section, log_header, c, Fore, Style,
    IS_LINUX, IS_WINDOWS, IS_MACOS, IS_ANDROID, IS_ROOT,
    SELENE_DIR, LOGS_DIR, DATA_DIR, REPORTS_DIR, CONFIG_FILE,
    ALERTS_FILE, HP_CAPTURES_FILE, HEALTH_FILE,
    require_root, check_dependency, check_binary,
    confirm, prompt, prompt_password,
    write_alert, append_jsonl, read_jsonl,
    save_json, load_json,
    fmt_bytes, fmt_duration, risk_color, risk_label,
    Spinner, get_local_ip, get_hostname,
    is_port_open, is_port_available,
)
from selene.core.config import get_config, config
