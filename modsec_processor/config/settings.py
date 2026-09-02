#!/usr/bin/env python3
"""
config/settings.py - 统一配置管理
"""
import os
import secrets
from pathlib import Path
from datetime import datetime
from typing import List

# ============================================================
# 系统层
# ============================================================
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
PROJECT_NAME = "告警研判引擎"
VERSION = "0.2.0"

# ============================================================
# 路径层
# ============================================================
LOG_DIR = PROJECT_ROOT / "logs"
CONFIG_DIR = PROJECT_ROOT / "config"
STATIC_DIR = PROJECT_ROOT / "static"
DB_PATH = LOG_DIR / "modsec_logs.db"
SYSLOG_FILE = Path(f"/var/log/remote/modsec_{datetime.now().strftime('%Y-%m-%d')}.log")
OFFSET_FILE = Path("/opt/modsec_offset.txt")
SINK_RULES_FILE = CONFIG_DIR / "sink_rules.json"
BLOCKED_IPS_FILE = CONFIG_DIR / "blocked_ips.txt"
WHITELIST_IPS_FILE = CONFIG_DIR / "whitelist_ips.txt"
TEMP_BLACKLIST_DIR = CONFIG_DIR / "temp_blacklist"
FINANCIAL_FACTORS_FILE = CONFIG_DIR / "financial_factors.yaml"

# ============================================================
# 业务层
# ============================================================
COLLECTOR = {
    "batch_size": 10,
    "flush_interval": 30,
    "file_wait_timeout": 60,
    "read_sleep_interval": 1,
}

ID_GENERATOR = {
    "seq_digits": 6,
    "template": "{MARKER}{DATE}{SEQ}",
    "default_marker": "A",
    "status_markers": {
        "active": "A",
        "blocked": "B",
        "whitelist": "W",
        "processed": "P",
        "ignored": "I",
        "error": "E",
        "rule": "R",
    }
}

DEFAULTS = {
    "src_ip": "0.0.0.0",
    "severity": "INFO",
    "attack_type": "UNKNOWN",
}

# ============================================================
# 安全层（敏感信息不硬编码）
# ============================================================
BASIC_AUTH_USERNAME = os.getenv("BASIC_AUTH_USERNAME")
BASIC_AUTH_PASSWORD = os.getenv("BASIC_AUTH_PASSWORD")

if not BASIC_AUTH_USERNAME or not BASIC_AUTH_PASSWORD:
    temp_password = secrets.token_urlsafe(16)
    print("=" * 60)
    print("警告：未设置 BASIC_AUTH_USERNAME 或 BASIC_AUTH_PASSWORD")
    print("临时账号: admin")
    print(f"临时密码: {temp_password}")
    print("请在环境变量中配置，或修改 config/settings.py")
    print("=" * 60)
    BASIC_AUTH_USERNAME = "admin"
    BASIC_AUTH_PASSWORD = temp_password

DEDUP_WINDOW = int(os.getenv("DEDUP_WINDOW", "60"))
DEDUP_FINGERPRINT_FIELDS = ["src_ip", "attack_type", "uri"]
COOKIE_USER_KEY = "alert_user"
COOKIE_MAX_AGE = 86400

# ============================================================
# API 服务层
# ============================================================
API = {
    "host": "0.0.0.0",
    "port": 8000,
    "reload": True,
    "cors_origins": ["*"],
    "allow_methods": ["POST", "GET"],
}

# ============================================================
# 辅助函数
# ============================================================
def ensure_directories():
    required_dirs = [LOG_DIR, CONFIG_DIR, STATIC_DIR, TEMP_BLACKLIST_DIR, Path("/var/log/remote")]
    for d in required_dirs:
        d.mkdir(parents=True, exist_ok=True)

def get_config_summary() -> dict:
    return {
        "project_root": str(PROJECT_ROOT),
        "db_path": str(DB_PATH),
        "log_dir": str(LOG_DIR),
        "syslog_file": str(SYSLOG_FILE),
        "api_port": API["port"],
        "batch_size": COLLECTOR["batch_size"],
        "dedup_window": DEDUP_WINDOW,
        "basic_auth_enabled": True,
    }

ensure_directories()

__all__ = [
    "PROJECT_ROOT", "PROJECT_NAME", "VERSION",
    "LOG_DIR", "CONFIG_DIR", "STATIC_DIR",
    "DB_PATH", "SYSLOG_FILE", "OFFSET_FILE",
    "SINK_RULES_FILE", "BLOCKED_IPS_FILE", "WHITELIST_IPS_FILE",
    "TEMP_BLACKLIST_DIR", "FINANCIAL_FACTORS_FILE",
    "COLLECTOR", "ID_GENERATOR", "DEFAULTS",
    "BASIC_AUTH_USERNAME", "BASIC_AUTH_PASSWORD",
    "DEDUP_WINDOW", "DEDUP_FINGERPRINT_FIELDS",
    "COOKIE_USER_KEY", "COOKIE_MAX_AGE",
    "API",
    "ensure_directories", "get_config_summary",
]
