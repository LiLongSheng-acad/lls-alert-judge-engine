#!/usr/bin/env python3
"""
storage/db.py - 统一数据库连接入口

统一读连接的：超时、busy_timeout、REGEXP（regex 规则）与 ip_in_cidr（CIDR 规则）。
避免各路由各自 sqlite3.connect，导致超时/锁行为不一致。
"""
import sys
import os
import re
import sqlite3
import ipaddress

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import DB_PATH


def _sqlite_regexp(pattern: str, value: str) -> int:
    """为 SQLite 注册 REGEXP（Python re）"""
    try:
        return 1 if re.search(pattern, value or "") else 0
    except re.error:
        return 0


def _sqlite_ip_in_cidr(ip: str, cidr: str) -> int:
    """为 SQLite 注册 ip_in_cidr(ip, cidr)：判断 IP 是否落在网段内"""
    try:
        return 1 if ipaddress.ip_address((ip or "").strip()) in ipaddress.ip_network(cidr, strict=False) else 0
    except ValueError:
        return 0


def get_conn():
    """获取数据库连接（统一超时 + busy_timeout + REGEXP + ip_in_cidr）"""
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.create_function("regexp", 2, _sqlite_regexp)
    conn.create_function("ip_in_cidr", 2, _sqlite_ip_in_cidr)
    return conn
