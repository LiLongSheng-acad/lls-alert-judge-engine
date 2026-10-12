#!/usr/bin/env python3
"""
lib/preflight.py - 启动自检

在 API / 采集器启动时校验目录、权限与关键配置，把「跑起来才发现」的错误
提前成清晰的启动报错：
  - 致命问题 -> errors（API 直接拒绝启动；采集器打印后退出）
  - 非致命   -> warnings（提示，但不阻断）

按角色区分检查项：api 关注静态目录；collector 关注评分配置、偏移量目录、日志源目录。
"""
import os
import json
import sqlite3
from pathlib import Path

from config import settings as S


def _dir_writable(path) -> bool:
    """目录存在且可写（实际写一个探针文件再删掉）"""
    try:
        p = Path(path)
        p.mkdir(parents=True, exist_ok=True)
        probe = p / ".preflight_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except OSError:
        return False


def _readable_file(path) -> bool:
    p = Path(path)
    return p.is_file() and os.access(str(p), os.R_OK)


def _json_ok(path) -> bool:
    try:
        json.loads(Path(path).read_text(encoding="utf-8"))
        return True
    except (OSError, json.JSONDecodeError):
        return False


def run_preflight(role: str = "api"):
    """返回 (errors, warnings)，均为字符串列表"""
    errors = []
    warnings = []

    # 1. 目录可写
    for label, d in (("日志目录", S.LOG_DIR), ("配置目录", S.CONFIG_DIR)):
        if not _dir_writable(d):
            errors.append(f"{label}不可写: {d}")

    # 2. 数据库可打开
    try:
        conn = sqlite3.connect(str(S.DB_PATH), timeout=5)
        conn.execute("SELECT 1")
        conn.close()
    except sqlite3.Error as e:
        errors.append(f"数据库不可用: {S.DB_PATH} ({e})")

    # 3. 规则文件（缺失=空规则；存在但非法=致命）
    rules_file = Path(S.SINK_RULES_FILE)
    if rules_file.exists():
        if not _readable_file(rules_file):
            errors.append(f"规则文件不可读: {rules_file}")
        elif not _json_ok(rules_file):
            errors.append(f"规则文件不是合法 JSON: {rules_file}")
    else:
        warnings.append(f"规则文件不存在，将视为空规则: {rules_file}")

    # 4. 资产文件（可选，缺失会自建）
    assets_file = Path(S.CONFIG_DIR) / "assets.json"
    if assets_file.exists() and not _json_ok(assets_file):
        warnings.append(f"资产文件不是合法 JSON: {assets_file}")

    # 5. 角色专属
    if role == "api":
        if not Path(S.STATIC_DIR).is_dir():
            errors.append(f"静态目录不存在: {S.STATIC_DIR}")
    elif role == "collector":
        if not _readable_file(S.FINANCIAL_FACTORS_FILE):
            errors.append(f"评分配置不可读: {S.FINANCIAL_FACTORS_FILE}")
        offset_dir = Path(S.OFFSET_FILE).parent
        if not _dir_writable(offset_dir):
            errors.append(f"偏移量目录不可写: {offset_dir}")
        if not Path(S.SYSLOG_DIR).is_dir():
            warnings.append(f"日志源目录不存在（等待 rsyslog 创建）: {S.SYSLOG_DIR}")

    return errors, warnings


def format_report(role: str, errors: list, warnings: list) -> str:
    head = "通过" if not errors else f"发现 {len(errors)} 项致命问题"
    lines = [f"[Preflight] 启动自检（{role}）：{head}"]
    lines += [f"  [WARN] {w}" for w in warnings]
    lines += [f"  [ERROR] {e}" for e in errors]
    return "\n".join(lines)


def assert_preflight(role: str = "api") -> None:
    """打印自检报告；有致命问题时抛 RuntimeError，阻断启动"""
    errors, warnings = run_preflight(role)
    print(format_report(role, errors, warnings))
    if errors:
        raise RuntimeError(f"启动自检未通过（{len(errors)} 项致命问题），请先修复后再启动")
