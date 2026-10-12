#!/usr/bin/env python3
"""
storage/audit.py - 统一审计写入

三类审计（规则 / 资产 / 沉底动作）原先分散在各路由中，JSON 字段与异常处理各自不同。
这里收敛为单一模块，**保持既有 JSON 字段与 DB 表结构不变**：
  - 规则审计：rule_audit.log(JSONL) + audit_rule_log(DB)
  - 资产审计：asset_audit.log(JSONL) + audit_asset_log(DB)
  - 沉底审计：sink_audit.log(JSONL)（供 /api/actions/history 读取）
"""
import sys
import os
import json
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import LOG_DIR
from storage.db import get_conn


def _append_jsonl(filename: str, entry: dict) -> None:
    """统一追加一行 JSON；失败只告警，不影响主流程"""
    path = Path(LOG_DIR) / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, 'a') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as e:
        print(f"[WARN] 审计日志写入文件失败({filename}): {e}")


def _insert(sql: str, params: tuple, what: str) -> bool:
    try:
        conn = get_conn()
        conn.execute(sql, params)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERROR] {what}写入数据库失败: {e}")
        return False


# ============================================================
# 规则审计
# ============================================================
def insert_rule_audit(operator: str, action: str, rule_id: str,
                      rule_data: dict = None, source: str = "manual",
                      client_ip: str = None) -> bool:
    """写规则审计到 DB（升格信号等多条路径共用）"""
    return _insert(
        "INSERT INTO audit_rule_log (operator, action, rule_id, rule_data, source, client_ip) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (operator, action, rule_id,
         json.dumps(rule_data, ensure_ascii=False) if rule_data else None,
         source, client_ip or "unknown"),
        "规则审计")


def write_rule_audit(operator: str, action: str, rule_id: str, detail: str = "",
                     rule_data: dict = None, client_ip: str = None) -> None:
    """规则审计：JSONL + DB"""
    _append_jsonl("rule_audit.log", {
        "timestamp": datetime.now().isoformat(),
        "operator": operator,
        "action": action,
        "rule_id": rule_id,
        "detail": detail,
        "rule_data": rule_data,
        "client_ip": client_ip or "unknown",
    })
    insert_rule_audit(operator, action, rule_id, rule_data, "manual", client_ip)


# ============================================================
# 资产审计
# ============================================================
def write_asset_audit(operator: str, action: str, asset_id: str, detail: str = "",
                      asset_data: dict = None, client_ip: str = None) -> None:
    """资产审计：JSONL + DB"""
    _append_jsonl("asset_audit.log", {
        "timestamp": datetime.now().isoformat(),
        "operator": operator,
        "action": action,
        "asset_id": asset_id,
        "detail": detail,
        "asset_data": asset_data,
        "client_ip": client_ip or "unknown",
    })
    _insert(
        "INSERT INTO audit_asset_log (operator, action, asset_id, asset_data, detail, client_ip) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (operator, action, asset_id,
         json.dumps(asset_data) if asset_data else None,
         detail, client_ip or "unknown"),
        "资产审计")


# ============================================================
# 沉底动作审计
# ============================================================
def write_sink_audit(operator: str, action: str, mode: str, src_ip: str,
                     alert_id: str, reason: str, count: int, rule_id: str = None) -> None:
    """沉底动作审计：JSONL（供 /api/actions/history 读取）"""
    _append_jsonl("sink_audit.log", {
        "timestamp": datetime.now().isoformat(),
        "operator": operator,
        "action": action,
        "mode": mode,
        "src_ip": src_ip,
        "alert_id": alert_id,
        "reason": reason,
        "affected_count": count,
        "rule_id": rule_id,
    })


def read_sink_audit(operator: str) -> list:
    """读取某操作人的沉底审计（时间倒序，最近 100 条）"""
    path = Path(LOG_DIR) / "sink_audit.log"
    if not path.exists():
        return []
    items = []
    with open(path, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                if entry.get('operator') == operator:
                    items.append(entry)
            except Exception:
                continue
    items.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return items[:100]
