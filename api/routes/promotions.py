#!/usr/bin/env python3
"""
api/routes/promotions.py - 规则升格候选（通知）API

机制：同一规则指纹在窗口期内被「多人多次」提出时，作为一条“升格候选通知”
推送到管理员界面（拉模式）。管理员可：
  - 知晓：仅确认收到通知，此后 15 天内同一指纹不再重复通知
  - 升格：据此手动新建长期（全局）规则（由规则管理接口完成）

本接口只读 + 记录「知晓」，不自动改写任何现有规则。
"""
import sys
import os
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fastapi import APIRouter, Cookie, Request

from config.settings import CONFIG_DIR, COOKIE_USER_KEY, RULE_PROMOTION
from storage.db import get_conn
from lib.rule_fingerprint import compute_fingerprint
from api.common import ApiResponse, server_error

router = APIRouter()


def ensure_promotion_table():
    """确保 rule_promotion_ack 表存在（API 独立启动、采集器未运行时也要可用）"""
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rule_promotion_ack (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                field TEXT,
                rule_operator TEXT,
                value TEXT,
                operator TEXT NOT NULL,
                note TEXT,
                created_at TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_promotion_ack_fingerprint ON rule_promotion_ack(fingerprint)")
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"[WARN] 确保升格知晓表存在时出错: {e}")


def _load_acks() -> Dict[str, str]:
    """加载知晓记录：{fingerprint: 最近一次知晓时间}"""
    result: Dict[str, str] = {}
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT fingerprint, created_at FROM rule_promotion_ack ORDER BY created_at ASC")
        for fp, created_at in cursor.fetchall():
            if fp:
                result[fp] = created_at or ""
        conn.close()
    except sqlite3.Error as e:
        print(f"[WARN] 加载升格知晓记录失败: {e}")
    return result


def _load_global_fingerprints() -> set:
    """已存在的全局规则指纹集合（已升格的候选无需再通知）"""
    rules_file = CONFIG_DIR / "sink_rules.json"
    fingerprints = set()
    if not rules_file.exists():
        return fingerprints
    try:
        with open(rules_file, 'r') as f:
            data = json.load(f)
        for rule in data.get('rules', []):
            if rule.get('scope') == 'global':
                fingerprints.add(compute_fingerprint(
                    rule.get('field', ''), rule.get('operator', ''), rule.get('value', '')
                ))
    except Exception as e:
        print(f"[WARN] 加载全局规则指纹失败: {e}")
    return fingerprints


def _ack_candidate(req_data: Dict[str, Any], user: str) -> ApiResponse:
    """记录「知晓」：15 天内同一指纹不再重复通知"""
    fingerprint = (req_data.get("fingerprint") or "").strip()
    if not fingerprint:
        return ApiResponse(code=400, msg="缺少 fingerprint")
    note = str(req_data.get("note") or "已知晓")
    field = str(req_data.get("field") or "")
    rule_operator = str(req_data.get("rule_operator") or "")
    value = str(req_data.get("value") or "")
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO rule_promotion_ack (fingerprint, field, rule_operator, value, operator, note)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (fingerprint, field, rule_operator, value, user, note))
        conn.commit()
        conn.close()
        return ApiResponse(code=0, msg="已记录知晓", data={"fingerprint": fingerprint})
    except sqlite3.Error as e:
        return server_error(e, "查询")
    finally:
        if conn:
            conn.close()


@router.post("/promotions")
async def handle_promotions(
    request: Request,
    req_data: Dict[str, Any],
    user: str = Cookie(default="system", alias=COOKIE_USER_KEY)
) -> ApiResponse:
    """规则升格候选通知（仅管理员）"""
    if user != 'admin':
        return ApiResponse(code=403, msg="只有管理员可以查看规则升格候选")

    action = req_data.get("action", "list")
    if action == "ack":
        return _ack_candidate(req_data, user)
    if action != "list":
        return ApiResponse(code=400, msg=f"未知的 action: {action}")

    mode = req_data.get("mode") or RULE_PROMOTION.get("default_mode", "loose")
    if mode not in ("loose", "strict"):
        mode = "loose"
    threshold = RULE_PROMOTION.get(mode, RULE_PROMOTION["loose"])
    min_creators = int(threshold["min_creators"])
    min_per_creator = int(threshold["min_per_creator"])
    window_days = int(RULE_PROMOTION.get("window_days", 15))

    cutoff = (datetime.now() - timedelta(days=window_days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT operator, rule_data, created_at
            FROM audit_rule_log
            WHERE action = 'create' AND created_at >= ?
        """, (cutoff,))
        rows = cursor.fetchall()
        conn.close()
    except sqlite3.Error as e:
        return server_error(e, "查询")
    finally:
        if conn:
            conn.close()

    # 按规则指纹聚合
    groups: Dict[str, Dict[str, Any]] = {}
    for operator, rule_data, created_at in rows:
        try:
            rd = json.loads(rule_data) if rule_data else None
        except Exception:
            rd = None
        if not isinstance(rd, dict):
            continue
        field = rd.get('field')
        op = rd.get('operator')
        value = rd.get('value')
        if not field or not op or value in (None, ''):
            continue

        fp = compute_fingerprint(field, op, value)
        group = groups.setdefault(fp, {
            "field": field,
            "operator": op,
            "value": value,
            "creators": {},
            "total_count": 0,
            "last_time": ""
        })
        group["creators"][operator] = group["creators"].get(operator, 0) + 1
        group["total_count"] += 1
        if created_at and created_at > group["last_time"]:
            group["last_time"] = created_at

    promoted = _load_global_fingerprints()
    acks = _load_acks()

    items = []
    for fp, group in groups.items():
        if fp in promoted:
            continue
        # 知晓后 15 天内不再重复通知
        if fp in acks and acks[fp] >= cutoff:
            continue
        creators = group["creators"]
        if len(creators) < min_creators:
            continue
        if min(creators.values()) < min_per_creator:
            continue
        items.append({
            "fingerprint": fp,
            "field": group["field"],
            "operator": group["operator"],
            "value": group["value"],
            "creator_count": len(creators),
            "total_count": group["total_count"],
            "creators": [{"operator": k, "count": v}
                          for k, v in sorted(creators.items(), key=lambda x: -x[1])],
            "last_time": group["last_time"],
        })

    items.sort(key=lambda x: (-x["creator_count"], -x["total_count"]))

    return ApiResponse(
        code=0,
        msg="success",
        data={
            "mode": mode,
            "window_days": window_days,
            "min_creators": min_creators,
            "min_per_creator": min_per_creator,
            "total": len(items),
            "items": items
        }
    )


ensure_promotion_table()
