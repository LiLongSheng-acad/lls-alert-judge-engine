#!/usr/bin/env python3
"""
api/routes/alerts.py - 告警查询 API（查询层统一过滤 + 聚合支持）
"""
import sys
import os
import json
from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import APIRouter, Cookie, HTTPException, Request
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.settings import CONFIG_DIR, COOKIE_USER_KEY
from lib.validator import InputValidator
from storage.db import get_conn
from api.common import ApiResponse, server_error

router = APIRouter()

# 严重度等级序：聚合取“最高等级”时按此排序，避免字典序把 MEDIUM 判为高于 CRITICAL
SEVERITY_BY_RANK = {6: "CRITICAL", 5: "HIGH", 4: "MEDIUM", 3: "LOW", 2: "WARNING", 1: "INFO", 0: "INFO"}


# ============================================================
# 请求模型
# ============================================================

class AlertFilters(BaseModel):
    time_from: Optional[str] = None
    time_to: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    attack_type: Optional[str] = None
    severity: Optional[str] = None
    rule_id: Optional[str] = None
    vendor: Optional[str] = None
    is_blocked: Optional[int] = None


class AlertListRequest(BaseModel):
    action: str = "list"
    page: int = Field(default=1, ge=1)
    size: int = Field(default=20, ge=1, le=200)
    sort: str = "-priority_score"
    ignore_filters: bool = False
    aggregate: bool = False
    filters: Optional[AlertFilters] = None
    time_from: Optional[str] = None
    time_to: Optional[str] = None


class AlertDetailRequest(BaseModel):
    action: str = "detail"
    alert_id: str


class AlertStatsRequest(BaseModel):
    action: str = "stats"


# ============================================================
# 辅助函数
# ============================================================

# 规则字段 -> 数据库列（user_agent 实际存放于 headers JSON 中，未知字段一律跳过）
RULE_FIELD_COLUMN = {
    "uri": "uri",
    "src_ip": "src_ip",
    "method": "method",
    "attack_type": "attack_type",
    "user_agent": "headers",
}


def load_rules(user: str) -> dict:
    """加载所有规则：全局规则 + 个人规则"""
    rules_file = CONFIG_DIR / "sink_rules.json"
    result = {"global": [], "personal": []}
    if not rules_file.exists():
        return result
    try:
        with open(rules_file, 'r') as f:
            data = json.load(f)
            for rule in data.get('rules', []):
                if not rule.get('enabled', True):
                    continue
                # 过期规则不再参与查询层过滤（长期规则 expire_at 为空，永不过期）
                expire_at = rule.get('expire_at')
                if expire_at:
                    try:
                        if datetime.fromisoformat(expire_at) <= datetime.now():
                            continue
                    except ValueError:
                        pass
                scope = rule.get('scope', 'personal')
                if scope == 'global':
                    result['global'].append(rule)
                elif scope == 'personal' and rule.get('creator') == user:
                    result['personal'].append(rule)
            return result
    except Exception as e:
        print(f"[WARN] 加载规则失败: {e}")
        return result


def build_rule_filter_sql(rules: list) -> tuple:
    """构建规则过滤 SQL（字段经白名单映射，避免把未知字段拼成非法列名）"""
    if not rules:
        return "", []
    conditions = []
    params = []
    for rule in rules:
        column = RULE_FIELD_COLUMN.get(rule.get('field'))
        operator = rule.get('operator')
        value = rule.get('value')
        if not column or value in (None, ''):
            continue
        # COALESCE 避免列值为 NULL 时 NOT(cond) 因三值逻辑误伤正常告警
        expr = f"COALESCE({column}, '')"
        # src_ip 且值为 CIDR 网段时，用 ip_in_cidr 判定（与 RuleProvider 原语义一致）
        if rule.get('field') == 'src_ip' and '/' in str(value):
            conditions.append("ip_in_cidr(COALESCE(src_ip, ''), ?)")
            params.append(value)
            continue
        if operator == 'exact':
            conditions.append(f"{expr} = ?")
            params.append(value)
        elif operator == 'contains':
            conditions.append(f"{expr} LIKE ?")
            params.append(f"%{value}%")
        elif operator == 'startswith':
            conditions.append(f"{expr} LIKE ?")
            params.append(f"{value}%")
        elif operator == 'endswith':
            conditions.append(f"{expr} LIKE ?")
            params.append(f"%{value}")
        elif operator == 'regex':
            conditions.append(f"{expr} REGEXP ?")
            params.append(value)
    if conditions:
        return "NOT (" + " OR ".join(conditions) + ")", params
    return "", []


# ============================================================
# API 路由
# ============================================================

@router.post("/alerts")
async def handle_alerts(
    request: Request,
    req_data: Dict[str, Any],
    user: str = Cookie(default="system", alias=COOKIE_USER_KEY)
) -> ApiResponse:
    """
    告警统一入口
    从 Cookie 读取当前用户，用于个人规则过滤
    所有输入经过统一校验清洗
    """
    action = req_data.get("action", "list")

    # ---- 统一输入校验 ----
    validated = InputValidator.validate_and_clean(
        req_data,
        rules={
            "src_ip": "ip",
            "dst_ip": "ip",
            "attack_type": "str",
            "severity": "str",
            "time_from": "str",
            "time_to": "str",
            "alert_id": "str",
            "vendor": "str",
            "rule_id": "str",
            "sort": "str",
            "page": "int",
            "size": "int",
        }
    )

    if action == "list":
        req = AlertListRequest(**validated)
        if validated.get("time_from"):
            req.time_from = validated.get("time_from")
        if validated.get("time_to"):
            req.time_to = validated.get("time_to")
        return await list_alerts(req, user)
    elif action == "detail":
        req = AlertDetailRequest(**validated)
        return await detail_alert(req)
    elif action == "stats":
        req = AlertStatsRequest(**validated)
        return await stats_alerts(req)
    elif action == "report":
        return await report_alerts(validated)
    else:
        raise HTTPException(status_code=400, detail=f"未知的 action: {action}")


async def list_alerts(req: AlertListRequest, user: str) -> ApiResponse:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()

        where_clauses = []
        params = []

        # 时间过滤
        if req.time_from:
            where_clauses.append("log_time >= ?")
            params.append(req.time_from)
        if req.time_to:
            where_clauses.append("log_time <= ?")
            params.append(req.time_to)

        # 监控模式：过滤已沉底告警
        if not req.ignore_filters:
            where_clauses.append("is_blocked = 0")

        # 其他过滤条件
        filters = req.filters
        if filters:
            # 兼容 Pydantic v1/v2：优先 model_dump，避免调用已弃用的 dict()
            if hasattr(filters, 'model_dump'):
                f = filters.model_dump()
            elif hasattr(filters, 'dict'):
                f = filters.dict()
            else:
                f = filters
            src_ip = f.get('src_ip')
            if src_ip is not None and src_ip != '':
                src_ip = src_ip.strip()
                if '*' in src_ip or '?' in src_ip:
                    like_pattern = src_ip.replace('*', '%').replace('?', '_')
                    where_clauses.append("src_ip LIKE ?")
                    params.append(like_pattern)
                elif src_ip.endswith('.'):
                    where_clauses.append("src_ip LIKE ?")
                    params.append(src_ip + '%')
                else:
                    where_clauses.append("src_ip = ?")
                    params.append(src_ip)
            dst_ip = f.get('dst_ip')
            if dst_ip is not None and dst_ip != '':
                dst_ip = dst_ip.strip()
                if '*' in dst_ip or '?' in dst_ip:
                    like_pattern = dst_ip.replace('*', '%').replace('?', '_')
                    where_clauses.append("dest_ip LIKE ?")
                    params.append(like_pattern)
                elif dst_ip.endswith('.'):
                    where_clauses.append("dest_ip LIKE ?")
                    params.append(dst_ip + '%')
                else:
                    where_clauses.append("dest_ip = ?")
                    params.append(dst_ip)
            if f.get('attack_type'):
                where_clauses.append("attack_type = ?")
                params.append(f['attack_type'])
            if f.get('severity'):
                where_clauses.append("severity = ?")
                params.append(f['severity'])

        # 规则过滤
        if not req.ignore_filters:
            rules = load_rules(user)
            global_sql, global_params = build_rule_filter_sql(rules.get('global', []))
            if global_sql:
                where_clauses.append(global_sql)
                params.extend(global_params)
            personal_sql, personal_params = build_rule_filter_sql(rules.get('personal', []))
            if personal_sql:
                where_clauses.append(personal_sql)
                params.extend(personal_params)

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

        if req.aggregate:
            # 聚合查询：按 src_ip + dest_ip + attack_type + uri 聚合
            # severity 用显式等级序取最大（字典序会把 MEDIUM 排在 CRITICAL 之前，导致误判）
            sev_rank_expr = """
                    MAX(CASE severity
                        WHEN 'CRITICAL' THEN 6
                        WHEN 'HIGH' THEN 5
                        WHEN 'MEDIUM' THEN 4
                        WHEN 'LOW' THEN 3
                        WHEN 'WARNING' THEN 2
                        WHEN 'INFO' THEN 1
                        ELSE 0 END)"""
            sql = f"""
                SELECT 
                    src_ip,
                    dest_ip,
                    COALESCE(uri, '') as uri,
                    attack_type,
                    {sev_rank_expr} as sev_rank,
                    COUNT(*) as cnt,
                    MAX(priority_score) as max_priority_score,
                    MIN(log_time) as first_log_time,
                    MAX(log_time) as last_log_time
                FROM modsec_alerts
                WHERE {where_sql}
                GROUP BY src_ip, dest_ip, attack_type, COALESCE(uri, '')
                ORDER BY max_priority_score DESC
                LIMIT ? OFFSET ?
            """
            offset = (req.page - 1) * req.size
            cursor.execute(sql, params + [req.size, offset])
            rows = cursor.fetchall()

            # 聚合总数
            count_sql = f"""
                SELECT COUNT(DISTINCT src_ip || '|' || dest_ip || '|' || attack_type || '|' || COALESCE(uri, ''))
                FROM modsec_alerts
                WHERE {where_sql}
            """
            cursor.execute(count_sql, params)
            total = cursor.fetchone()[0]

            items = []
            for row in rows:
                src_ip, dest_ip, uri, attack_type = row[0], row[1], row[2], row[3]
                sev_rank, cnt, max_score = row[4], row[5], row[6]
                first_t, last_t = row[7], row[8]
                # 样例取「最高优先级」那条，保证与行上展示的分数/等级一致
                cursor.execute(f"""
                    SELECT alert_id FROM modsec_alerts
                    WHERE {where_sql}
                      AND src_ip = ?
                      AND COALESCE(attack_type, '') = COALESCE(?, '')
                      AND COALESCE(uri, '') = ?
                      AND COALESCE(dest_ip, '') = COALESCE(?, '')
                    ORDER BY priority_score DESC, alert_id DESC
                    LIMIT 1
                """, params + [src_ip, attack_type, uri, dest_ip])
                sample = cursor.fetchone()
                items.append({
                    "fingerprint": f"{src_ip}|{dest_ip}|{uri}|{attack_type}",
                    "src_ip": src_ip or "",
                    "dest_ip": dest_ip or "",
                    "uri": uri or "",
                    "attack_type": attack_type or "UNKNOWN",
                    "severity": SEVERITY_BY_RANK.get(sev_rank, "INFO"),
                    "count": cnt,
                    "max_priority_score": max_score or 0.0,
                    "first_log_time": first_t or "",
                    "last_log_time": last_t or "",
                    "sample_alert_id": (sample[0] if sample else "") or "",
                })
            conn.close()
            return ApiResponse(
                code=0,
                msg="success",
                data={
                    "total": total,
                    "page": req.page,
                    "size": req.size,
                    "items": items,
                    "aggregated": True,
                    "ignore_filters": req.ignore_filters
                }
            )
        else:
            # 明细查询
            sql = f"""
                SELECT 
                    alert_id, src_ip, dest_ip, uri, method,
                    attack_type, severity, priority_score, log_time
                FROM modsec_alerts
                WHERE {where_sql}
                ORDER BY priority_score DESC
                LIMIT ? OFFSET ?
            """
            offset = (req.page - 1) * req.size
            cursor.execute(sql, params + [req.size, offset])
            rows = cursor.fetchall()

            count_sql = f"SELECT COUNT(*) FROM modsec_alerts WHERE {where_sql}"
            cursor.execute(count_sql, params)
            total = cursor.fetchone()[0]

            items = []
            for row in rows:
                items.append({
                    "alert_id": row[0] or "",
                    "src_ip": row[1] or "",
                    "dest_ip": row[2] or "",
                    "uri": row[3] or "",
                    "method": row[4] or "",
                    "attack_type": row[5] or "UNKNOWN",
                    "severity": row[6] or "INFO",
                    "priority_score": row[7] or 0.0,
                    "log_time": row[8] or "",
                })
            conn.close()
            return ApiResponse(
                code=0,
                msg="success",
                data={
                    "total": total,
                    "page": req.page,
                    "size": req.size,
                    "items": items,
                    "aggregated": False,
                    "ignore_filters": req.ignore_filters
                }
            )
    except Exception as e:
        return server_error(e, "查询")
    finally:
        if conn:
            conn.close()


async def detail_alert(req: AlertDetailRequest) -> ApiResponse:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                alert_id, src_ip, dest_ip, uri, method,
                attack_type, severity, priority_score,
                payload, raw_message, log_time
            FROM modsec_alerts
            WHERE alert_id = ?
        """, (req.alert_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return ApiResponse(code=404, msg=f"告警 {req.alert_id} 不存在")
        return ApiResponse(
            code=0,
            msg="success",
            data={
                "alert_id": row[0] or "",
                "src_ip": row[1] or "",
                "dest_ip": row[2] or "",
                "uri": row[3] or "",
                "method": row[4] or "",
                "attack_type": row[5] or "UNKNOWN",
                "severity": row[6] or "INFO",
                "priority_score": row[7] or 0.0,
                "payload": row[8] or "",
                "raw_message": row[9] or "",
                "log_time": row[10] or "",
            }
        )
    except Exception as e:
        return server_error(e, "查询")
    finally:
        if conn:
            conn.close()


async def stats_alerts(req: AlertStatsRequest) -> ApiResponse:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM modsec_alerts")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM modsec_alerts WHERE is_blocked = 1")
        blocked = cursor.fetchone()[0]
        pending = max(total - blocked, 0)
        cursor.execute("SELECT COUNT(*) FROM modsec_alerts WHERE date(log_time) = date('now', 'localtime')")
        today = cursor.fetchone()[0]
        cursor.execute("""
            SELECT attack_type, COUNT(*) as cnt 
            FROM modsec_alerts 
            WHERE attack_type != 'UNKNOWN'
            GROUP BY attack_type ORDER BY cnt DESC LIMIT 5
        """)
        top_types = [{"attack_type": row[0] or "UNKNOWN", "count": row[1]} for row in cursor.fetchall()]
        conn.close()
        return ApiResponse(
            code=0,
            msg="success",
            data={
                "total": total,
                "pending": pending,
                "blocked": blocked,
                "today": today,
                "top_attack_types": top_types,
            }
        )
    except Exception as e:
        return server_error(e, "统计")
    finally:
        if conn:
            conn.close()


async def report_alerts(validated: Dict[str, Any]) -> ApiResponse:
    """
    日报统计（只报真实存在的状态）：
      总告警 / 已沉底 / 剩余未研判
    时间范围默认当天，可按 log_time 指定起止。
    """
    time_from = validated.get("time_from")
    time_to = validated.get("time_to")
    if not time_from or not time_to:
        today = datetime.now().strftime("%Y-%m-%d")
        time_from = time_from or f"{today} 00:00:00"
        time_to = time_to or f"{today} 23:59:59"

    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM modsec_alerts WHERE log_time >= ? AND log_time <= ?",
            (time_from, time_to)
        )
        total = cursor.fetchone()[0]
        cursor.execute(
            "SELECT COUNT(*) FROM modsec_alerts WHERE log_time >= ? AND log_time <= ? AND is_blocked = 1",
            (time_from, time_to)
        )
        blocked = cursor.fetchone()[0]
        conn.close()
        return ApiResponse(
            code=0,
            msg="success",
            data={
                "time_from": time_from,
                "time_to": time_to,
                "total": total,
                "blocked": blocked,
                "remaining": max(total - blocked, 0),
            }
        )
    except Exception as e:
        return server_error(e, "统计")
    finally:
        if conn:
            conn.close()
