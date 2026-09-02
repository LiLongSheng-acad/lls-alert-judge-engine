#!/usr/bin/env python3
"""
api/routes/alerts.py - 告警查询 API（查询层统一过滤 + 聚合支持）
"""
import sys
import os
import json
import sqlite3
from typing import Dict, Any, Optional
from fastapi import APIRouter, Cookie, HTTPException, Request
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.settings import DB_PATH, CONFIG_DIR, COOKIE_USER_KEY
from lib.validator import InputValidator

router = APIRouter()


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


class ApiResponse(BaseModel):
    code: int = 0
    msg: str = "success"
    data: Optional[Any] = None


# ============================================================
# 辅助函数
# ============================================================

def get_db_conn():
    return sqlite3.connect(str(DB_PATH))


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
    """构建规则过滤 SQL"""
    if not rules:
        return "", []
    conditions = []
    params = []
    for rule in rules:
        field = rule.get('field')
        operator = rule.get('operator')
        value = rule.get('value')
        if not field or not value:
            continue
        if operator == 'exact':
            conditions.append(f"{field} = ?")
            params.append(value)
        elif operator == 'contains':
            conditions.append(f"{field} LIKE ?")
            params.append(f"%{value}%")
        elif operator == 'startswith':
            conditions.append(f"{field} LIKE ?")
            params.append(f"{value}%")
        elif operator == 'endswith':
            conditions.append(f"{field} LIKE ?")
            params.append(f"%{value}")
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
    else:
        raise HTTPException(status_code=400, detail=f"未知的 action: {action}")


async def list_alerts(req: AlertListRequest, user: str) -> ApiResponse:
    try:
        conn = get_db_conn()
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
            f = filters.dict() if hasattr(filters, 'dict') else filters
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
            sql = f"""
                SELECT 
                    src_ip,
                    dest_ip,
                    COALESCE(uri, '') as uri,
                    attack_type,
                    MAX(severity) as severity,
                    COUNT(*) as cnt,
                    MAX(priority_score) as max_priority_score,
                    MIN(log_time) as first_log_time,
                    MAX(log_time) as last_log_time,
                    MAX(alert_id) as sample_alert_id
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
                items.append({
                    "fingerprint": f"{row[0]}|{row[1]}|{row[2]}|{row[3]}",
                    "src_ip": row[0] or "",
                    "dest_ip": row[1] or "",
                    "uri": row[2] or "",
                    "attack_type": row[3] or "UNKNOWN",
                    "severity": row[4] or "INFO",
                    "count": row[5],
                    "max_priority_score": row[6] or 0.0,
                    "first_log_time": row[7] or "",
                    "last_log_time": row[8] or "",
                    "sample_alert_id": row[9] or "",
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
    except sqlite3.Error as e:
        return ApiResponse(code=500, msg=f"数据库错误: {str(e)}")
    except Exception as e:
        return ApiResponse(code=500, msg=f"查询失败: {str(e)}")


async def detail_alert(req: AlertDetailRequest) -> ApiResponse:
    try:
        conn = get_db_conn()
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
    except sqlite3.Error as e:
        return ApiResponse(code=500, msg=f"数据库错误: {str(e)}")
    except Exception as e:
        return ApiResponse(code=500, msg=f"查询失败: {str(e)}")


async def stats_alerts(req: AlertStatsRequest) -> ApiResponse:
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM modsec_alerts")
        total = cursor.fetchone()[0]
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
            data={"total": total, "today": today, "top_attack_types": top_types}
        )
    except sqlite3.Error as e:
        return ApiResponse(code=500, msg=f"数据库错误: {str(e)}")
    except Exception as e:
        return ApiResponse(code=500, msg=f"统计失败: {str(e)}")
