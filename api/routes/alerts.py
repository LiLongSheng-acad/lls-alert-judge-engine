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
from pydantic import BaseModel, Field, field_validator

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.settings import CONFIG_DIR, COOKIE_USER_KEY
from lib.validator import InputValidator
from storage.db import get_conn
from engine.scorer import load_red_line, load_loss_table_keys
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
    view: str = Field(default="main", description="视图: main（主视图）/ internal（内网源）/ processing（排查中）")
    filters: Optional[AlertFilters] = None
    time_from: Optional[str] = None
    time_to: Optional[str] = None

    @field_validator('view')
    @classmethod
    def validate_view(cls, v):
        if v not in ('main', 'internal', 'processing'):
            raise ValueError('view 必须是 main / internal / processing')
        return v


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


def rule_condition(rule: dict) -> tuple:
    """单条规则 -> (SQL 条件, 参数)。字段经白名单映射，未知字段返回空。"""
    column = RULE_FIELD_COLUMN.get(rule.get('field'))
    operator = rule.get('operator')
    value = rule.get('value')
    if not column or value in (None, ''):
        return "", []
    # COALESCE 避免列值为 NULL 时 NOT(cond) 因三值逻辑误伤正常告警
    expr = f"COALESCE({column}, '')"
    # src_ip 且值为 CIDR 网段时，用 ip_in_cidr 判定
    if rule.get('field') == 'src_ip' and '/' in str(value):
        return "ip_in_cidr(COALESCE(src_ip, ''), ?)", [value]
    if operator == 'exact':
        return f"{expr} = ?", [value]
    if operator == 'contains':
        return f"{expr} LIKE ?", [f"%{value}%"]
    if operator == 'startswith':
        return f"{expr} LIKE ?", [f"{value}%"]
    if operator == 'endswith':
        return f"{expr} LIKE ?", [f"%{value}"]
    if operator == 'regex':
        return f"{expr} REGEXP ?", [value]
    return "", []


def build_rule_filter_sql(rules: list) -> tuple:
    """多规则 -> 读取层过滤用的 "NOT (... OR ...)" 片段"""
    conditions = []
    params = []
    for rule in rules:
        cond, ps = rule_condition(rule)
        if cond:
            conditions.append(cond)
            params.extend(ps)
    if conditions:
        return "NOT (" + " OR ".join(conditions) + ")", params
    return "", []


def build_rule_match_sql(rules: list) -> tuple:
    """多规则 -> 正向匹配 "(cond1 OR cond2 ...)"，用于统计「被规则隐去」的数量"""
    conditions = []
    params = []
    for rule in rules:
        cond, ps = rule_condition(rule)
        if cond:
            conditions.append(cond)
            params.extend(ps)
    if conditions:
        return "(" + " OR ".join(conditions) + ")", params
    return "", []


def split_rules_by_intent(rules: list) -> tuple:
    """按 intent 拆分规则 -> (sink 沉底规则, exempt 内网源豁免规则)。

    历史规则没有 intent 字段，一律视为 sink（保持原有行为）。
    """
    sink, exempt = [], []
    for rule in rules:
        (exempt if rule.get('intent') == 'exempt' else sink).append(rule)
    return sink, exempt


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
            "view": "str",
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
        return await detail_alert(req, user)
    elif action == "stats":
        req = AlertStatsRequest(**validated)
        return await stats_alerts(req, user)
    elif action == "report":
        return await report_alerts(validated, user)
    else:
        raise HTTPException(status_code=400, detail=f"未知的 action: {action}")


async def list_alerts(req: AlertListRequest, user: str) -> ApiResponse:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        red_line = load_red_line()

        where_clauses = []
        params = []

        # 时间过滤
        if req.time_from:
            where_clauses.append("log_time >= ?")
            params.append(req.time_from)
        if req.time_to:
            where_clauses.append("log_time <= ?")
            params.append(req.time_to)

        # 监控模式：过滤已沉底告警（「排查中」是独立透镜，不受此限）
        if not req.ignore_filters and req.view != 'processing':
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

        # ---- 视图分流 + 规则过滤 ----
        # 规则按「意图」分两类（缺省视为 sink）：
        #   sink   —— 沉底规则：命中即从主视图隐去；仅在「监控模式」下生效
        #   exempt —— 内网源豁免：命中即划入「内网源视图」，始终从主视图移出
        # 注意：豁免是「分区」不是「沉底」——统计口径不分离，仍计入 total / rule_sunk。
        rules = load_rules(user)
        active_rules = rules.get('global', []) + rules.get('personal', [])
        sink_rules, exempt_rules = split_rules_by_intent(active_rules)

        if req.view == 'internal':
            # 内网源视图：只保留豁免规则命中的告警
            match_sql, match_params = build_rule_match_sql(exempt_rules)
            if match_sql:
                where_clauses.append(match_sql)
                params.extend(match_params)
            else:
                where_clauses.append("1 = 0")  # 未配置任何豁免规则 → 视图为空
        elif req.view == 'processing':
            # 排查中视图：只看被标记为「在办」的告警（不分沉底状态、不受规则影响）
            where_clauses.append("is_processed = 1")
        else:
            # 主视图：豁免命中的告警始终移出
            exempt_sql, exempt_params = build_rule_filter_sql(exempt_rules)
            if exempt_sql:
                where_clauses.append(exempt_sql)
                params.extend(exempt_params)
            if not req.ignore_filters:
                sink_sql, sink_params = build_rule_filter_sql(sink_rules)
                if sink_sql:
                    where_clauses.append(sink_sql)
                    params.extend(sink_params)

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
                    MAX(log_time) as last_log_time,
                    MAX(is_processed) as has_processing
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
                has_processing = row[9]
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
                    "below_red_line": (max_score or 0.0) < red_line,
                    "has_processing": bool(has_processing),
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
                    attack_type, severity, priority_score, log_time, is_processed
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
                    "below_red_line": (row[7] or 0.0) < red_line,
                    "log_time": row[8] or "",
                    "is_processed": row[9] or 0,
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


async def detail_alert(req: AlertDetailRequest, user: str) -> ApiResponse:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                alert_id, src_ip, dest_ip, uri, method,
                attack_type, severity, priority_score,
                payload, raw_message, log_time, is_blocked
            FROM modsec_alerts
            WHERE alert_id = ?
        """, (req.alert_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return ApiResponse(code=404, msg=f"告警 {req.alert_id} 不存在")

        # 按需归因：实时计算哪些（当前用户可见的）规则会隐去这条告警（不落字段）
        hidden_by = []
        rules = load_rules(user)
        for rule in rules.get('global', []) + rules.get('personal', []):
            cond, ps = rule_condition(rule)
            if not cond:
                continue
            cursor.execute(
                f"SELECT 1 FROM modsec_alerts WHERE alert_id = ? AND {cond} LIMIT 1",
                [req.alert_id] + ps)
            if cursor.fetchone():
                hidden_by.append({
                    "rule_id": rule.get('id', ''),
                    "field": rule.get('field', ''),
                    "operator": rule.get('operator', ''),
                    "value": rule.get('value', ''),
                    "scope": rule.get('scope', 'personal'),
                    "creator": rule.get('creator', ''),
                    "reason": rule.get('reason', ''),
                    "expire_at": rule.get('expire_at', ''),
                })
        conn.close()
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
                "below_red_line": (row[7] or 0.0) < load_red_line(),
                "payload": row[8] or "",
                "raw_message": row[9] or "",
                "log_time": row[10] or "",
                "is_blocked": row[11] or 0,
                "hidden_by": hidden_by,
            }
        )
    except Exception as e:
        return server_error(e, "查询")
    finally:
        if conn:
            conn.close()


async def stats_alerts(req: AlertStatsRequest, user: str) -> ApiResponse:
    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM modsec_alerts")
        total = cursor.fetchone()[0]
        # 动作沉底：显式标记 is_blocked=1
        cursor.execute("SELECT COUNT(*) FROM modsec_alerts WHERE is_blocked = 1")
        action_sunk = cursor.fetchone()[0]
        # 规则沉底：未标记 is_blocked，但被当前用户可见的规则在读取层隐去
        rules = load_rules(user)
        rule_match, rule_params = build_rule_match_sql(
            rules.get('global', []) + rules.get('personal', []))
        if rule_match:
            cursor.execute(
                f"SELECT COUNT(*) FROM modsec_alerts WHERE is_blocked = 0 AND {rule_match}",
                rule_params)
            rule_sunk = cursor.fetchone()[0]
        else:
            rule_sunk = 0
        sunk_total = action_sunk + rule_sunk
        # 真实待处理 = 既没被动作沉底、也没被规则隐去
        pending = max(total - sunk_total, 0)
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
                "action_sunk": action_sunk,
                "rule_sunk": rule_sunk,
                "sunk_total": sunk_total,
                "blocked": sunk_total,
                "sunk_ratio": round(sunk_total / total, 4) if total else 0.0,
                "today": today,
                "top_attack_types": top_types,
            }
        )
    except Exception as e:
        return server_error(e, "统计")
    finally:
        if conn:
            conn.close()


async def report_alerts(validated: Dict[str, Any], user: str) -> ApiResponse:
    """
    日报统计：
      总告警 / 动作沉底 / 规则沉底 / 剩余未研判 / 沉底占比
      + 规则维度明细（每条规则在区间内的隐去量）
      + 未分类攻击类型（损失表未配置的类型 → 交由管理员评判后补录）
    口径说明：规则维度为「按当前规则重算」，非历史实际值。
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
        rng = "log_time >= ? AND log_time <= ?"
        rng_params = [time_from, time_to]

        cursor.execute(f"SELECT COUNT(*) FROM modsec_alerts WHERE {rng}", rng_params)
        total = cursor.fetchone()[0]
        cursor.execute(
            f"SELECT COUNT(*) FROM modsec_alerts WHERE {rng} AND is_blocked = 1", rng_params)
        action_sunk = cursor.fetchone()[0]

        active_rules = load_rules(user)
        active_rules = active_rules.get('global', []) + active_rules.get('personal', [])
        rule_match, rule_params = build_rule_match_sql(active_rules)
        if rule_match:
            cursor.execute(
                f"SELECT COUNT(*) FROM modsec_alerts WHERE {rng} AND is_blocked = 0 AND {rule_match}",
                rng_params + rule_params)
            rule_sunk = cursor.fetchone()[0]
        else:
            rule_sunk = 0

        sunk_total = action_sunk + rule_sunk
        remaining = max(total - sunk_total, 0)

        # 规则维度：逐条规则统计区间内隐去量
        by_rule = []
        for rule in active_rules:
            cond, ps = rule_condition(rule)
            if not cond:
                continue
            cursor.execute(
                f"SELECT COUNT(*) FROM modsec_alerts WHERE {rng} AND is_blocked = 0 AND {cond}",
                rng_params + ps)
            by_rule.append({
                "rule_id": rule.get('id', ''),
                "field": rule.get('field', ''),
                "operator": rule.get('operator', ''),
                "value": rule.get('value', ''),
                "scope": rule.get('scope', 'personal'),
                "creator": rule.get('creator', ''),
                "hidden_count": cursor.fetchone()[0],
            })
        by_rule.sort(key=lambda x: -x["hidden_count"])

        # 未分类攻击类型：区间内出现过、但损失表尚未配置的类型
        # 按当前 yaml 判定——甲方补录配置后，该类型会自动移出本清单
        known_types = load_loss_table_keys()
        unclassified = []
        if known_types:
            cursor.execute(
                f"SELECT attack_type, COUNT(*) FROM modsec_alerts WHERE {rng} "
                f"GROUP BY attack_type", rng_params)
            for attack_type, cnt in cursor.fetchall():
                name = (attack_type or "UNKNOWN").upper()
                if name not in known_types:
                    unclassified.append({"attack_type": name, "count": cnt})
            unclassified.sort(key=lambda x: -x["count"])

        conn.close()
        return ApiResponse(
            code=0,
            msg="success",
            data={
                "time_from": time_from,
                "time_to": time_to,
                "total": total,
                "action_sunk": action_sunk,
                "rule_sunk": rule_sunk,
                "sunk_total": sunk_total,
                "blocked": sunk_total,
                "remaining": remaining,
                "sunk_ratio": round(sunk_total / total, 4) if total else 0.0,
                "by_rule": by_rule,
                "unclassified": unclassified,
            }
        )
    except Exception as e:
        return server_error(e, "统计")
    finally:
        if conn:
            conn.close()
