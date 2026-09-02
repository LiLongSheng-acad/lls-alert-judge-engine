#!/usr/bin/env python3
"""
api/routes/actions.py - 告警动作处理（从 Cookie 读取用户身份）
"""
import sys
import os
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional

# 修正 sys.path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import APIRouter, Cookie, HTTPException, Request
from pydantic import BaseModel, Field

from config.settings import CONFIG_DIR, LOG_DIR, DB_PATH, COOKIE_USER_KEY
from lib.validator import InputValidator

router = APIRouter(prefix="/actions")


# ============================================================
# 请求模型
# ============================================================

class SinkRequest(BaseModel):
    action: str = Field(default="sink", description="操作类型")
    alert_id: str = Field(..., description="告警ID")
    mode: str = Field(..., description="single 或 ip_temp")
    reason: str = Field(..., description="沉底原因")
    create_rule: bool = Field(default=False, description="是否创建临时规则")


class BatchSinkRequest(BaseModel):
    action: str = "batch_sink"
    alert_ids: list = Field(..., description="告警ID列表")
    reason: str = Field(default="批量沉底", description="沉底原因")


class ApiResponse(BaseModel):
    code: int = 0
    msg: str = "success"
    data: Optional[Any] = None


# ============================================================
# 辅助函数
# ============================================================

def get_db_conn():
    return sqlite3.connect(str(DB_PATH))


def write_audit_log(operator: str, action: str, mode: str, src_ip: str, alert_id: str, reason: str, count: int, rule_id: str = None):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "operator": operator,
        "action": action,
        "mode": mode,
        "src_ip": src_ip,
        "alert_id": alert_id,
        "reason": reason,
        "affected_count": count,
        "rule_id": rule_id
    }
    log_path = LOG_DIR / "sink_audit.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, 'a') as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")


def create_temp_rule(ip: str, reason: str, operator: str) -> Optional[str]:
    """创建临时规则（24小时过期，个人规则）"""
    rule_id = f"temp_{datetime.now().strftime('%Y%m%d%H%M%S')}_{ip.replace('.', '_')}"

    rules_file = CONFIG_DIR / "sink_rules.json"
    if rules_file.exists():
        try:
            with open(rules_file, 'r') as f:
                data = json.load(f)
                rules = data.get('rules', [])
        except:
            rules = []
    else:
        rules = []

    # 去重检查
    for r in rules:
        if r.get('field') == 'src_ip' and r.get('value') == ip and r.get('enabled') is True:
            return r.get('id')

    new_rule = {
        "id": rule_id,
        "field": "src_ip",
        "operator": "exact",
        "value": ip,
        "scope": "personal",
        "creator": operator,
        "reason": f"临时沉底: {reason}",
        "expire_at": (datetime.now() + timedelta(hours=24)).isoformat(),
        "enabled": True
    }
    rules.append(new_rule)

    # 原子写入
    tmp_path = rules_file.with_suffix('.tmp')
    try:
        rules_file.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp_path, 'w') as f:
            json.dump({"rules": rules}, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, rules_file)
    except Exception as e:
        print(f"[ERROR] 保存规则失败: {e}")
        return None

    try:
        from providers.rule_provider import RuleProvider
        provider = RuleProvider()
        provider.reload()
    except Exception as e:
        print(f"[WARN] 热重载失败: {e}")

    return rule_id


# ============================================================
# API 路由
# ============================================================

@router.post("/sink")
async def sink_alert(
    request: Request,
    req_data: Dict[str, Any],
    user: str = Cookie(default="system", alias=COOKIE_USER_KEY)
) -> ApiResponse:
    """
    沉底操作（用户身份从 Cookie 自动获取）
    """
    # ---- 统一输入校验 ----
    validated = InputValidator.validate_and_clean(
        req_data,
        rules={
            "alert_id": "str",
            "mode": "str",
            "reason": "str",
            "create_rule": "bool",
        }
    )

    req = SinkRequest(**validated)

    try:
        conn = get_db_conn()
        cursor = conn.cursor()

        cursor.execute("SELECT src_ip FROM modsec_alerts WHERE alert_id = ?", (req.alert_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return ApiResponse(code=404, msg=f"告警 {req.alert_id} 不存在")
        src_ip = row[0]

        affected_count = 0
        rule_id = None

        if req.mode == "single":
            cursor.execute(
                "UPDATE modsec_alerts SET is_blocked = 1, priority_score = -1.0 WHERE alert_id = ?",
                (req.alert_id,)
            )
            affected_count = 1
        elif req.mode == "ip_temp":
            cursor.execute(
                "UPDATE modsec_alerts SET is_blocked = 1, priority_score = -1.0 WHERE src_ip = ? AND is_blocked = 0",
                (src_ip,)
            )
            affected_count = cursor.rowcount
            if req.create_rule and affected_count > 0:
                rule_id = create_temp_rule(src_ip, req.reason, user)
        else:
            conn.close()
            return ApiResponse(code=400, msg=f"无效的 mode: {req.mode}")

        conn.commit()
        conn.close()

        write_audit_log(user, "sink", req.mode, src_ip, req.alert_id, req.reason, affected_count, rule_id)

        return ApiResponse(
            code=0,
            msg="沉底成功",
            data={
                "mode": req.mode,
                "src_ip": src_ip,
                "affected_count": affected_count,
                "rule_id": rule_id
            }
        )

    except Exception as e:
        return ApiResponse(code=500, msg=f"沉底失败: {str(e)}")


@router.post("/batch")
async def batch_sink(
    request: Request,
    req_data: Dict[str, Any],
    user: str = Cookie(default="system", alias=COOKIE_USER_KEY)
) -> ApiResponse:
    """
    批量沉底操作（用户身份从 Cookie 自动获取）
    """
    # ---- 统一输入校验 ----
    validated = InputValidator.validate_and_clean(
        req_data,
        rules={
            "alert_ids": "str",  # 列表通过，不深度清洗
            "reason": "str",
        }
    )

    req = BatchSinkRequest(**validated)

    if not req.alert_ids:
        return ApiResponse(code=400, msg="未选择告警")

    try:
        conn = get_db_conn()
        cursor = conn.cursor()

        placeholders = ','.join(['?'] * len(req.alert_ids))
        cursor.execute(
            f"UPDATE modsec_alerts SET is_blocked = 1, priority_score = -1.0 WHERE alert_id IN ({placeholders})",
            req.alert_ids
        )
        affected = cursor.rowcount
        conn.commit()
        conn.close()

        write_audit_log(user, "batch_sink", "batch", "multiple", ",".join(req.alert_ids[:3]), req.reason, affected, None)

        return ApiResponse(
            code=0,
            msg=f"成功沉底 {affected} 条告警",
            data={"affected_count": affected}
        )

    except Exception as e:
        return ApiResponse(code=500, msg=f"批量沉底失败: {str(e)}")


@router.post("/history")
async def get_history(
    user: str = Cookie(default="system", alias=COOKIE_USER_KEY)
) -> ApiResponse:
    """获取操作历史（仅当前用户可见）"""
    log_path = LOG_DIR / "sink_audit.log"
    if not log_path.exists():
        return ApiResponse(code=0, msg="success", data={"items": []})

    items = []
    with open(log_path, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                if entry.get('operator') == user:
                    items.append(entry)
            except:
                continue

    items.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return ApiResponse(code=0, msg="success", data={"items": items[:100]})


@router.post("/aggregate_sink")
async def aggregate_sink(
    request: Request,
    req_data: Dict[str, Any],
    user: str = Cookie(default="system", alias=COOKIE_USER_KEY)
) -> ApiResponse:
    """
    聚合沉底：根据 src_ip + attack_type + uri 批量沉底
    """
    # ---- 统一输入校验 ----
    validated = InputValidator.validate_and_clean(
        req_data,
        rules={
            "src_ip": "ip",
            "attack_type": "str",
            "uri": "str",
            "reason": "str",
        }
    )

    src_ip = validated.get("src_ip")
    attack_type = validated.get("attack_type")
    uri = validated.get("uri")
    reason = validated.get("reason", "聚合沉底")

    if not src_ip or not attack_type:
        return ApiResponse(code=400, msg="缺少 src_ip 或 attack_type")

    try:
        conn = get_db_conn()
        cursor = conn.cursor()

        if uri:
            cursor.execute(
                "UPDATE modsec_alerts SET is_blocked = 1, priority_score = -1.0 "
                "WHERE src_ip = ? AND attack_type = ? AND COALESCE(uri, '') = ? AND is_blocked = 0",
                (src_ip, attack_type, uri)
            )
        else:
            cursor.execute(
                "UPDATE modsec_alerts SET is_blocked = 1, priority_score = -1.0 "
                "WHERE src_ip = ? AND attack_type = ? AND (uri IS NULL OR uri = '') AND is_blocked = 0",
                (src_ip, attack_type)
            )

        affected_count = cursor.rowcount
        conn.commit()
        conn.close()

        write_audit_log(user, "aggregate_sink", "aggregate", src_ip, 
                        f"{attack_type}|{uri}", reason, affected_count, None)

        return ApiResponse(
            code=0,
            msg=f"聚合沉底成功，影响 {affected_count} 条告警",
            data={"affected_count": affected_count}
        )

    except Exception as e:
        return ApiResponse(code=500, msg=f"聚合沉底失败: {str(e)}")


@router.post("/ip_sink")
async def ip_sink(
    request: Request,
    req_data: Dict[str, Any],
    user: str = Cookie(default="system", alias=COOKIE_USER_KEY)
) -> ApiResponse:
    """
    IP批量沉底（监控模式快捷入口）
    沉底指定IP的所有未沉底告警
    可选同步到临时规则（24小时，仅个人）
    """
    # ---- 统一输入校验 ----
    validated = InputValidator.validate_and_clean(
        req_data,
        rules={
            "src_ip": "ip",
            "reason": "str",
            "create_rule": "bool",
        }
    )

    src_ip = validated.get("src_ip")
    reason = validated.get("reason", "IP批量沉底")
    create_rule = validated.get("create_rule", False)

    if not src_ip:
        return ApiResponse(code=400, msg="缺少 src_ip 参数")

    try:
        conn = get_db_conn()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE modsec_alerts SET is_blocked = 1, priority_score = -1.0 WHERE src_ip = ? AND is_blocked = 0",
            (src_ip,)
        )
        affected_count = cursor.rowcount
        conn.commit()
        conn.close()

        rule_id = None
        if create_rule and affected_count > 0:
            rule_id = create_temp_rule(src_ip, reason, user)

        write_audit_log(user, "ip_sink", "ip_batch", src_ip, "batch", reason, affected_count, rule_id)

        return ApiResponse(
            code=0,
            msg=f"IP批量沉底成功，影响 {affected_count} 条告警",
            data={
                "affected_count": affected_count,
                "rule_id": rule_id
            }
        )

    except Exception as e:
        return ApiResponse(code=500, msg=f"IP批量沉底失败: {str(e)}")