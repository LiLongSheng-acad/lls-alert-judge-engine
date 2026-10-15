#!/usr/bin/env python3
"""
api/routes/actions.py - 告警动作处理（从 Cookie 读取用户身份）
"""
import sys
import os
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional

# 修正 sys.path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import APIRouter, Cookie, HTTPException, Request
from pydantic import BaseModel, Field

from config.settings import CONFIG_DIR, COOKIE_USER_KEY
from lib.validator import InputValidator
from storage.db import get_conn
from storage.audit import write_sink_audit, read_sink_audit, insert_rule_audit
from api.common import ApiResponse, server_error

router = APIRouter(prefix="/actions")


# ============================================================
# 请求模型
# ============================================================

class SinkRequest(BaseModel):
    action: str = Field(default="sink", description="操作类型")
    alert_id: str = Field(..., description="告警ID")
    mode: str = Field(..., description="single 或 ip_temp")
    verdict: str = Field(default="ignore", description="研判结论: ignore 忽略 / investigate 排查 / block 封堵")
    reason: str = Field(default="", description="理由（仅「忽略」需要二级说明）")
    create_rule: bool = Field(default=False, description="是否创建临时规则")


class BatchSinkRequest(BaseModel):
    action: str = "batch_sink"
    alert_ids: list = Field(..., description="告警ID列表")
    verdict: str = Field(default="ignore", description="研判结论")
    reason: str = Field(default="", description="理由")


# ============================================================
# 辅助函数
# ============================================================

# ---- 研判结论（verdict）----
# 一线对一条告警只有三个动作，且三者的下游痕迹完全不同：
#   ignore      忽略 —— 结案：从主视图移出（沉底）。**只有它需要理由**
#                       （因为只有它能凭空让告警消失），二级为枚举值。
#   investigate 排查 —— 在办：同样从主视图移出，但**不进规则**（个案排查，不是"这类都别看"）。
#                       下游要拉人、沟通、截图，痕迹比封堵还重 → 系统不再要说明。
#                       保留 is_processed 标记 → 可用「排查中」视图找回；**分数也保留**（仍按优先级排）。
#   block       封堵 —— 结案：从主视图移出（避免已封 IP 刷屏）。
#                       下游要与外界沟通并发截图，证据在系统外 → 系统不再要说明。
VALID_VERDICTS = ("ignore", "investigate", "block")

VERDICT_EFFECT = {
    "ignore": "is_blocked = 1, priority_score = -1.0",
    "investigate": "is_blocked = 1, is_processed = 1",
    "block": "is_blocked = 1, priority_score = -1.0",
}
VERDICT_MSG = {"ignore": "已忽略", "investigate": "已标记排查", "block": "已登记封堵"}


def normalize_verdict(v) -> str:
    return v if v in VALID_VERDICTS else "ignore"


def verdict_effect(verdict: str) -> str:
    """结论 -> UPDATE 的 SET 片段（取自常量表，无注入面）"""
    return VERDICT_EFFECT[verdict]


def is_closing(verdict: str) -> bool:
    """忽略 / 封堵 = 结案（可沉底、可建临时规则）；排查 = 在办"""
    return verdict != "investigate"


def create_temp_rule(ip: str, reason: str, operator: str) -> Optional[str]:
    """创建临时规则（24小时过期，个人规则）

    注意：无论是否命中已有规则，都会记录一次「提出」审计，
    以支撑规则升格机制的「多人多次」统计（去重短路不能吞掉提出信号）。
    """
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

    # 去重检查：命中已有规则时仍记录一次「提出」
    for r in rules:
        if r.get('field') == 'src_ip' and r.get('value') == ip and r.get('enabled') is True:
            insert_rule_audit(operator, "create", r.get('id'), r, source="sink_temp")
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
        "enabled": True,
        "created_at": datetime.now().isoformat(),
        "retired_at": None
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

    insert_rule_audit(operator, "create", rule_id, new_rule, source="sink_temp")

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
            "verdict": "str",
            "reason": "str",
            "create_rule": "bool",
        }
    )

    req = SinkRequest(**validated)

    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()

        cursor.execute("SELECT src_ip FROM modsec_alerts WHERE alert_id = ?", (req.alert_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return ApiResponse(code=404, msg=f"告警 {req.alert_id} 不存在")
        src_ip = row[0]

        affected_count = 0
        rule_id = None

        verdict = normalize_verdict(req.verdict)
        effect = verdict_effect(verdict)

        if req.mode == "single":
            cursor.execute(
                f"UPDATE modsec_alerts SET {effect} WHERE alert_id = ?",
                (req.alert_id,)
            )
            affected_count = 1
        elif req.mode == "ip_temp":
            cursor.execute(
                f"UPDATE modsec_alerts SET {effect} WHERE src_ip = ? AND is_blocked = 0",
                (src_ip,)
            )
            affected_count = cursor.rowcount
            if req.create_rule and affected_count > 0 and is_closing(verdict):
                rule_id = create_temp_rule(src_ip, req.reason, user)
        else:
            conn.close()
            return ApiResponse(code=400, msg=f"无效的 mode: {req.mode}")

        conn.commit()
        conn.close()

        write_sink_audit(user, verdict, req.mode, src_ip, req.alert_id, req.reason, affected_count, rule_id)

        return ApiResponse(
            code=0,
            msg=VERDICT_MSG[verdict],
            data={
                "mode": req.mode,
                "verdict": verdict,
                "src_ip": src_ip,
                "affected_count": affected_count,
                "rule_id": rule_id
            }
        )

    except Exception as e:
        return server_error(e, "沉底", db_label=None)
    finally:
        if conn:
            conn.close()


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
    # 注意：alert_ids 是列表，不能被按字符串清洗，否则会被 str() 化成 "[...]" 导致校验失败
    validated = InputValidator.validate_and_clean(
        req_data,
        rules={
            "verdict": "str",
            "reason": "str",
        }
    )

    req = BatchSinkRequest(**validated)

    if not req.alert_ids:
        return ApiResponse(code=400, msg="未选择告警")

    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()

        verdict = normalize_verdict(req.verdict)
        placeholders = ','.join(['?'] * len(req.alert_ids))
        cursor.execute(
            f"UPDATE modsec_alerts SET {verdict_effect(verdict)} WHERE alert_id IN ({placeholders})",
            req.alert_ids
        )
        affected = cursor.rowcount
        conn.commit()
        conn.close()

        write_sink_audit(user, verdict, "batch", "multiple", ",".join(req.alert_ids[:3]), req.reason, affected, None)

        return ApiResponse(
            code=0,
            msg=f"{VERDICT_MSG[verdict]}（{affected} 条）",
            data={"affected_count": affected, "verdict": verdict}
        )

    except Exception as e:
        return server_error(e, "批量沉底", db_label=None)
    finally:
        if conn:
            conn.close()


@router.post("/history")
async def get_history(
    user: str = Cookie(default="system", alias=COOKIE_USER_KEY)
) -> ApiResponse:
    """获取操作历史（仅当前用户可见）"""
    items = read_sink_audit(user)
    return ApiResponse(code=0, msg="success", data={"items": items})


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
            "verdict": "str",
            "reason": "str",
        }
    )

    src_ip = validated.get("src_ip")
    attack_type = validated.get("attack_type")
    uri = validated.get("uri")
    verdict = normalize_verdict(validated.get("verdict"))
    reason = validated.get("reason", "")

    if not src_ip or not attack_type:
        return ApiResponse(code=400, msg="缺少 src_ip 或 attack_type")

    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()

        effect = verdict_effect(verdict)
        if uri:
            cursor.execute(
                f"UPDATE modsec_alerts SET {effect} "
                "WHERE src_ip = ? AND attack_type = ? AND COALESCE(uri, '') = ? AND is_blocked = 0",
                (src_ip, attack_type, uri)
            )
        else:
            cursor.execute(
                f"UPDATE modsec_alerts SET {effect} "
                "WHERE src_ip = ? AND attack_type = ? AND (uri IS NULL OR uri = '') AND is_blocked = 0",
                (src_ip, attack_type)
            )

        affected_count = cursor.rowcount
        conn.commit()
        conn.close()

        write_sink_audit(user, verdict, "aggregate", src_ip,
                        f"{attack_type}|{uri}", reason, affected_count, None)

        return ApiResponse(
            code=0,
            msg=f"{VERDICT_MSG[verdict]}（{affected_count} 条）",
            data={"affected_count": affected_count, "verdict": verdict}
        )

    except Exception as e:
        return server_error(e, "聚合沉底", db_label=None)
    finally:
        if conn:
            conn.close()


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
            "verdict": "str",
            "reason": "str",
            "create_rule": "bool",
        }
    )

    src_ip = validated.get("src_ip")
    verdict = normalize_verdict(validated.get("verdict"))
    reason = validated.get("reason", "")
    create_rule = validated.get("create_rule", False)

    if not src_ip:
        return ApiResponse(code=400, msg="缺少 src_ip 参数")

    conn = None
    try:
        conn = get_conn()
        cursor = conn.cursor()

        cursor.execute(
            f"UPDATE modsec_alerts SET {verdict_effect(verdict)} WHERE src_ip = ? AND is_blocked = 0",
            (src_ip,)
        )
        affected_count = cursor.rowcount
        conn.commit()
        conn.close()

        rule_id = None
        if create_rule and affected_count > 0 and is_closing(verdict):
            rule_id = create_temp_rule(src_ip, reason, user)

        write_sink_audit(user, verdict, "ip_batch", src_ip, "batch", reason, affected_count, rule_id)

        return ApiResponse(
            code=0,
            msg=f"{VERDICT_MSG[verdict]}（{affected_count} 条）",
            data={
                "affected_count": affected_count,
                "verdict": verdict,
                "rule_id": rule_id
            }
        )

    except Exception as e:
        return server_error(e, "IP批量沉底", db_label=None)
    finally:
        if conn:
            conn.close()