#!/usr/bin/env python3
"""
api/routes/rules.py - 沉底规则管理 API（原子写入 + 权限隔离 + 审计日志）
"""
import sys
import os
import json
import uuid
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Cookie, Request, HTTPException
from pydantic import BaseModel, Field, field_validator, ValidationInfo

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.settings import CONFIG_DIR, COOKIE_USER_KEY
from lib.validator import InputValidator
from storage.audit import write_rule_audit
from api.common import ApiResponse, server_error

router = APIRouter()


# ============================================================
# 数据模型
# ============================================================

class RuleListRequest(BaseModel):
    action: str = "list"
    page: int = Field(default=1, ge=1)
    size: int = Field(default=20, ge=1, le=100)


class RuleCreateRequest(BaseModel):
    action: str = "create"
    field: str = Field(..., description="匹配字段")
    operator: str = Field(..., description="操作符")
    value: str = Field(..., description="匹配值")
    scope: str = Field(default="personal", description="作用域: global / personal")
    reason: str = Field(..., description="沉底原因")
    expire_at: str = Field(..., description="过期时间")

    @field_validator('field')
    @classmethod
    def validate_field(cls, v):
        allowed = ['uri', 'src_ip', 'user_agent', 'method', 'attack_type']
        if v not in allowed:
            raise ValueError(f'field 必须是以下之一: {", ".join(allowed)}')
        return v

    @field_validator('value')
    @classmethod
    def validate_value(cls, v, info: ValidationInfo):
        # src_ip 值为 CIDR 时必须是合法网段，否则规则会静默永不匹配
        field = (info.data or {}).get('field')
        if field == 'src_ip' and '/' in str(v or ''):
            try:
                ipaddress.ip_network(v, strict=False)
            except ValueError:
                raise ValueError(f'无效的 CIDR 网段: {v}')
        return v

    @field_validator('operator')
    @classmethod
    def validate_operator(cls, v):
        allowed = ['contains', 'startswith', 'endswith', 'exact', 'regex']
        if v not in allowed:
            raise ValueError(f'operator 必须是以下之一: {", ".join(allowed)}')
        return v

    @field_validator('scope')
    @classmethod
    def validate_scope(cls, v):
        if v not in ['global', 'personal']:
            raise ValueError('scope 必须是 global 或 personal')
        return v

    @field_validator('expire_at')
    @classmethod
    def validate_expire_at(cls, v, info: ValidationInfo):
        scope = (info.data or {}).get('scope', 'personal')
        # 全局规则允许留空，表示长期有效（升格后的长期规则形态）
        if v is None or str(v).strip() == '':
            if scope == 'global':
                return ''
            raise ValueError('仅全局规则可设为长期有效（留空过期时间）')
        try:
            expire = datetime.fromisoformat(v)
        except ValueError:
            raise ValueError(f'无效的时间格式: {v}')
        now = datetime.now()
        if expire <= now:
            raise ValueError('过期时间必须是将来的时间')
        # 个人规则仍限制在 24 小时内；全局规则可长期
        if scope != 'global':
            max_expire = now + timedelta(hours=24)
            if expire > max_expire:
                raise ValueError(f'过期时间不能超过24小时（最大: {max_expire.isoformat()}）')
        return v


class RuleDeleteRequest(BaseModel):
    action: str = "delete"
    rule_id: str = Field(..., description="规则 ID")


class RuleToggleRequest(BaseModel):
    action: str = "toggle"
    rule_id: str = Field(..., description="规则 ID")
    enabled: bool = Field(..., description="true=启用, false=禁用")


# ============================================================
# 辅助函数
# ============================================================

def get_rules_file_path() -> Path:
    return CONFIG_DIR / "sink_rules.json"


def load_rules_from_file() -> List[Dict]:
    file_path = get_rules_file_path()
    if not file_path.exists():
        return []
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            return data.get('rules', [])
    except Exception:
        return []


def save_rules_to_file(rules: List[Dict]) -> bool:
    file_path = get_rules_file_path()
    tmp_path = file_path.with_suffix('.tmp')
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp_path, 'w') as f:
            json.dump({"rules": rules}, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, file_path)
        return True
    except Exception as e:
        print(f"[ERROR] 保存规则文件失败: {e}")
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except:
                pass
        return False


# ============================================================
# API 路由
# ============================================================

@router.post("/rules")
async def handle_rules(
    request: Request,
    req_data: Dict[str, Any],
    user: str = Cookie(default="system", alias=COOKIE_USER_KEY)
) -> ApiResponse:
    action = req_data.get("action", "list")
    client_ip = request.client.host if request.client else "unknown"

    # ---- 统一输入校验 ----
    validated = InputValidator.validate_and_clean(
        req_data,
        rules={
            "field": "str",
            "operator": "str",
            "value": "str",
            "scope": "str",
            "reason": "str",
            "expire_at": "str",
            "rule_id": "str",
            "enabled": "bool",
        }
    )

    if action == "list":
        req = RuleListRequest(**validated)
        return await list_rules(req, user)
    elif action == "create":
        req = RuleCreateRequest(**validated)
        return await create_rule(req, user, client_ip)
    elif action == "delete":
        req = RuleDeleteRequest(**validated)
        return await delete_rule(req, user, client_ip)
    elif action == "toggle":
        req = RuleToggleRequest(**validated)
        return await toggle_rule(req, user, client_ip)
    else:
        raise HTTPException(status_code=400, detail=f"未知的 action: {action}")


async def list_rules(req: RuleListRequest, user: str) -> ApiResponse:
    all_rules = load_rules_from_file()
    filtered = []
    for r in all_rules:
        if r.get('scope') == 'global':
            filtered.append(r)
        elif r.get('creator') == user:
            filtered.append(r)
    total = len(filtered)
    start = (req.page - 1) * req.size
    end = start + req.size
    items = filtered[start:end]
    return ApiResponse(
        code=0,
        msg="success",
        data={"total": total, "page": req.page, "size": req.size, "items": items}
    )


async def create_rule(req: RuleCreateRequest, user: str, client_ip: str) -> ApiResponse:
    rule_id = f"rule_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}"
    if req.scope == 'personal':
        creator = user
    else:
        if user != 'admin':
            return ApiResponse(code=403, msg="只有管理员可以创建全局规则")
        creator = user
    new_rule = {
        "id": rule_id,
        "field": req.field,
        "operator": req.operator,
        "value": req.value,
        "scope": req.scope,
        "creator": creator,
        "reason": req.reason,
        "expire_at": req.expire_at,
        "enabled": True
    }
    rules = load_rules_from_file()
    rules.append(new_rule)
    if not save_rules_to_file(rules):
        return ApiResponse(code=500, msg="保存规则失败")
    write_rule_audit(user, "create", rule_id, f"field={req.field}, value={req.value}, scope={req.scope}", new_rule, client_ip)
    return ApiResponse(code=0, msg="规则创建成功", data={"rule_id": rule_id})


async def delete_rule(req: RuleDeleteRequest, user: str, client_ip: str) -> ApiResponse:
    rules = load_rules_from_file()
    found = None
    for rule in rules:
        if rule.get('id') == req.rule_id:
            found = rule
            break
    if not found:
        return ApiResponse(code=404, msg=f"规则 {req.rule_id} 不存在")
    if found.get('scope') == 'global':
        if user != 'admin':
            return ApiResponse(code=403, msg="只有管理员可以删除全局规则")
    elif found.get('creator') != user:
        return ApiResponse(code=403, msg="只能删除自己创建的规则")
    new_rules = [r for r in rules if r.get('id') != req.rule_id]
    if not save_rules_to_file(new_rules):
        return ApiResponse(code=500, msg="保存规则失败")
    write_rule_audit(user, "delete", req.rule_id, f"field={found.get('field')}, value={found.get('value')}", found, client_ip)
    return ApiResponse(code=0, msg=f"规则 {req.rule_id} 已删除")


async def toggle_rule(req: RuleToggleRequest, user: str, client_ip: str) -> ApiResponse:
    rules = load_rules_from_file()
    found = None
    for rule in rules:
        if rule.get('id') == req.rule_id:
            found = rule
            break
    if not found:
        return ApiResponse(code=404, msg=f"规则 {req.rule_id} 不存在")
    if found.get('scope') == 'global':
        if user != 'admin':
            return ApiResponse(code=403, msg="只有管理员可以操作全局规则")
    elif found.get('creator') != user:
        return ApiResponse(code=403, msg="只能操作自己创建的规则")
    old_enabled = found.get('enabled', True)
    found['enabled'] = req.enabled
    if not save_rules_to_file(rules):
        return ApiResponse(code=500, msg="保存规则失败")
    write_rule_audit(user, "enable" if req.enabled else "disable", req.rule_id, f"{old_enabled} -> {req.enabled}", {"old_enabled": old_enabled, "new_enabled": req.enabled}, client_ip)
    return ApiResponse(code=0, msg=f"规则 {req.rule_id} 已{'启用' if req.enabled else '禁用'}")
