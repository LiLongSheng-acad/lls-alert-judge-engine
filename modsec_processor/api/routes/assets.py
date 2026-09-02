#!/usr/bin/env python3
"""
api/routes/assets.py - 资产管理 API（权限控制 + 审计）
"""
import sys
import os
import json
import uuid
import sqlite3
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
from fastapi import APIRouter, Cookie, Request, HTTPException
from pydantic import BaseModel, Field, validator
from lib.validator import InputValidator

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.settings import CONFIG_DIR, COOKIE_USER_KEY, DB_PATH

router = APIRouter()


# ============================================================
# 数据模型
# ============================================================

class AssetListRequest(BaseModel):
    action: str = "list"
    page: int = Field(default=1, ge=1)
    size: int = Field(default=20, ge=1, le=200)
    enabled_only: bool = Field(default=False)


class AssetDetailRequest(BaseModel):
    action: str = "detail"
    asset_id: str = Field(..., description="资产 ID")


class AssetCreateRequest(BaseModel):
    action: str = "create"
    identifier: str = Field(..., description="资产标识")
    name: str = Field(..., description="资产名称")
    base_weight: float = Field(..., ge=0.1, le=100)
    temp_weight: Optional[float] = Field(None, ge=0.1, le=100)
    temp_expire_at: Optional[str] = None
    owner: Optional[str] = None
    remark: Optional[str] = None
    enabled: bool = Field(default=True)


class AssetUpdateRequest(BaseModel):
    action: str = "update"
    asset_id: str = Field(..., description="资产 ID")
    identifier: Optional[str] = None
    name: Optional[str] = None
    base_weight: Optional[float] = Field(None, ge=0.1, le=100)
    temp_weight: Optional[float] = Field(None, ge=0.1, le=100)
    temp_expire_at: Optional[str] = None
    owner: Optional[str] = None
    remark: Optional[str] = None
    enabled: Optional[bool] = None


class AssetDeleteRequest(BaseModel):
    action: str = "delete"
    asset_id: str = Field(..., description="资产 ID")


class ApiResponse(BaseModel):
    code: int = 0
    msg: str = "success"
    data: Optional[Any] = None


# ============================================================
# 辅助函数
# ============================================================

def get_assets_file_path() -> Path:
    return CONFIG_DIR / "assets.json"


def load_assets_from_file() -> List[Dict]:
    file_path = get_assets_file_path()
    if not file_path.exists():
        default_assets = {
            "assets": [
                {
                    "id": "asset_default_001",
                    "identifier": "127.0.0.1",
                    "name": "本机回环（测试环境）",
                    "base_weight": 0.5,
                    "temp_weight": None,
                    "temp_expire_at": None,
                    "owner": "system",
                    "remark": "默认测试资产",
                    "enabled": True,
                    "created_at": datetime.now().isoformat(),
                    "updated_at": datetime.now().isoformat()
                }
            ]
        }
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w') as f:
            json.dump(default_assets, f, indent=2, ensure_ascii=False)
        return default_assets.get('assets', [])

    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            return data.get('assets', [])
    except Exception:
        return []


def save_assets_to_file(assets: List[Dict]) -> bool:
    """原子写入：先写 .tmp 再 mv 覆盖"""
    file_path = get_assets_file_path()
    tmp_path = file_path.with_suffix('.tmp')
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(tmp_path, 'w') as f:
            json.dump({"assets": assets}, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, file_path)
        return True
    except Exception as e:
        print(f"[ERROR] 保存资产文件失败: {e}")
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except:
                pass
        return False


def write_asset_audit(operator: str, action: str, asset_id: str, detail: str = "", asset_data: dict = None, client_ip: str = None):
    """写入资产审计日志（JSON + SQLite 双写）"""
    # 1. JSON 文件
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "operator": operator,
        "action": action,
        "asset_id": asset_id,
        "detail": detail,
        "asset_data": asset_data,
        "client_ip": client_ip or "unknown"
    }
    log_path = CONFIG_DIR.parent / "logs" / "asset_audit.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, 'a') as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

    # 2. SQLite 数据库
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=5)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_asset_log (operator, action, asset_id, asset_data, detail, client_ip)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            operator,
            action,
            asset_id,
            json.dumps(asset_data) if asset_data else None,
            detail,
            client_ip or "unknown"
        ))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"[ERROR] 资产审计日志写入数据库失败: {e}")


# ============================================================
# API 路由
# ============================================================

@router.post("/assets")
async def handle_assets(
    request: Request,
    req_data: Dict[str, Any],
    user: str = Cookie(default="system", alias=COOKIE_USER_KEY)
) -> ApiResponse:
    """
    资产管理 API 统一入口
    权限：普通用户只能查看，admin 可增删改
    """
    action = req_data.get("action", "list")
    client_ip = request.client.host if request.client else "unknown"

    if action in ["create", "update", "delete"] and user != "admin":
        return ApiResponse(code=403, msg="只有管理员可以管理资产")

    # ---- 统一输入校验 ----
    validated = InputValidator.validate_and_clean(
        req_data,
        rules={
            "identifier": "str",
            "name": "str",
            "base_weight": "float",
            "temp_weight": "float",
            "temp_expire_at": "str",
            "owner": "str",
            "remark": "str",
            "enabled": "bool",
            "asset_id": "str",
        }
    )

    if action == "list":
        req = AssetListRequest(**validated)
        return await list_assets(req)
    elif action == "detail":
        req = AssetDetailRequest(**validated)
        return await detail_asset(req)
    elif action == "create":
        req = AssetCreateRequest(**validated)
        return await create_asset(req, user, client_ip)
    elif action == "update":
        req = AssetUpdateRequest(**validated)
        return await update_asset(req, user, client_ip)
    elif action == "delete":
        req = AssetDeleteRequest(**validated)
        return await delete_asset(req, user, client_ip)
    else:
        raise HTTPException(status_code=400, detail=f"未知的 action: {action}")

async def list_assets(req: AssetListRequest) -> ApiResponse:
    """查询资产列表（所有人可查看）"""
    assets = load_assets_from_file()
    if req.enabled_only:
        assets = [a for a in assets if a.get('enabled', True)]

    total = len(assets)
    start = (req.page - 1) * req.size
    end = start + req.size
    items = assets[start:end]

    for item in items:
        current_weight = item.get('base_weight', 1.0)
        temp_weight = item.get('temp_weight')
        temp_expire_at = item.get('temp_expire_at')
        if temp_weight is not None and temp_expire_at:
            try:
                if datetime.fromisoformat(temp_expire_at) > datetime.now():
                    current_weight = temp_weight
            except:
                pass
        item['_current_weight'] = round(current_weight, 2)
        item['_is_temp_active'] = current_weight != item.get('base_weight', 1.0)

    return ApiResponse(
        code=0,
        msg="success",
        data={
            "total": total,
            "page": req.page,
            "size": req.size,
            "items": items
        }
    )


async def detail_asset(req: AssetDetailRequest) -> ApiResponse:
    """获取单条资产详情（用于编辑）"""
    assets = load_assets_from_file()
    for asset in assets:
        if asset.get('id') == req.asset_id:
            return ApiResponse(code=0, msg="success", data=asset)
    return ApiResponse(code=404, msg=f"资产 {req.asset_id} 不存在")


async def create_asset(req: AssetCreateRequest, user: str, client_ip: str) -> ApiResponse:
    """创建资产（仅 admin）"""
    asset_id = f"asset_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:6]}"

    new_asset = {
        "id": asset_id,
        "identifier": req.identifier,
        "name": req.name,
        "base_weight": req.base_weight,
        "temp_weight": req.temp_weight,
        "temp_expire_at": req.temp_expire_at,
        "owner": req.owner,
        "remark": req.remark,
        "enabled": req.enabled,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }

    assets = load_assets_from_file()
    assets.append(new_asset)

    if not save_assets_to_file(assets):
        return ApiResponse(code=500, msg="保存资产失败")

    write_asset_audit(
        operator=user,
        action="create",
        asset_id=asset_id,
        detail=f"identifier={req.identifier}, name={req.name}, weight={req.base_weight}",
        asset_data=new_asset,
        client_ip=client_ip
    )

    return ApiResponse(code=0, msg="资产创建成功", data={"asset_id": asset_id})


async def update_asset(req: AssetUpdateRequest, user: str, client_ip: str) -> ApiResponse:
    """更新资产（仅 admin）"""
    assets = load_assets_from_file()

    found = False
    old_data = None
    for asset in assets:
        if asset.get('id') == req.asset_id:
            found = True
            old_data = dict(asset)  # 复制旧数据
            if req.identifier is not None:
                asset['identifier'] = req.identifier
            if req.name is not None:
                asset['name'] = req.name
            if req.base_weight is not None:
                asset['base_weight'] = req.base_weight
            if req.temp_weight is not None:
                asset['temp_weight'] = req.temp_weight
            if req.temp_expire_at is not None:
                asset['temp_expire_at'] = req.temp_expire_at
            if req.owner is not None:
                asset['owner'] = req.owner
            if req.remark is not None:
                asset['remark'] = req.remark
            if req.enabled is not None:
                asset['enabled'] = req.enabled
            asset['updated_at'] = datetime.now().isoformat()
            break

    if not found:
        return ApiResponse(code=404, msg=f"资产 {req.asset_id} 不存在")

    if not save_assets_to_file(assets):
        return ApiResponse(code=500, msg="保存资产失败")

    write_asset_audit(
        operator=user,
        action="update",
        asset_id=req.asset_id,
        detail=f"old: {old_data}",
        asset_data=assets,
        client_ip=client_ip
    )

    return ApiResponse(code=0, msg=f"资产 {req.asset_id} 已更新")


async def delete_asset(req: AssetDeleteRequest, user: str, client_ip: str) -> ApiResponse:
    """删除资产（仅 admin）"""
    assets = load_assets_from_file()

    found = False
    new_assets = []
    deleted_asset = None
    for asset in assets:
        if asset.get('id') == req.asset_id:
            found = True
            deleted_asset = asset
            continue
        new_assets.append(asset)

    if not found:
        return ApiResponse(code=404, msg=f"资产 {req.asset_id} 不存在")

    if not save_assets_to_file(new_assets):
        return ApiResponse(code=500, msg="保存资产失败")

    write_asset_audit(
        operator=user,
        action="delete",
        asset_id=req.asset_id,
        detail=f"identifier={deleted_asset.get('identifier')}, name={deleted_asset.get('name')}",
        asset_data=deleted_asset,
        client_ip=client_ip
    )

    return ApiResponse(code=0, msg=f"资产 {req.asset_id} 已删除")
