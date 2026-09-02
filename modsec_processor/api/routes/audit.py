#!/usr/bin/env python3
"""
api/routes/audit.py - 审计日志查询 API
"""
import sys
import os
import json
import sqlite3
from typing import Dict, Any, Optional
from fastapi import APIRouter, Cookie, HTTPException
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config.settings import DB_PATH, COOKIE_USER_KEY

router = APIRouter()


# ============================================================
# 请求模型
# ============================================================

class AuditListRequest(BaseModel):
    action: str = "list"
    page: int = Field(default=1, ge=1)
    size: int = Field(default=20, ge=1, le=100)
    filter_action: Optional[str] = Field(None, description="create / delete / enable / disable")
    filter_operator: Optional[str] = Field(None, description="按操作人过滤")


class ApiResponse(BaseModel):
    code: int = 0
    msg: str = "success"
    data: Optional[Any] = None


# ============================================================
# 辅助函数
# ============================================================

def get_db_conn():
    return sqlite3.connect(str(DB_PATH))


# ============================================================
# API 路由
# ============================================================

@router.post("/audit/rules")
async def list_audit(
    request: Dict[str, Any],
    user: str = Cookie(default="system", alias=COOKIE_USER_KEY)
) -> ApiResponse:
    """
    查询规则审计日志
    权限：只返回当前用户的操作记录，admin 可查看全部
    """
    req = AuditListRequest(**request)
    
    try:
        conn = get_db_conn()
        cursor = conn.cursor()

        where_clauses = []
        params = []

        # 权限隔离
        if user != 'admin':
            where_clauses.append("operator = ?")
            params.append(user)

        # 操作类型过滤
        if req.filter_action:
            where_clauses.append("action = ?")
            params.append(req.filter_action)

        # 按操作人过滤（仅 admin 可用）
        if req.filter_operator and user == 'admin':
            where_clauses.append("operator = ?")
            params.append(req.filter_operator)

        where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        # 查询总数
        count_sql = f"SELECT COUNT(*) FROM audit_rule_log{where_sql}"
        cursor.execute(count_sql, params)
        total = cursor.fetchone()[0]

        # 分页查询
        offset = (req.page - 1) * req.size
        sql = f"""
            SELECT id, operator, action, rule_id, rule_data, client_ip, created_at
            FROM audit_rule_log{where_sql}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """
        cursor.execute(sql, params + [req.size, offset])
        rows = cursor.fetchall()
        conn.close()

        items = []
        for row in rows:
            items.append({
                "id": row[0],
                "operator": row[1] or "",
                "action": row[2] or "",
                "rule_id": row[3] or "",
                "rule_data": json.loads(row[4]) if row[4] else None,
                "client_ip": row[5] or "",
                "created_at": row[6] or "",
            })

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

    except sqlite3.Error as e:
        return ApiResponse(code=500, msg=f"数据库错误: {str(e)}")
    except Exception as e:
        return ApiResponse(code=500, msg=f"查询失败: {str(e)}")

# ============================================================
# 表初始化（确保表存在）
# ============================================================

def ensure_audit_table():
    """确保 audit_rule_log 表存在"""
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='audit_rule_log'
        """)
        if not cursor.fetchone():
            cursor.execute("""
                CREATE TABLE audit_rule_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    operator TEXT NOT NULL,
                    action TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    rule_data TEXT,
                    source TEXT DEFAULT 'manual',
                    client_ip TEXT,
                    created_at TEXT DEFAULT (datetime('now', 'localtime'))
                )
            """)
            cursor.execute("CREATE INDEX idx_audit_operator ON audit_rule_log(operator)")
            cursor.execute("CREATE INDEX idx_audit_action ON audit_rule_log(action)")
            cursor.execute("CREATE INDEX idx_audit_created_at ON audit_rule_log(created_at)")
            conn.commit()
            print("[DB] 已创建审计日志表 audit_rule_log")
        conn.close()
    except Exception as e:
        print(f"[WARN] 确保审计表存在时出错: {e}")

# 在模块加载时执行
ensure_audit_table()

# ============================================================
# 资产审计查询
# ============================================================

@router.post("/audit/assets")
async def list_asset_audit(
    request: Dict[str, Any],
    user: str = Cookie(default="system", alias=COOKIE_USER_KEY)
) -> ApiResponse:
    """
    查询资产审计日志
    权限：只返回当前用户的操作记录，admin 可查看全部
    """
    req = AuditListRequest(**request)

    try:
        conn = get_db_conn()
        cursor = conn.cursor()

        where_clauses = []
        params = []

        if user != 'admin':
            where_clauses.append("operator = ?")
            params.append(user)

        if req.filter_action:
            where_clauses.append("action = ?")
            params.append(req.filter_action)

        if req.filter_operator and user == 'admin':
            where_clauses.append("operator = ?")
            params.append(req.filter_operator)

        where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        count_sql = f"SELECT COUNT(*) FROM audit_asset_log{where_sql}"
        cursor.execute(count_sql, params)
        total = cursor.fetchone()[0]

        offset = (req.page - 1) * req.size
        sql = f"""
            SELECT id, operator, action, asset_id, asset_data, detail, client_ip, created_at
            FROM audit_asset_log{where_sql}
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """
        cursor.execute(sql, params + [req.size, offset])
        rows = cursor.fetchall()
        conn.close()

        items = []
        for row in rows:
            items.append({
                "id": row[0],
                "operator": row[1] or "",
                "action": row[2] or "",
                "asset_id": row[3] or "",
                "asset_data": json.loads(row[4]) if row[4] else None,
                "detail": row[5] or "",
                "client_ip": row[6] or "",
                "created_at": row[7] or "",
                "type": "asset"   # 标记类型，便于前端混合展示
            })

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

    except sqlite3.Error as e:
        return ApiResponse(code=500, msg=f"数据库错误: {str(e)}")
    except Exception as e:
        return ApiResponse(code=500, msg=f"查询失败: {str(e)}")
