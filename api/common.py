#!/usr/bin/env python3
"""
api/common.py - 路由公共定义

- ApiResponse：统一的响应封装（原先 6 个路由各定义一份）
- server_error：统一异常 -> {code:500}，并保持各接口既有 msg 口径
"""
import re
import sqlite3
from typing import Any, Optional
from pydantic import BaseModel, ValidationError


class ApiResponse(BaseModel):
    code: int = 0
    msg: str = "success"
    data: Optional[Any] = None


def server_error(exc: Exception, label: str, db_label: str = "数据库错误") -> ApiResponse:
    """
    把异常统一收敛为 500 响应。

    - 若为 sqlite3.Error 且 db_label 非空 -> "{db_label}: {exc}"（如「数据库错误: ...」）
    - 其它 -> "{label}失败: {exc}"，并打印到服务端日志
    传 db_label=None 可让数据库错误也走 "{label}失败" 口径（保持既有行为）。
    """
    if db_label and isinstance(exc, sqlite3.Error):
        return ApiResponse(code=500, msg=f"{db_label}: {exc}")
    print(f"[ERROR] {label}: {exc}")
    return ApiResponse(code=500, msg=f"{label}失败: {exc}")


def validation_error(exc: ValidationError) -> ApiResponse:
    """把请求参数校验失败收敛为 400 口径（取第一条错误信息）"""
    msg = "参数校验失败"
    try:
        detail = exc.errors()[0].get("msg", "")
        detail = re.sub(r"^Value error,\s*", "", detail)
        if detail:
            msg = f"参数校验失败: {detail}"
    except Exception:
        pass
    return ApiResponse(code=400, msg=msg)
