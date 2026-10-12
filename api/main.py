#!/usr/bin/env python3
"""
api/main.py - FastAPI 应用入口
version 0.3.0
"""
import sys
import os
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from api.routes.alerts import router as alerts_router
from api.routes.rules import router as rules_router
from api.routes.assets import router as assets_router
from api.routes.actions import router as actions_router
from api.routes.audit import router as audit_router
from api.routes.promotions import router as promotions_router

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import BASIC_AUTH_USERNAME, BASIC_AUTH_PASSWORD, STATIC_DIR
from lib.preflight import assert_preflight
from api.common import validation_error
from pydantic import ValidationError

# 启动自检：目录/权限/关键配置有问题时，直接阻断启动并给出清晰报错
assert_preflight("api")

app = FastAPI(
    title="告警研判引擎 API",
    description="统一 POST 接口，支持告警查询、详情、统计",
    version="0.3.0"
)

# ============================================================
# 全局异常处理（不泄露堆栈）
# ============================================================
@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    # 请求参数校验失败 -> 400（参数错误），而非 500
    return JSONResponse(status_code=400, content=validation_error(exc).model_dump())


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"[ERROR] {exc}")
    return JSONResponse(
        status_code=500,
        content={"code": 500, "msg": "服务器内部错误，请联系管理员"}
    )

# ============================================================
# 静态文件挂载（由 settings 推导，兼容 Windows 本地与 /opt 部署）
# ============================================================
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ============================================================
# 根路径重定向到前端
# ============================================================
@app.get("/")
async def root():
    return RedirectResponse(url="/static/index.html")

# ============================================================
# CORS 配置
# ============================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ============================================================
# HTTP Basic Auth
# ============================================================
security = HTTPBasic()

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = BASIC_AUTH_USERNAME
    correct_password = BASIC_AUTH_PASSWORD
    if credentials.username != correct_username or credentials.password != correct_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="认证失败，请检查用户名和密码",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# ============================================================
# 注册路由
# ============================================================
app.include_router(alerts_router, prefix="/api", dependencies=[Depends(verify_credentials)])
app.include_router(rules_router, prefix="/api", dependencies=[Depends(verify_credentials)])
app.include_router(assets_router, prefix="/api", dependencies=[Depends(verify_credentials)])
app.include_router(actions_router, prefix="/api", dependencies=[Depends(verify_credentials)])
app.include_router(audit_router, prefix="/api", dependencies=[Depends(verify_credentials)])
app.include_router(promotions_router, prefix="/api", dependencies=[Depends(verify_credentials)])

# ============================================================
# 公共接口（无需鉴权）
# ============================================================
@app.get("/api/health")
async def health():
    return {"status": "healthy"}