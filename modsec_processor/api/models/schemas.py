#!/usr/bin/env python3
"""
api/models/schemas.py - API 请求/响应数据模型
"""
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class AlertFilters(BaseModel):
    """告警列表查询过滤条件"""
    time_from: Optional[str] = None
    time_to: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    attack_type: Optional[str] = None
    severity: Optional[str] = None
    rule_id: Optional[str] = None
    vendor: Optional[str] = None
    is_blocked: Optional[int] = None  # 0/1


class AlertListRequest(BaseModel):
    """告警列表请求"""
    action: str = "list"
    page: int = 1
    size: int = 20
    sort: str = "-priority_score"
    ignore_sink: bool = False  # False=监控模式, True=调查模式
    filters: Optional[AlertFilters] = None


class AlertDetailRequest(BaseModel):
    """告警详情请求"""
    action: str = "detail"
    alert_id: str


class AlertStatsRequest(BaseModel):
    """统计概览请求"""
    action: str = "stats"


class ApiResponse(BaseModel):
    """统一返回格式"""
    code: int = 0
    msg: str = "success"
    data: Optional[Any] = None