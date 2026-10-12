#!/usr/bin/env python3
"""
models.py - 通用数据结构定义
定义 CommonSchema，所有适配器的输出格式
"""

from typing import List, Dict, Any, Optional


class CommonSchema:
    """标准化日志格式（所有适配器的统一输出）"""
    
    def __init__(self):
        # 基础元数据
        self.alert_id: str = ""              # 告警业务编号
        self.vendor: str = ""                # 设备类型：modsecurity / safeline / aws_waf
        self.timestamp: str = ""             # 时间戳（原始格式）
        self.transaction_id: str = ""        # 事务ID
        
        # 状态标记（预留字段，后续可扩展）
        self.is_blocked: int = 0             # 是否已封堵
        self.is_processed: int = 0           # 是否已处理
        
        # 网络层
        self.src_ip: str = "0.0.0.0"
        self.src_port: int = 0
        self.dest_ip: str = ""
        self.dest_port: int = 0
        
        # 请求层
        self.method: str = ""
        self.uri: str = ""
        self.headers: Dict[str, str] = {}
        self.request_body: str = ""          # 截断至 1KB
        
        # 响应层
        self.response_status: int = 0
        self.response_body_preview: str = "" # 截断至 1KB
        
        # 攻击告警（多条）
        self.attacks: List[Dict[str, Any]] = []
        
        # 主告警（从 attacks 中提取的第一条）
        self.attack_type: str = "UNKNOWN"
        self.severity: str = "INFO"
        self.rule_id: str = ""
        self.payload: str = ""
        
        # 评分
        self.priority_score: float = 0.0
        
        # 原始日志（截断保存）
        self.raw_message: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """将对象转为字典，方便入库"""
        return {
            'alert_id': self.alert_id,
            'vendor': self.vendor,
            'log_time': self.timestamp,
            'transaction_id': self.transaction_id,
            'src_ip': self.src_ip,
            'src_port': self.src_port,
            'dest_ip': self.dest_ip,
            'dest_port': self.dest_port,
            'method': self.method,
            'uri': self.uri,
            'headers': self._json_dumps(self.headers),
            'request_body': self.request_body,
            'response_status': self.response_status,
            'attacks': self._json_dumps(self.attacks),
            'attack_type': self.attack_type,
            'severity': self.severity,
            'rule_id': self.rule_id,
            'payload': self.payload,
            'response_body_preview': self.response_body_preview,
            'priority_score': self.priority_score,
            'is_blocked': self.is_blocked,
            'is_processed': self.is_processed,
            'raw_message': self.raw_message
        }
    
    @staticmethod
    def _json_dumps(obj):
        """安全地转为 JSON 字符串，失败时返回空字符串"""
        if obj is None:
            return ''
        try:
            import json
            return json.dumps(obj, ensure_ascii=False)
        except:
            return ''