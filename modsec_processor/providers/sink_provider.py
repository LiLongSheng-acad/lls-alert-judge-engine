#!/usr/bin/env python3
"""
sink_provider.py - 黑白名单数据源提供者（抽象接口 + 文件实现）

提供：
1. SinkProvider: 抽象基类
2. FileSinkProvider: 基于 TXT/JSON 文件的黑白名单实现
"""
import os
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any
from datetime import datetime, timedelta

# 导入配置
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import LOG_DIR

logger = logging.getLogger(__name__)


class SinkProvider(ABC):
    """黑白名单数据源抽象接口"""
    
    @abstractmethod
    def contains(self, ip: str, operator: str = None) -> bool:
        pass
    
    @abstractmethod
    def add(self, ip: str, reason: str, operator: str, expire_at: str = None) -> bool:
        pass
    
    @abstractmethod
    def remove(self, ip: str, operator: str = None) -> bool:
        pass
    
    @abstractmethod
    def reload(self) -> None:
        pass


class FileSinkProvider(SinkProvider):
    """基于文件的黑白名单提供者（单文件版本，用于永久黑白名单）"""
    
    def __init__(self, file_path: str, is_temp: bool = False):
        self.file_path = file_path
        self.is_temp = is_temp
        self._data: Dict[str, Any] = {}
        self._last_mtime: float = 0
        self.reload()
    
    def contains(self, ip: str, operator: str = None) -> bool:
        self._check_reload()
        if self.is_temp:
            if ip not in self._data:
                return False
            record = self._data[ip]
            expire_at = record.get('expire_at')
            if expire_at and datetime.now().isoformat() > expire_at:
                del self._data[ip]
                self._save()
                return False
            if operator and record.get('operator') != operator:
                return False
            return True
        else:
            return ip in self._data
    
    def add(self, ip: str, reason: str, operator: str, expire_at: str = None) -> bool:
        self._check_reload()
        if self.is_temp:
            if not expire_at:
                expire_at = (datetime.now() + timedelta(hours=24)).isoformat()
            self._data[ip] = {
                'ip': ip,
                'reason': reason,
                'operator': operator,
                'expire_at': expire_at,
                'created_at': datetime.now().isoformat()
            }
            self._save()
            self._log_audit('add', ip, reason, operator, expire_at)
            return True
        else:
            if ip in self._data:
                return False
            self._data[ip] = True
            self._save()
            return True
    
    def remove(self, ip: str, operator: str = None) -> bool:
        self._check_reload()
        if ip not in self._data:
            return False
        if self.is_temp:
            record = self._data[ip]
            if operator and record.get('operator') != operator:
                logger.warning(f"操作人 {operator} 无权删除 {ip} 的临时黑名单（创建者: {record.get('operator')}）")
                return False
            del self._data[ip]
            self._save()
            self._log_audit('remove', ip, '手动解除', operator, '')
            return True
        else:
            del self._data[ip]
            self._save()
            return True
    
    def reload(self) -> None:
        if self.is_temp:
            self._load_json()
        else:
            self._load_txt()
        self._last_mtime = os.path.getmtime(self.file_path) if os.path.exists(self.file_path) else 0
    
    def _check_reload(self):
        if not os.path.exists(self.file_path):
            return
        current_mtime = os.path.getmtime(self.file_path)
        if current_mtime != self._last_mtime:
            self.reload()
    
    def _load_txt(self):
        self._data = {}
        if not os.path.exists(self.file_path):
            return
        with open(self.file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                self._data[line] = True
    
    def _load_json(self):
        self._data = {}
        if not os.path.exists(self.file_path):
            return
        with open(self.file_path, 'r') as f:
            try:
                data = json.load(f)
                if isinstance(data, dict):
                    self._data = data
            except json.JSONDecodeError:
                logger.warning(f"JSON解析失败: {self.file_path}")
    
    def _save(self):
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
        if self.is_temp:
            with open(self.file_path, 'w') as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
        else:
            with open(self.file_path, 'w') as f:
                for ip in sorted(self._data.keys()):
                    f.write(f"{ip}\n")
    
    def _log_audit(self, action: str, ip: str, reason: str, operator: str, expire_at: str):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'ip': ip,
            'reason': reason,
            'operator': operator,
            'expire_at': expire_at
        }
        # 使用配置的日志目录
        log_path = LOG_DIR / "temp_blacklist_audit.log"
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, 'a') as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
