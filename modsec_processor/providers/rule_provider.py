#!/usr/bin/env python3
"""
rule_provider.py - 沉底规则数据源提供者（支持热更新）
"""
import os
import json
import re
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
import ipaddress

# 导入配置
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import CONFIG_DIR

logger = logging.getLogger(__name__)


class SinkRule:
    """沉底规则实体"""
    
    def __init__(self, data: Dict[str, Any]):
        self.id = data.get('id', '')
        self.field = data.get('field', '')
        self.operator = data.get('operator', '')
        self.value = data.get('value', '')
        self.scope = data.get('scope', 'personal')
        self.creator = data.get('creator', '')
        self.expire_at = data.get('expire_at', '')
        self.reason = data.get('reason', '')
        self.enabled = data.get('enabled', True)
    
    def matches(self, context: Dict[str, str]) -> bool:
        if not self.enabled:
            return False
        if self.expire_at and datetime.now().isoformat() > self.expire_at:
            return False
        field_value = context.get(self.field, '')
        if not field_value:
            return False
        # ---- CIDR 网段匹配 ----
        if self.field == 'src_ip' and '/' in self.value:
            try:
                network = ipaddress.ip_network(self.value, strict=False)
                ip_obj = ipaddress.ip_address(field_value)
                return ip_obj in network
            except ValueError:
                return False
        # ---- 操作符匹配 ----
        if self.operator == 'exact':
            return field_value == self.value
        elif self.operator == 'startswith':
            return field_value.startswith(self.value)
        elif self.operator == 'endswith':
            return field_value.endswith(self.value)
        elif self.operator == 'contains':
            return self.value in field_value
        elif self.operator == 'regex':
            try:
                return bool(re.search(self.value, field_value))
            except re.error:
                return False
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'field': self.field,
            'operator': self.operator,
            'value': self.value,
            'scope': self.scope,
            'creator': self.creator,
            'expire_at': self.expire_at,
            'reason': self.reason,
            'enabled': self.enabled
        }


class RuleProvider:
    """沉底规则数据源提供者（支持热更新）"""

    def match_global_first(self, context: Dict[str, str]) -> Optional[SinkRule]:
        """只匹配全局规则（用于采集引擎）"""
        self._check_reload()
        for rule in self.get_global_rules():
            if rule.matches(context):
                return rule
        return None

    def __init__(self, config_dir: str = None):
        if config_dir is None:
            config_dir = str(CONFIG_DIR)
        self.config_dir = config_dir
        self.rules: List[SinkRule] = []
        self._last_mtime: float = 0
        self._file_path = os.path.join(config_dir, "sink_rules.json")
        self.reload()
    
    def _check_reload(self):
        """检查文件是否变更，如有变更则重载"""
        if not os.path.exists(self._file_path):
            return
        current_mtime = os.path.getmtime(self._file_path)
        if current_mtime != self._last_mtime:
            logger.info(f"检测到规则文件变更，正在热重载...")
            self.reload()
    
    def reload(self):
        """重新加载规则"""
        self.rules = []
        if not os.path.exists(self._file_path):
            logger.info(f"规则文件不存在，跳过加载: {self._file_path}")
            self._last_mtime = 0
            return
        
        try:
            with open(self._file_path, 'r') as f:
                data = json.load(f)
            for rule_data in data.get('rules', []):
                self.rules.append(SinkRule(rule_data))
            self._last_mtime = os.path.getmtime(self._file_path)
            logger.info(f"热重载成功，加载了 {len(self.rules)} 条沉底规则")
        except Exception as e:
            logger.error(f"加载规则文件失败: {e}")
    
    def get_personal_rules(self, creator: str) -> List[SinkRule]:
        self._check_reload()
        return [r for r in self.rules if r.scope == 'personal' and r.creator == creator]
    
    def get_global_rules(self) -> List[SinkRule]:
        self._check_reload()
        return [r for r in self.rules if r.scope == 'global']
    
    def get_rules(self) -> List[SinkRule]:
        self._check_reload()
        return self.rules
    
    def match_first(self, context: Dict[str, str], creator: str = None) -> Optional[SinkRule]:
        self._check_reload()
        for rule in self.get_global_rules():
            if rule.matches(context):
                return rule
        if creator:
            for rule in self.get_personal_rules(creator):
                if rule.matches(context):
                    return rule
        return None