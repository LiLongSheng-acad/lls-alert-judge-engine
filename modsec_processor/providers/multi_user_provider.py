#!/usr/bin/env python3
"""
multi_user_provider.py - 多人独立临时黑名单提供者

特点：
1. 每个用户独立 JSON 文件（config/temp_blacklist/{operator}.json）
2. 自动过期清理（默认24小时）
3. 完整审计日志（操作人、时间、IP、原因）
4. 线程安全
"""
import os
import json
import time
import logging
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from threading import Lock

# 导入配置
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import CONFIG_DIR, LOG_DIR

logger = logging.getLogger(__name__)


class MultiUserTempBlacklist:
    """多人独立临时黑名单"""

    def __init__(self, config_dir: str = None):
        """
        初始化多人临时黑名单

        Args:
            config_dir: 配置目录路径，默认使用 CONFIG_DIR
        """
        if config_dir is None:
            config_dir = str(CONFIG_DIR)

        self.blacklist_dir = os.path.join(config_dir, "temp_blacklist")
        self.audit_log = LOG_DIR / "temp_blacklist_audit.log"
        self._lock = Lock()
        self._cache: Dict[str, Dict] = {}  # {operator: {ip: record}}
        self._last_reload: float = 0
        self._reload_interval = 10  # 秒

        # 确保目录存在
        os.makedirs(self.blacklist_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.audit_log), exist_ok=True)

        self._load_all()

    def _load_all(self):
        """加载所有用户的临时黑名单"""
        with self._lock:
            self._cache = {}
            for filename in os.listdir(self.blacklist_dir):
                if not filename.endswith('.json'):
                    continue
                operator = filename[:-5]
                filepath = os.path.join(self.blacklist_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                        if isinstance(data, dict):
                            self._cache[operator] = data
                except Exception as e:
                    logger.error(f"加载用户 {operator} 的临时黑名单失败: {e}")
            self._last_reload = time.time()
            total = sum(len(v) for v in self._cache.values())
            logger.info(f"加载了 {len(self._cache)} 个用户的临时黑名单，共 {total} 条记录")

    def _reload_if_needed(self):
        """按需重载（检测文件变更）"""
        if time.time() - self._last_reload > self._reload_interval:
            self._load_all()

    def _save_user(self, operator: str):
        """保存单个用户的临时黑名单到文件"""
        filepath = os.path.join(self.blacklist_dir, f"{operator}.json")
        with open(filepath, 'w') as f:
            json.dump(self._cache.get(operator, {}), f, indent=2, ensure_ascii=False)

    def _write_audit(self, operator: str, action: str, ip: str, reason: str = "", expire_at: str = ""):
        """写入审计日志"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "operator": operator,
            "action": action,
            "ip": ip,
            "reason": reason,
            "expire_at": expire_at
        }
        with open(self.audit_log, 'a') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def contains(self, ip: str, operator: str) -> bool:
        """检查某个用户的临时黑名单是否包含该 IP"""
        self._reload_if_needed()
        with self._lock:
            user_data = self._cache.get(operator, {})
            if ip not in user_data:
                return False
            record = user_data[ip]
            expire_at = record.get('expire_at')
            if expire_at and datetime.now().isoformat() > expire_at:
                del user_data[ip]
                self._save_user(operator)
                return False
            return True

    def add(self, ip: str, reason: str, operator: str, expire_hours: int = 24) -> bool:
        """添加临时黑名单（默认24小时过期）"""
        self._reload_if_needed()
        with self._lock:
            if operator not in self._cache:
                self._cache[operator] = {}
            expire_at = (datetime.now() + timedelta(hours=expire_hours)).isoformat()
            self._cache[operator][ip] = {
                "reason": reason,
                "created_at": datetime.now().isoformat(),
                "expire_at": expire_at
            }
            self._save_user(operator)
            self._write_audit(operator, "add", ip, reason, expire_at)
            return True

    def remove(self, ip: str, operator: str) -> bool:
        """移除临时黑名单"""
        self._reload_if_needed()
        with self._lock:
            user_data = self._cache.get(operator, {})
            if ip not in user_data:
                return False
            del user_data[ip]
            self._save_user(operator)
            self._write_audit(operator, "remove", ip, "手动解除", "")
            return True

    def get_user_list(self, operator: str) -> List[Dict]:
        """获取某个用户的临时黑名单列表（用于展示）"""
        self._reload_if_needed()
        with self._lock:
            user_data = self._cache.get(operator, {})
            result = []
            for ip, record in user_data.items():
                result.append({
                    "ip": ip,
                    "reason": record.get("reason", ""),
                    "created_at": record.get("created_at", ""),
                    "expire_at": record.get("expire_at", ""),
                    "is_expired": datetime.now().isoformat() > record.get("expire_at", "")
                })
            return sorted(result, key=lambda x: x["expire_at"])

    def cleanup_expired(self):
        """清理所有用户的过期条目（可定时调用）"""
        with self._lock:
            expired_count = 0
            for operator, user_data in self._cache.items():
                expired_ips = []
                for ip, record in user_data.items():
                    expire_at = record.get('expire_at')
                    if expire_at and datetime.now().isoformat() > expire_at:
                        expired_ips.append(ip)
                for ip in expired_ips:
                    del user_data[ip]
                    expired_count += 1
                if expired_ips:
                    self._save_user(operator)
            if expired_count > 0:
                logger.info(f"清理了 {expired_count} 条过期临时黑名单")
                self._last_reload = time.time()
