#!/usr/bin/env python3
"""
id_generator.py - 告警编号生成器

职责：
1. 生成全局唯一的告警业务编号
2. 支持可配置的序号位数和模板
3. 支持标记码（A/B/R/T/W 等）
4. 从数据库恢复计数器，避免重启后重复
5. 线程安全

编号格式：{标记码}{YYYYMMDD}{序号}
示例：A20260829000001
"""
import sys
import os
import re
import threading
import sqlite3
from datetime import datetime
from typing import Dict, Optional

# 确保项目根目录在 sys.path 中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import ID_GENERATOR as ID_CONFIG, DB_PATH


class AlertIDGenerator:
    """告警编号生成器（线程安全）"""

    def __init__(self, config: Dict = None, db_path: str = None):
        """
        初始化编号生成器

        Args:
            config: 配置字典，默认使用 ID_CONFIG
            db_path: 数据库路径，默认使用 DB_PATH
        """
        if config is None:
            config = ID_CONFIG
        if db_path is None:
            db_path = str(DB_PATH)

        self._lock = threading.Lock()
        self._current_date = ""
        self._counter = 0

        self.seq_digits = config.get("seq_digits", 6)
        self.template = config.get("template", "{MARKER}{DATE}{SEQ}")
        self.default_marker = config.get("default_marker", "A")
        self.status_markers = config.get("status_markers", {})
        self.db_path = db_path

        self.max_seq = 10 ** self.seq_digits - 1
        self._load_counter_from_db()

        print(f"[IDGen] 初始化完成，序号位数: {self.seq_digits}，最大日容量: {self.max_seq:,}")

    def _load_counter_from_db(self):
        """从数据库加载当天已使用的最大序号"""
        today = datetime.now().strftime("%Y%m%d")

        try:
            conn = sqlite3.connect(self.db_path, timeout=5)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT MAX(CAST(substr(alert_id, 10) AS INTEGER))
                FROM modsec_alerts
                WHERE substr(alert_id, 2, 8) = ?
            """, (today,))
            row = cursor.fetchone()

            if row and row[0]:
                self._counter = row[0]
                self._current_date = today
                print(f"[IDGen] 从数据库加载计数器: 日期={today}, 当前序号={self._counter}")
            else:
                self._counter = 0
                self._current_date = today

            conn.close()
        except sqlite3.Error as e:
            print(f"[IDGen] 加载计数器失败: {e}, 从 0 开始")
            self._counter = 0
            self._current_date = ""

    def generate(self, schema, marker: str = None) -> str:
        """
        生成告警编号

        Args:
            schema: CommonSchema 对象
            marker: 标记码（如 A/B/R/T/W），默认从 schema 自动推断

        Returns:
            str: 告警编号，如 A20260829000001
        """
        if marker is None:
            marker = self._get_marker(schema)

        now = datetime.now()
        date_str = now.strftime("%Y%m%d")

        with self._lock:
            # 日期变化时重置计数器
            if self._current_date != date_str:
                self._current_date = date_str
                self._counter = 0

            # 检查是否超出容量
            if self._counter >= self.max_seq:
                raise RuntimeError(
                    f"今日告警量已达上限 ({self.max_seq:,})，"
                    f"请增加 seq_digits 配置或联系管理员"
                )

            self._counter += 1
            seq_str = str(self._counter).zfill(self.seq_digits)

        # 替换占位符
        placeholders = {
            "{MARKER}": marker,
            "{DATE}": date_str,
            "{SEQ}": seq_str,
            "{YEAR}": now.strftime("%Y"),
            "{MONTH}": now.strftime("%m"),
            "{DAY}": now.strftime("%d"),
            "{HOUR}": now.strftime("%H"),
            "{MINUTE}": now.strftime("%M"),
            "{SECOND}": now.strftime("%S"),
        }

        # 如果有攻击类型和严重等级，也加入
        if hasattr(schema, 'attack_type') and schema.attack_type:
            placeholders["{TYPE}"] = schema.attack_type[:4].upper()
        else:
            placeholders["{TYPE}"] = "UNKN"

        if hasattr(schema, 'severity') and schema.severity:
            placeholders["{SEVERITY}"] = schema.severity[:4].upper()
        else:
            placeholders["{SEVERITY}"] = "INFO"

        result = self.template
        for key, value in placeholders.items():
            result = result.replace(key, value)

        return result

    def _get_marker(self, schema) -> str:
        """根据 schema 状态获取标记码"""
        # 已封堵 → B
        if hasattr(schema, 'is_blocked') and schema.is_blocked:
            return self.status_markers.get("blocked", "B")

        # 已处理 → P
        if hasattr(schema, 'is_processed') and schema.is_processed:
            return self.status_markers.get("processed", "P")

        # 默认 → A
        return self.default_marker

    def parse(self, alert_id: str) -> Dict:
        """
        解析告警编号，提取信息

        Args:
            alert_id: 告警编号

        Returns:
            dict: 包含 marker, date, sequence, seq_digits 等字段
        """
        if len(alert_id) < 8:
            return {"valid": False, "error": "编号长度不足"}

        marker = alert_id[0]
        match = re.search(r'\d{8}', alert_id)
        if not match:
            return {"valid": False, "error": "未找到有效日期"}

        date_str = match.group()
        parts = alert_id.split(date_str)
        if len(parts) != 2:
            return {"valid": False, "error": "编号格式异常"}

        seq_str = parts[1]
        try:
            seq = int(seq_str) if seq_str else 0
        except ValueError:
            return {"valid": False, "error": "序号无效"}

        return {
            "valid": True,
            "marker": marker,
            "date": date_str,
            "sequence": seq,
            "seq_digits": len(seq_str),
        }


# ============================================================
# 全局单例管理
# ============================================================

_generator: Optional[AlertIDGenerator] = None


def init_id_generator(config: Dict = None, db_path: str = None):
    """初始化全局编号生成器"""
    global _generator
    if config is None:
        config = ID_CONFIG
    if db_path is None:
        db_path = str(DB_PATH)
    _generator = AlertIDGenerator(config, db_path)


def get_id_generator() -> AlertIDGenerator:
    """获取全局编号生成器实例"""
    if _generator is None:
        init_id_generator()
    return _generator
