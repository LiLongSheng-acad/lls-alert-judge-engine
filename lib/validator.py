#!/usr/bin/env python3
"""
lib/validator.py - 统一输入校验与类型归一化模块（不做破坏性清洗）
"""

import re
import ipaddress
from pathlib import Path
from typing import Any, Dict


class InputValidator:
    """统一输入校验器（只做类型归一化，不做破坏性清洗）

    安全边界说明：
    - SQL 注入：所有查询均使用参数化占位符（?），不依赖输入清洗；
    - XSS：在输出侧转义（前端 escapeHtml / 响应编码），不依赖输入清洗。
    因此这里**不再删除**输入中的子串——否则会破坏「规则值本身就是攻击载荷」
    这类合法用法：例如 value 为 `' OR 1=1--` 的沉底规则会被削成 `' OR 1=1`，永不匹配。
    """

    @classmethod
    def validate_ip(cls, ip: str) -> str:
        if not ip:
            return ''
        cleaned = re.sub(r'[^0-9a-fA-F:.]', '', ip)
        try:
            ipaddress.ip_address(cleaned)
            return cleaned
        except ValueError:
            return ''

    @classmethod
    def validate_path(cls, base_dir: Path, user_path: str) -> Path:
        if not user_path:
            raise ValueError("路径不能为空")
        full_path = (base_dir / user_path).resolve()
        base_resolved = base_dir.resolve()
        if not str(full_path).startswith(str(base_resolved)):
            raise ValueError(f"路径越界: {user_path}")
        return full_path

    @classmethod
    def validate_and_clean(cls, data: Dict[str, Any], rules: Dict[str, str]) -> Dict[str, Any]:
        if not data:
            return {}
        cleaned = {}
        for key, value in data.items():
            if key in rules:
                field_type = rules[key]
                if value is None:
                    cleaned[key] = None
                elif field_type == 'str':
                    cleaned[key] = str(value)
                elif field_type == 'ip':
                    cleaned[key] = cls.validate_ip(str(value))
                elif field_type == 'int':
                    try:
                        cleaned[key] = int(value)
                    except (ValueError, TypeError):
                        cleaned[key] = 0
                elif field_type == 'float':
                    try:
                        cleaned[key] = float(value)
                    except (ValueError, TypeError):
                        cleaned[key] = 0.0
                elif field_type == 'bool':
                    if isinstance(value, bool):
                        cleaned[key] = value
                    elif isinstance(value, str):
                        cleaned[key] = value.lower() in ('true', '1', 'yes')
                    else:
                        cleaned[key] = bool(value)
                else:
                    cleaned[key] = value
            else:
                cleaned[key] = value
        return cleaned
