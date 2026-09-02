#!/usr/bin/env python3
"""
lib/validator.py - 统一输入校验与清洗模块
"""

import re
import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class InputValidator:
    """统一输入校验器"""

    DANGEROUS_PATTERNS = [
        r'<script[^>]*>',
        r'</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'SELECT\s+.*\s+FROM',
        r'DROP\s+TABLE',
        r'DELETE\s+FROM',
        r'UPDATE\s+.*\s+SET',
        r'INSERT\s+INTO',
        r'UNION\s+SELECT',
        r'--',
        r';\s*DROP',
    ]

    @classmethod
    def sanitize(cls, value: str) -> str:
        if not isinstance(value, str):
            return value
        for pattern in cls.DANGEROUS_PATTERNS:
            value = re.sub(pattern, '', value, flags=re.IGNORECASE)
        return value

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
                    cleaned[key] = cls.sanitize(str(value))
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


class OutputEncoder:
    @staticmethod
    def escape_html(text: str) -> str:
        if not text:
            return ''
        replacements = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;',
        }
        for char, entity in replacements.items():
            text = text.replace(char, entity)
        return text

    @classmethod
    def escape_dict(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        escaped = {}
        for key, value in data.items():
            if isinstance(value, str):
                escaped[key] = cls.escape_html(value)
            elif isinstance(value, dict):
                escaped[key] = cls.escape_dict(value)
            elif isinstance(value, list):
                escaped[key] = [cls.escape_html(item) if isinstance(item, str) else item for item in value]
            else:
                escaped[key] = value
        return escaped