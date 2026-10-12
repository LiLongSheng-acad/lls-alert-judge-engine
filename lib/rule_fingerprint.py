#!/usr/bin/env python3
"""
lib/rule_fingerprint.py - 沉底规则指纹计算

用于「规则升格机制」：将 (field, operator, value) 归一化后生成稳定指纹，
以便跨用户、跨时间统计“同一条规则”被提出的次数，避免逐字段两两比对。

归一化规则必须显式定义（见 normalize_value），否则语义相近的规则会被拆成多条。
"""
import hashlib
import ipaddress


def normalize_value(field: str, value: str) -> str:
    """对匹配值做归一化，使语义相同的取值得到相同的指纹输入"""
    v = (value or '').strip()
    if not v:
        return ''

    # IP / CIDR：交给 ipaddress 规范化
    if field == 'src_ip':
        if '/' in v:
            try:
                return str(ipaddress.ip_network(v, strict=False))
            except ValueError:
                return v.lower()
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return v.lower()

    # 枚举类字段统一大写
    if field in ('method', 'attack_type'):
        return v.upper()

    # URI / User-Agent 等文本类字段：统一小写
    return v.lower()


def compute_fingerprint(field: str, operator: str, value: str) -> str:
    """计算规则指纹：md5(field | operator | normalized_value)"""
    normalized = normalize_value(field, value)
    raw = f"{(field or '').strip()}|{(operator or '').strip()}|{normalized}"
    return hashlib.md5(raw.encode('utf-8')).hexdigest()
