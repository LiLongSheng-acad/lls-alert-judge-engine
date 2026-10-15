#!/usr/bin/env python3
"""
modsec_adapter.py - ModSecurity 日志适配器（统一日志格式版）

日志格式假设：
    采集器IP 2026-08-30T00:51:00+08:00 localhost modsec {"transaction":{...}}

职责：
1. 识别 ModSecurity 日志行
2. 从行首提取采集器 IP
3. 解析 JSON 格式的日志内容
4. 提取标准化字段：src_ip, uri, method, attack_type, severity, payload, collector_ip
5. 输出 CommonSchema 对象
"""
import re
import json
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.models import CommonSchema
from adapters.base_adapter import BaseAdapter


class ModSecAdapter(BaseAdapter):
    """ModSecurity 日志适配器（统一日志格式版）"""

    TAG = "modsec"

    def match(self, raw_line: str) -> bool:
        """判断是否为 ModSecurity 日志行"""
        return self.TAG in raw_line and "{" in raw_line

    def parse(self, raw_line: str) -> CommonSchema:
        """
        解析 ModSecurity 日志行

        Args:
            raw_line: 原始日志行，格式: 采集器IP timestamp hostname tag {...}

        Returns:
            CommonSchema: 标准化后的数据对象
        """
        schema = CommonSchema()
        schema.vendor = "modsecurity"
        schema.raw_message = raw_line[:500]

        # ---- 提取采集器 IP（行首第一个空格前的内容） ----
        parts = raw_line.split(' ', 1)
        if len(parts) >= 2:
            schema.collector_ip = parts[0]
            remaining = parts[1]
        else:
            schema.collector_ip = "0.0.0.0"
            remaining = raw_line

        # ---- 提取 JSON 部分 ----
        start = remaining.find('{')
        if start == -1:
            return schema

        try:
            data = json.loads(remaining[start:])

            trans = data.get('transaction', {})
            req = data.get('request', {})
            resp = data.get('response', {})
            audit = data.get('audit_data', {})

            # --- 基础信息 ---
            # ---- 时间转换：从 ModSecurity 格式转为标准格式 ----
            time_raw = trans.get('time', '')
            if time_raw:
                try:
                    # 格式: "30/Aug/2026:07:54:20.235579 +0800"
                    # 去掉时区部分
                    time_part = time_raw.split(' +')[0]  # "30/Aug/2026:07:54:20.235579"
                    # 去掉毫秒
                    time_part = time_part.split('.')[0]  # "30/Aug/2026:07:54:20"
                    # 转换为 datetime 对象
                    dt = datetime.strptime(time_part, "%d/%b/%Y:%H:%M:%S")
                    # 转为标准格式
                    schema.timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                except Exception as e:
                    print(f"[WARN] 时间解析失败: {e}, 原始值: {time_raw}")
                    schema.timestamp = time_raw
            else:
                schema.timestamp = ''

            schema.transaction_id = trans.get('transaction_id', '')
            schema.src_ip = trans.get('remote_address', '0.0.0.0')
            schema.src_port = trans.get('remote_port', 0)

            # --- 目的 IP / Host（从请求头提取） ---
            headers = req.get('headers', {})
            schema.dest_ip = headers.get('Host', '')

            # --- 从 request_line 提取 method 和 uri ---
            request_line = req.get('request_line', '')
            if request_line:
                parts_line = request_line.split(' ')
                if len(parts_line) >= 2:
                    schema.method = parts_line[0]
                    schema.uri = parts_line[1]
            else:
                schema.method = req.get('method', '')
                schema.uri = req.get('uri', '')

            # --- 请求头 ---
            schema.headers = {
                'host': headers.get('Host', ''),
                'user_agent': headers.get('User-Agent', '')[:255],
                'content_type': headers.get('Content-Type', '')
            }

            # --- 请求体 ---
            body_list = req.get('body', [])
            schema.request_body = body_list[0][:1024] if body_list else ''

            # --- 响应状态 ---
            schema.response_status = resp.get('status', 0)

            # --- 响应体预览 ---
            body = resp.get('body', '')
            if body and len(body) > 1024:
                schema.response_body_preview = body[:1024] + '... [truncated]'
            else:
                schema.response_body_preview = body

            # --- 提取攻击信息 ---
            messages = audit.get('messages', [])
            schema.attacks = []

            for msg in messages:
                if isinstance(msg, str):
                    msg_text = msg
                else:
                    msg_text = msg.get('message', '')

                if msg_text:
                    attack_info = self._parse_message(msg_text)
                    if attack_info and attack_info.get('rule_id'):
                        schema.attacks.append(attack_info)

            # --- 选择主要攻击类型 ---
            # 按「单次损失」从高到低排列，与 config/financial_factors.yaml 的 attack_loss 对应
            priority_order = [
                'RCE', 'COMMAND_INJECTION', 'DESERIALIZATION', 'SSTI',
                'SQLI',
                'LFI', 'RFI', 'FILE', 'FILE_UPLOAD',
                'SSRF',
                'XSS',
                'OPEN_REDIRECT',
                'UNKNOWN',
                'PROTOCOL', 'GENERIC',
            ]
            primary = None

            for priority_type in priority_order:
                for attack in schema.attacks:
                    if attack.get('attack_type') == priority_type:
                        primary = attack
                        break
                if primary:
                    break

            if not primary:
                for attack in schema.attacks:
                    if attack.get('attack_type') != 'UNKNOWN':
                        primary = attack
                        break

            if not primary and schema.attacks:
                primary = schema.attacks[0]

            if primary:
                schema.attack_type = primary.get('attack_type', 'UNKNOWN')
                schema.severity = primary.get('severity', 'INFO')
                schema.rule_id = primary.get('rule_id', '')
                schema.payload = primary.get('payload', '')

        except json.JSONDecodeError:
            # JSON 解析失败，返回当前已填充的 schema
            pass
        except Exception as e:
            print(f"[ERROR] ModSecAdapter.parse 异常: {e}")
            import traceback
            traceback.print_exc()

        return schema

    def _parse_message(self, msg_text: str) -> dict:
        """
        从 ModSecurity 的 message 字符串中提取结构化信息

        Args:
            msg_text: 原始 message 字符串

        Returns:
            dict: 包含 rule_id, severity, attack_type, message, payload
        """
        result = {
            'rule_id': '',
            'severity': 'INFO',
            'attack_type': 'UNKNOWN',
            'message': '',
            'payload': ''
        }

        # 提取 rule_id
        match = re.search(r'\[id\s+"?(\d+)"?\]', msg_text)
        if match:
            result['rule_id'] = match.group(1)

        # 提取 severity
        match = re.search(r'\[severity\s+"?(\w+)"?\]', msg_text, re.IGNORECASE)
        if match:
            result['severity'] = match.group(1).upper()

        # 提取 msg
        match = re.search(r'\[msg\s+"([^"]+)"\]', msg_text)
        if match:
            result['message'] = match.group(1)

        # 提取 payload（Matched Data 部分）
        match = re.search(r'Matched Data:\s+(.+?)(?:\s+\[|$)', msg_text)
        if match:
            result['payload'] = match.group(1)[:500]

        # 从 tags 中提取 attack_type
        # 统一命名：attack-file-upload → FILE_UPLOAD（多词标签的 - 转 _）
        # （与 config/financial_factors.yaml 的 attack_loss 键保持一致）
        tags = re.findall(r'\[tag\s+"([^"]+)"\]', msg_text)
        for tag in tags:
            if tag.startswith('attack-'):
                result['attack_type'] = tag.replace('attack-', '').upper().replace('-', '_')
                break

        return result