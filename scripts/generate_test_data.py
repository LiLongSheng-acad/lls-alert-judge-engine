#!/usr/bin/env python3
"""
生成测试数据脚本
直接向数据库插入 5000 条模拟告警，包含不同攻击类型、严重等级、源 IP
"""

import sqlite3
import random
import datetime
import os
import sys

# 配置
DB_PATH = "/opt/lls-alert-judge-engine/logs/lls-alert-judge-engine.db"
TOTAL_RECORDS = 5000

# 攻击类型及对应的严重等级和危害指数（用于生成分数）
ATTACK_TYPES = {
    'XSS': ['CRITICAL', 'HIGH', 'MEDIUM'],
    'SQLI': ['CRITICAL', 'HIGH'],
    'RCE': ['CRITICAL'],
    'LFI': ['HIGH', 'MEDIUM'],
    'RFI': ['HIGH', 'MEDIUM'],
    'PROTOCOL': ['WARNING', 'INFO'],
    'GENERIC': ['WARNING', 'INFO'],
    'FILE_UPLOAD': ['HIGH', 'MEDIUM'],
}

# 核心资产 IP（将给予高权重）
CORE_IPS = ['10.255.255.254']

# 生成随机公网 IP
def random_public_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

# 生成 URI
def random_uri(attack_type):
    if attack_type == 'XSS':
        return f"/search?q={random.choice(['<script>', 'alert', 'img'])}"
    elif attack_type == 'SQLI':
        return f"/login?user={random.choice(["' OR 1=1--", "admin'--"])}"
    elif attack_type == 'RCE':
        return f"/exec?cmd={random.choice([';ls', ';whoami', '|id'])}"
    elif attack_type == 'PROTOCOL':
        return f"/{random.choice(['ping', 'test', 'health'])}"
    else:
        return f"/{random.choice(['api', 'v1', 'data'])}"

# 生成一条告警记录
def generate_alert(i, src_ip=None, attack_type=None, severity=None, log_time=None):
    if src_ip is None:
        if random.random() < 0.3:  # 30% 是核心 IP
            src_ip = random.choice(CORE_IPS)
        else:
            src_ip = random_public_ip()
    if attack_type is None:
        attack_type = random.choice(list(ATTACK_TYPES.keys()))
    if severity is None:
        severity = random.choice(ATTACK_TYPES[attack_type])
    if log_time is None:
        days_ago = random.randint(0, 7)
        hours_ago = random.randint(0, 23)
        minutes_ago = random.randint(0, 59)
        dt = datetime.datetime.now() - datetime.timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
        log_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    uri = random_uri(attack_type)
    alert_id = f"TEST_{i:08d}"
    vendor = "modsecurity"
    transaction_id = f"txn_{i}"
    src_port = random.randint(1024, 65535)
    dest_ip = "0.0.0.0"
    dest_port = 80
    method = random.choice(['GET', 'POST'])
    headers = '{"host":"example.com"}'
    request_body = ""
    response_status = 200
    attacks = '[{"rule_id":"123","severity":"' + severity + '","attack_type":"' + attack_type + '"}]'
    # 模拟分数：根据攻击类型和严重等级估算
    hazard = {
        'CRITICAL': 10, 'HIGH': 6, 'MEDIUM': 3, 'WARNING': 1, 'INFO': 0.5
    }
    hazard_value = hazard.get(severity, 1)
    # 核心资产权重大
    #if src_ip in CORE_IPS:
        weight = 1.0
    #else:
        weight = 1.0
    # 简单分数 = 权重 * 危害 * 100（约）
    priority_score = round(weight * hazard_value * random.uniform(80, 120), 2)
    is_blocked = 0
    is_processed = 0
    raw_message = f"Test message for {attack_type}"
    return (alert_id, vendor, log_time, transaction_id, src_ip, src_port, dest_ip, dest_port,
            method, uri, headers, request_body, response_status, attacks, attack_type, severity,
            "", "",  # rule_id, payload
            "",  # response_body_preview
            priority_score, is_blocked, is_processed, raw_message)

def main():
    # 备份提示
    print("=" * 60)
    print("测试数据生成脚本")
    print(f"将插入 {TOTAL_RECORDS} 条模拟告警到数据库: {DB_PATH}")
    print("注意：请确保已备份数据库，以免数据丢失。")
    print("=" * 60)

    if not os.path.exists(DB_PATH):
        print("错误：数据库文件不存在，请先运行采集引擎创建数据库。")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 检查表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='modsec_alerts'")
    if not cursor.fetchone():
        print("错误：表 modsec_alerts 不存在，请先运行采集引擎。")
        conn.close()
        sys.exit(1)

    batch = []
    batch_size = 200
    for i in range(1, TOTAL_RECORDS+1):
        rec = generate_alert(i)
        batch.append(rec)
        if len(batch) >= batch_size:
            cursor.executemany("""
                INSERT INTO modsec_alerts (
                    alert_id, vendor, log_time, transaction_id, src_ip, src_port,
                    dest_ip, dest_port, method, uri, headers, request_body,
                    response_status, attacks, attack_type, severity, rule_id,
                    payload, response_body_preview, priority_score, is_blocked,
                    is_processed, raw_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, batch)
            conn.commit()
            print(f"已插入 {i} 条记录", end='\r')
            batch = []
    if batch:
        cursor.executemany("""
            INSERT INTO modsec_alerts (
                alert_id, vendor, log_time, transaction_id, src_ip, src_port,
                dest_ip, dest_port, method, uri, headers, request_body,
                response_status, attacks, attack_type, severity, rule_id,
                payload, response_body_preview, priority_score, is_blocked,
                is_processed, raw_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, batch)
        conn.commit()

    conn.close()
    print(f"\n✅ 成功插入 {TOTAL_RECORDS} 条测试数据！")
    print("现在可以刷新前端页面查看效果。")

if __name__ == "__main__":
    main()
