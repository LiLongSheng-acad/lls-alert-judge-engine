#!/usr/bin/env python3
"""
db_writer.py - 统一数据库写入模块

职责：
1. 接收标准化数据（CommonSchema 字典）
2. 批量写入 SQLite 数据库
3. 支持“零存整取”策略（批量写入 + 定时刷盘）
4. 自动建表、创建索引（含审计表）
"""
import sys
import os
import sqlite3
import time
from typing import Dict, Any

# 确保项目根目录在 sys.path 中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import DB_PATH, COLLECTOR


class DBWriter:
    """SQLite 批量写入器（零存整取）"""
    
    def __init__(self, db_path: str = None, batch_size: int = None, flush_interval: int = None):
        """
        初始化数据库写入器

        Args:
            db_path: 数据库路径，默认使用 DB_PATH
            batch_size: 批量写入阈值，默认使用 COLLECTOR['batch_size']
            flush_interval: 强制刷盘间隔（秒），默认使用 COLLECTOR['flush_interval']
        """
        if db_path is None:
            db_path = str(DB_PATH)
        if batch_size is None:
            batch_size = COLLECTOR["batch_size"]
        if flush_interval is None:
            flush_interval = COLLECTOR["flush_interval"]

        self.db_path = db_path
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.buffer = []
        self.last_flush_time = time.time()
        
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        
    def _init_db(self):
        """创建表结构（如果不存在）"""
        conn = self._get_conn()
        cursor = conn.cursor()
        
        # ===== 主表：modsec_alerts =====
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS modsec_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                vendor TEXT NOT NULL,
                log_time TEXT NOT NULL,
                transaction_id TEXT,
                src_ip TEXT NOT NULL,
                src_port INTEGER,
                dest_ip TEXT,
                dest_port INTEGER,
                method TEXT,
                uri TEXT,
                headers TEXT,
                request_body TEXT,
                response_status INTEGER,
                attacks TEXT,
                attack_type TEXT,
                severity TEXT,
                rule_id TEXT,
                payload TEXT,
                response_body_preview TEXT,
                priority_score REAL DEFAULT 0,
                is_blocked INTEGER DEFAULT 0,
                is_processed INTEGER DEFAULT 0,
                raw_message TEXT,
                created_at TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)
        
        # 主表索引
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_id ON modsec_alerts(alert_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON modsec_alerts(src_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_priority ON modsec_alerts(priority_score DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_log_time ON modsec_alerts(log_time)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON modsec_alerts(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_dest_ip ON modsec_alerts(dest_ip)")

        # ===== 审计表：规则审计 =====
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_rule_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operator TEXT NOT NULL,
                action TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_data TEXT,
                source TEXT DEFAULT 'manual',
                client_ip TEXT,
                created_at TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_operator ON audit_rule_log(operator)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_rule_log(action)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_rule_log(created_at)")

        # ===== 审计表：资产审计 =====
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_asset_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operator TEXT NOT NULL,
                action TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                asset_data TEXT,
                detail TEXT,
                client_ip TEXT,
                created_at TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_asset_operator ON audit_asset_log(operator)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_asset_action ON audit_asset_log(action)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_asset_created_at ON audit_asset_log(created_at)")

        conn.commit()
        conn.close()
        print(f"[DB] 数据库初始化完成: {self.db_path}")
    
    def _get_conn(self):
        """获取数据库连接（启用 WAL 模式和超时设置）"""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-10000")
        conn.execute("PRAGMA busy_timeout = 5000")  # 等待锁最多5秒
        return conn
    
    def add(self, data: Dict[str, Any]):
        """添加一条记录到缓冲区"""
        self.buffer.append(data)
        if len(self.buffer) >= self.batch_size:
            self.flush()
            return
        if (time.time() - self.last_flush_time) >= self.flush_interval:
            self.flush()
    
    def flush(self):
        """将缓冲区中的数据批量写入数据库"""
        if not self.buffer:
            return
        
        conn = None
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT INTO modsec_alerts (
                    alert_id, vendor, log_time, transaction_id, src_ip, src_port,
                    dest_ip, dest_port, method, uri, headers, request_body,
                    response_status, attacks, attack_type, severity, rule_id,
                    payload, response_body_preview, priority_score, is_blocked,
                    is_processed, raw_message
                ) VALUES (
                    :alert_id, :vendor, :log_time, :transaction_id, :src_ip, :src_port,
                    :dest_ip, :dest_port, :method, :uri, :headers, :request_body,
                    :response_status, :attacks, :attack_type, :severity, :rule_id,
                    :payload, :response_body_preview, :priority_score, :is_blocked,
                    :is_processed, :raw_message
                )
            """, self.buffer)
            conn.commit()
            count = len(self.buffer)
            print(f"[DB] 批量写入 {count} 条记录")
            self.buffer = []
            self.last_flush_time = time.time()
        except sqlite3.Error as e:
            print(f"[ERROR] 数据库写入失败: {e}")
        finally:
            if conn:
                conn.close()
    
    def flush_on_exit(self):
        """程序退出时强制刷盘（防止数据丢失）"""
        if self.buffer:
            print(f"[DB] 退出前刷盘，剩余 {len(self.buffer)} 条")
            self.flush()
    
    def get_stats(self) -> Dict[str, Any]:
        """获取数据库统计信息"""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM modsec_alerts")
            total = cursor.fetchone()[0]
            cursor.execute("""
                SELECT severity, COUNT(*) FROM modsec_alerts 
                GROUP BY severity ORDER BY COUNT(*) DESC
            """)
            severity_dist = cursor.fetchall()
            cursor.execute("""
                SELECT attack_type, COUNT(*) FROM modsec_alerts 
                WHERE attack_type != 'UNKNOWN'
                GROUP BY attack_type ORDER BY COUNT(*) DESC LIMIT 10
            """)
            attack_dist = cursor.fetchall()
            conn.close()
            return {
                'total': total,
                'severity_distribution': dict(severity_dist),
                'top_attack_types': dict(attack_dist)
            }
        except Exception as e:
            print(f"[ERROR] 获取统计信息失败: {e}")
            return {}

# ==================== 独立测试 ====================
if __name__ == "__main__":
    writer = DBWriter(str(DB_PATH))
    test_data = {
        'alert_id': 'A20260829000001',
        'vendor': 'modsecurity',
        'log_time': '2026-08-29T10:00:00+08:00',
        'transaction_id': 'test123',
        'src_ip': '1.2.3.4',
        'src_port': 12345,
        'dest_ip': '192.168.1.10',
        'dest_port': 80,
        'method': 'POST',
        'uri': '/admin/login',
        'headers': '{"host":"example.com"}',
        'request_body': 'test=<script>alert(1)</script>',
        'response_status': 200,
        'attacks': '[{"rule_id":"941100","severity":"CRITICAL","attack_type":"XSS"}]',
        'attack_type': 'XSS',
        'severity': 'CRITICAL',
        'rule_id': '941100',
        'payload': '<script>alert(1)</script>',
        'response_body_preview': '<html>...</html>',
        'priority_score': 650,
        'is_blocked': 0,
        'is_processed': 0,
        'raw_message': 'ModSecurity log raw...'
    }
    writer.add(test_data)
    writer.flush_on_exit()
    stats = writer.get_stats()
    print(f"[TEST] 统计: {stats}")
