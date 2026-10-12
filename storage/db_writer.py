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

# 写入失败后的最大退避秒数（指数退避上限）
MAX_BACKOFF_SECONDS = 60
# 缓冲堆积告警阈值：超过说明数据库长时间不可用，提前暴露而不是静默吞掉
BUFFER_WARN_THRESHOLD = 10000


class DBWriter:
    """SQLite 批量写入器（零存整取）"""

    # 批量/单条写入共用同一 SQL，避免两处漂移
    _INSERT_SQL = """
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
    """
    
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
        # 失败退避状态：数据库暂时不可用时避免紧密重试
        self._next_retry_time = 0.0
        self._consecutive_failures = 0
        
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

        # ===== 规则升格「知晓」表（通知确认，窗口期内抑制重复通知） =====
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rule_promotion_ack (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                field TEXT,
                rule_operator TEXT,
                value TEXT,
                operator TEXT NOT NULL,
                note TEXT,
                created_at TEXT DEFAULT (datetime('now', 'localtime'))
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_promotion_ack_fingerprint ON rule_promotion_ack(fingerprint)")

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
        if len(self.buffer) == BUFFER_WARN_THRESHOLD:
            print(f"[WARN] 写入缓冲已达 {len(self.buffer)} 条，数据库可能长时间不可用")

        now = time.time()
        # 退避期内只入缓冲、不刷盘，避免对暂不可用的数据库做紧密重试
        if now < self._next_retry_time:
            return
        if len(self.buffer) >= self.batch_size:
            self.flush()
            return
        if (now - self.last_flush_time) >= self.flush_interval:
            self.flush()
    
    def flush(self):
        """将缓冲区中的数据批量写入数据库

        失败处理分两类：
          - 重复/非法记录（IntegrityError）：逐条降级写入，跳过错行，避免整批永久卡死；
          - 数据库暂不可用（锁、磁盘等）：保留缓冲并指数退避，绝不丢数据，也绝不紧密重试。
        """
        if not self.buffer:
            return
        
        conn = None
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            try:
                cursor.executemany(self._INSERT_SQL, self.buffer)
                conn.commit()
            except sqlite3.IntegrityError as e:
                # 批次里有重复/非法记录：回滚后逐条写入，隔离并跳过坏记录
                conn.rollback()
                skipped = self._insert_row_by_row(cursor)
                conn.commit()
                print(f"[WARN] 批量写入遇重复/非法记录，已跳过 {skipped} 条（首条错误: {e}）")

            count = len(self.buffer)
            self.buffer = []
            self.last_flush_time = time.time()
            self._next_retry_time = 0.0
            self._consecutive_failures = 0
            print(f"[DB] 批量写入 {count} 条记录")
        except sqlite3.Error as e:
            # 数据库暂时不可用：保留缓冲，指数退避后重试
            self._consecutive_failures += 1
            backoff = min(2 ** self._consecutive_failures, MAX_BACKOFF_SECONDS)
            self._next_retry_time = time.time() + backoff
            print(f"[ERROR] 数据库写入失败（第 {self._consecutive_failures} 次），"
                  f"{backoff}s 后重试，缓冲保留 {len(self.buffer)} 条: {e}")
        finally:
            if conn:
                conn.close()

    def _insert_row_by_row(self, cursor) -> int:
        """逐条写入缓冲，跳过 IntegrityError（重复/非法）行。

        其余数据库错误继续抛出，交由 flush() 走退避逻辑（此时事务未提交，自动回滚）。
        """
        skipped = 0
        for row in self.buffer:
            try:
                cursor.execute(self._INSERT_SQL, row)
            except sqlite3.IntegrityError as e:
                skipped += 1
                alert_id = row.get("alert_id") if isinstance(row, dict) else "?"
                print(f"[WARN] 跳过重复/非法记录 alert_id={alert_id}: {e}")
        return skipped
    
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
