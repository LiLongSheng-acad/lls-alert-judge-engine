#!/usr/bin/env python3
"""
聚合逻辑 与 关联IP报文查询 的单元测试（标准库 unittest，无第三方依赖）。

覆盖（后端）：
- 聚合 severity 按「等级序」取最大，不被字典序误判
- 聚合样例取「最高优先级」那条，使聚合行与详情一致
- 聚合分组与计数
- 监控模式排除已沉底 / 调查模式包含已沉底
- 关联IP报文查询：按 src_ip 过滤、含已沉底、按优先级倒序

说明：前端「🔎 关联该攻击 IP 的报文」按钮（queryByIp）是 JS 逻辑，
不在本 Python 单测范围；这里覆盖它的后端查询行为。

运行：
    python tests/test_aggregation_and_ip_query.py
或：
    python -m unittest discover -s tests -v
"""
import os
import sys
import asyncio
import sqlite3
import tempfile
import unittest
from pathlib import Path

# 使项目根目录可被导入
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage import db_writer as dbw
from storage import db as sdb
from api.routes import alerts
from api.routes.alerts import AlertListRequest, AlertFilters

TODAY = "2026-10-04"


def _run(coro):
    return asyncio.run(coro)


class _DbCase(unittest.TestCase):
    """公共基类：临时库 + 隔离配置目录，避免读写真实数据"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmpdir = Path(self.tmp.name)
        self.db_path = self.tmpdir / "test.db"
        self.cfg_dir = self.tmpdir / "config"
        self.cfg_dir.mkdir(parents=True, exist_ok=True)

        # 隔离：把 DB 与配置目录指向临时位置
        self._orig = (dbw.DB_PATH, sdb.DB_PATH, alerts.CONFIG_DIR)
        dbw.DB_PATH = self.db_path
        sdb.DB_PATH = self.db_path
        alerts.CONFIG_DIR = self.cfg_dir

        dbw.DBWriter()  # 使用与生产一致的建表语句
        self.conn = sqlite3.connect(str(self.db_path))

    def tearDown(self):
        self.conn.close()
        dbw.DB_PATH, sdb.DB_PATH, alerts.CONFIG_DIR = self._orig
        self.tmp.cleanup()

    def insert(self, alert_id, src_ip="1.1.1.1", dest_ip="d.example.com",
               uri="/x", attack_type="XSS", severity="MEDIUM",
               priority_score=100.0, is_blocked=0, log_time=None):
        self.conn.execute(
            """INSERT INTO modsec_alerts
               (alert_id, vendor, log_time, src_ip, dest_ip, uri, method,
                attack_type, severity, priority_score, is_blocked, is_processed)
               VALUES (?, 'modsecurity', ?, ?, ?, ?, 'GET', ?, ?, ?, ?, 0)""",
            (alert_id, log_time or (TODAY + " 10:00:00"), src_ip, dest_ip, uri,
             attack_type, severity, priority_score, is_blocked))
        self.conn.commit()

    def aggregate(self, **kw):
        res = _run(alerts.list_alerts(AlertListRequest(aggregate=True, **kw), "admin"))
        self.assertEqual(res.code, 0, res.msg)
        return res.data

    def detail(self, **kw):
        res = _run(alerts.list_alerts(AlertListRequest(aggregate=False, **kw), "admin"))
        self.assertEqual(res.code, 0, res.msg)
        return res.data


class AggregationTest(_DbCase):
    """聚合逻辑"""

    def test_severity_not_lexicographic(self):
        """同组含 CRITICAL 与 MEDIUM，应取 CRITICAL（字典序会误判为 MEDIUM）"""
        self.insert("A04000001", severity="CRITICAL", priority_score=3200)
        self.insert("A04000002", severity="MEDIUM", priority_score=100)
        items = self.aggregate(ignore_filters=True)["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["severity"], "CRITICAL")

    def test_sample_is_highest_priority(self):
        """样例取最高优先级那条（此例会暴露 MAX(alert_id) 的旧缺陷）"""
        self.insert("A04000001", severity="CRITICAL", priority_score=3200)
        self.insert("A04000002", severity="MEDIUM", priority_score=100)
        item = self.aggregate(ignore_filters=True)["items"][0]
        self.assertEqual(item["sample_alert_id"], "A04000001")
        self.assertEqual(item["max_priority_score"], 3200.0)

    def test_grouping_and_count(self):
        self.insert("A04000101", attack_type="XSS", uri="/a")
        self.insert("A04000102", attack_type="XSS", uri="/a")
        self.insert("A04000103", attack_type="SQLI", uri="/a")
        data = self.aggregate(ignore_filters=True)
        self.assertTrue(data["aggregated"])
        self.assertEqual(data["total"], 2)  # (XSS,/a) 与 (SQLI,/a) 两组
        self.assertEqual(sorted(i["count"] for i in data["items"]), [1, 2])

    def test_monitor_mode_excludes_blocked(self):
        """监控模式（ignore_filters=False）已沉底不计入聚合"""
        self.insert("A04000201", is_blocked=0)
        self.insert("A04000202", is_blocked=1)
        data = self.aggregate(ignore_filters=False)
        self.assertEqual(sum(i["count"] for i in data["items"]), 1)

    def test_investigate_mode_includes_blocked(self):
        """调查模式（ignore_filters=True）已沉底仍计入"""
        self.insert("A04000301", is_blocked=0)
        self.insert("A04000302", is_blocked=1)
        data = self.aggregate(ignore_filters=True)
        self.assertEqual(sum(i["count"] for i in data["items"]), 2)

    def test_null_severity_maps_to_info(self):
        self.insert("A04000401", severity=None)
        item = self.aggregate(ignore_filters=True)["items"][0]
        self.assertEqual(item["severity"], "INFO")

    def test_severity_rank_constant(self):
        self.assertEqual(alerts.SEVERITY_BY_RANK[6], "CRITICAL")
        self.assertEqual(alerts.SEVERITY_BY_RANK[5], "HIGH")
        self.assertEqual(alerts.SEVERITY_BY_RANK[4], "MEDIUM")
        self.assertEqual(alerts.SEVERITY_BY_RANK[0], "INFO")


class RelatedIpQueryTest(_DbCase):
    """关联IP报文查询（detail 模式 + filters.src_ip）"""

    IP = "9.9.9.9"

    def _seed(self):
        self.insert("A04000501", src_ip=self.IP, is_blocked=0, priority_score=500)
        self.insert("A04000502", src_ip=self.IP, is_blocked=1, priority_score=900)
        self.insert("A04000503", src_ip="8.8.8.8", is_blocked=0, priority_score=700)

    def test_filter_by_src_ip_includes_sunk(self):
        """调查模式下按源IP取出全部报文，含已沉底，且不含其它IP"""
        self._seed()
        data = self.detail(ignore_filters=True, filters=AlertFilters(src_ip=self.IP))
        self.assertEqual(data["total"], 2)
        ids = [i["alert_id"] for i in data["items"]]
        self.assertIn("A04000501", ids)
        self.assertIn("A04000502", ids)
        self.assertNotIn("A04000503", ids)

    def test_filter_by_src_ip_excludes_sunk_in_monitor(self):
        self._seed()
        data = self.detail(ignore_filters=False, filters=AlertFilters(src_ip=self.IP))
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["alert_id"], "A04000501")

    def test_ordered_by_priority_desc(self):
        self._seed()
        data = self.detail(ignore_filters=True, filters=AlertFilters(src_ip=self.IP))
        scores = [i["priority_score"] for i in data["items"]]
        self.assertEqual(scores, sorted(scores, reverse=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
