#!/usr/bin/env python3
"""
接口契约回归测试（重构安全网）。

目的：在重构（实现层）之前，把各路由「对外可观察的行为」钉住——
      请求分发、返回结构 {code,msg,data}、关键业务结果。
      只要这些测试保持绿色，就说明重构没有改变对外契约。

隔离：临时库 + 临时配置/日志目录，逐模块打补丁，不触碰真实数据。

运行： python tests/test_api_contract.py
"""
import os
import sys
import asyncio
import sqlite3
import tempfile
import types
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import HTTPException

from storage import db_writer as dbw
from storage import db as sdb
from storage import audit as saudit
from api.common import validation_error
from api.routes import alerts, rules, assets, actions, audit, promotions

TODAY = "2026-10-04"


def _run(coro):
    return asyncio.run(coro)


def _fake_request():
    """模拟 FastAPI Request（仅需 .client.host）"""
    return types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))


class _ApiCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.db = root / "test.db"
        self.cfg = root / "config"
        self.logs = root / "logs"
        self.cfg.mkdir(parents=True)
        self.logs.mkdir(parents=True)

        self._patches = []

        def patch(mod, name, val):
            self._patches.append((mod, name, getattr(mod, name)))
            setattr(mod, name, val)

        # DB 路径（统一连接入口 storage.db；DBWriter 另用 dbw.DB_PATH）
        patch(dbw, "DB_PATH", self.db)
        patch(sdb, "DB_PATH", self.db)
        # 配置目录
        for m in (alerts, actions, assets, rules, promotions):
            if hasattr(m, "CONFIG_DIR"):
                patch(m, "CONFIG_DIR", self.cfg)
        # 审计日志目录（统一入口 storage.audit）
        patch(saudit, "LOG_DIR", self.logs)

        dbw.DBWriter()  # 用生产同款 DDL 在临时库建表
        self.conn = sqlite3.connect(str(self.db))

    def tearDown(self):
        self.conn.close()
        for mod, name, val in reversed(self._patches):
            setattr(mod, name, val)
        self.tmp.cleanup()

    # ---- 工具 ----
    def insert_alert(self, alert_id, src_ip="1.1.1.1", dest_ip="d.example.com",
                     uri="/x", attack_type="XSS", severity="HIGH",
                     priority_score=100.0, is_blocked=0, method="GET"):
        self.conn.execute(
            """INSERT INTO modsec_alerts
               (alert_id, vendor, log_time, src_ip, dest_ip, uri, method,
                attack_type, severity, priority_score, is_blocked, is_processed)
               VALUES (?, 'modsecurity', ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (alert_id, TODAY + " 10:00:00", src_ip, dest_ip, uri, method,
             attack_type, severity, priority_score, is_blocked))
        self.conn.commit()

    def blocked_of(self, alert_id):
        row = self.conn.execute(
            "SELECT is_blocked FROM modsec_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return row[0] if row else None


# ============================================================
# /api/alerts
# ============================================================
class AlertsContractTest(_ApiCase):
    def setUp(self):
        super().setUp()
        self.insert_alert("A100", priority_score=3200, severity="CRITICAL")
        self.insert_alert("A101", priority_score=100, severity="MEDIUM")

    def call(self, payload, user="admin"):
        return _run(alerts.handle_alerts(_fake_request(), payload, user))

    def test_list_detail_shape(self):
        r = self.call({"action": "list", "ignore_filters": True})
        self.assertEqual(r.code, 0)
        self.assertFalse(r.data["aggregated"])
        self.assertIn("total", r.data)
        item = r.data["items"][0]
        for k in ("alert_id", "src_ip", "dest_ip", "uri", "method",
                  "attack_type", "severity", "priority_score", "log_time"):
            self.assertIn(k, item)

    def test_list_aggregate_shape(self):
        r = self.call({"action": "list", "aggregate": True, "ignore_filters": True})
        self.assertTrue(r.data["aggregated"])
        item = r.data["items"][0]
        for k in ("fingerprint", "src_ip", "dest_ip", "uri", "attack_type",
                  "severity", "count", "max_priority_score",
                  "first_log_time", "last_log_time", "sample_alert_id"):
            self.assertIn(k, item)

    def test_detail_found_and_not_found(self):
        r = self.call({"action": "detail", "alert_id": "A100"})
        self.assertEqual(r.code, 0)
        self.assertEqual(r.data["alert_id"], "A100")
        r2 = self.call({"action": "detail", "alert_id": "NOPE"})
        self.assertEqual(r2.code, 404)

    def test_stats_keys(self):
        r = self.call({"action": "stats"})
        self.assertEqual(r.code, 0)
        for k in ("total", "pending", "blocked", "today", "top_attack_types"):
            self.assertIn(k, r.data)

    def test_report_keys(self):
        r = self.call({"action": "report"})
        self.assertEqual(r.code, 0)
        for k in ("time_from", "time_to", "total", "blocked", "remaining"):
            self.assertIn(k, r.data)
        self.assertEqual(r.data["remaining"], max(r.data["total"] - r.data["blocked"], 0))

    def test_unknown_action_raises_400(self):
        with self.assertRaises(HTTPException) as ctx:
            self.call({"action": "nonsense"})
        self.assertEqual(ctx.exception.status_code, 400)


# ============================================================
# /api/rules
# ============================================================
class RulesContractTest(_ApiCase):
    def call(self, payload, user="zhangsan"):
        return _run(rules.handle_rules(_fake_request(), payload, user))

    def _create_payload(self, scope="personal"):
        return {
            "action": "create", "field": "uri", "operator": "contains",
            "value": "/health", "scope": scope, "reason": "test",
            "expire_at": (datetime.now() + timedelta(hours=1)).isoformat(),
        }

    def test_create_then_list(self):
        r = self.call(self._create_payload())
        self.assertEqual(r.code, 0)
        self.assertIn("rule_id", r.data)
        lst = self.call({"action": "list"})
        self.assertEqual(lst.code, 0)
        self.assertEqual(lst.data["total"], 1)

    def test_global_create_requires_admin(self):
        r = self.call(self._create_payload(scope="global"), user="zhangsan")
        self.assertEqual(r.code, 403)
        r2 = self.call(self._create_payload(scope="global"), user="admin")
        self.assertEqual(r2.code, 0)

    def test_toggle_and_delete(self):
        rid = self.call(self._create_payload()).data["rule_id"]
        tg = self.call({"action": "toggle", "rule_id": rid, "enabled": False})
        self.assertEqual(tg.code, 0)
        dl = self.call({"action": "delete", "rule_id": rid})
        self.assertEqual(dl.code, 0)
        self.assertEqual(self.call({"action": "list"}).data["total"], 0)

    def _create(self, **over):
        p = self._create_payload()
        p.update(over)
        return self.call(p)

    def test_user_agent_rule_maps_to_headers(self):
        """user_agent 规则应映射到 headers 列，而非不存在的列名（否则 SQL 报错）"""
        self.insert_alert("UA1", uri="/a")
        self.conn.execute(
            "UPDATE modsec_alerts SET headers=? WHERE alert_id='UA1'",
            ('{"user_agent":"bot"}',))
        self.conn.commit()
        self.insert_alert("UA2", uri="/a")
        self.assertEqual(self._create(field="user_agent", operator="contains", value="bot").code, 0)
        res = _run(alerts.handle_alerts(_fake_request(), {"action": "list"}, "zhangsan"))
        self.assertEqual(res.code, 0)
        ids = [i["alert_id"] for i in res.data["items"]]
        self.assertIn("UA2", ids)
        self.assertNotIn("UA1", ids)

    def test_cidr_rule_matches_range(self):
        """src_ip 规则值填 CIDR 网段时，应按网段匹配（而非字面等值）"""
        self.insert_alert("CIDR1", src_ip="10.1.2.3")
        self.insert_alert("CIDR2", src_ip="192.168.1.1")
        self.assertEqual(self._create(field="src_ip", operator="exact", value="10.0.0.0/8").code, 0)
        res = _run(alerts.handle_alerts(_fake_request(), {"action": "list"}, "zhangsan"))
        ids = [i["alert_id"] for i in res.data["items"]]
        self.assertIn("CIDR2", ids)
        self.assertNotIn("CIDR1", ids)

    def test_regex_rule_filters(self):
        """regex 操作符应真正生效"""
        self.insert_alert("RX1", uri="/admin/login")
        self.insert_alert("RX2", uri="/public")
        self.assertEqual(self._create(field="uri", operator="regex", value="^/admin/").code, 0)
        res = _run(alerts.handle_alerts(_fake_request(), {"action": "list"}, "zhangsan"))
        ids = [i["alert_id"] for i in res.data["items"]]
        self.assertIn("RX2", ids)
        self.assertNotIn("RX1", ids)


# ============================================================
# /api/assets
# ============================================================
class AssetsContractTest(_ApiCase):
    def call(self, payload, user="admin"):
        return _run(assets.handle_assets(_fake_request(), payload, user))

    def test_non_admin_create_forbidden(self):
        r = self.call({"action": "create", "identifier": "10.0.0.1",
                       "name": "x", "base_weight": 1.0}, user="zhangsan")
        self.assertEqual(r.code, 403)

    def test_crud(self):
        c = self.call({"action": "create", "identifier": "10.0.0.1",
                       "name": "核心", "base_weight": 2.0})
        self.assertEqual(c.code, 0)
        aid = c.data["asset_id"]

        lst = self.call({"action": "list"})
        self.assertEqual(lst.code, 0)
        self.assertGreaterEqual(lst.data["total"], 1)

        d = self.call({"action": "detail", "asset_id": aid})
        self.assertEqual(d.code, 0)
        self.assertEqual(d.data["identifier"], "10.0.0.1")

        u = self.call({"action": "update", "asset_id": aid, "base_weight": 3.0})
        self.assertEqual(u.code, 0)

        dl = self.call({"action": "delete", "asset_id": aid})
        self.assertEqual(dl.code, 0)


# ============================================================
# /api/actions
# ============================================================
class ActionsContractTest(_ApiCase):
    def setUp(self):
        super().setUp()
        self.insert_alert("B100", src_ip="9.9.9.9")
        self.insert_alert("B101", src_ip="9.9.9.9")

    def test_sink_single(self):
        r = _run(actions.sink_alert(_fake_request(), {
            "action": "sink", "alert_id": "B100", "mode": "single",
            "reason": "误报"}, "zhangsan"))
        self.assertEqual(r.code, 0)
        self.assertEqual(r.data["affected_count"], 1)
        self.assertEqual(self.blocked_of("B100"), 1)

    def test_ip_sink(self):
        r = _run(actions.ip_sink(_fake_request(), {
            "src_ip": "9.9.9.9", "reason": "扫描器", "create_rule": False}, "zhangsan"))
        self.assertEqual(r.code, 0)
        self.assertEqual(r.data["affected_count"], 2)

    def test_aggregate_sink(self):
        r = _run(actions.aggregate_sink(_fake_request(), {
            "src_ip": "9.9.9.9", "attack_type": "XSS", "uri": "/x",
            "reason": "聚合"}, "zhangsan"))
        self.assertEqual(r.code, 0)
        self.assertEqual(r.data["affected_count"], 2)

    def test_batch_sink(self):
        """批量沉底：alert_ids 列表不应被清洗成字符串（批次 1 已修复）"""
        r = _run(actions.batch_sink(_fake_request(), {
            "action": "batch_sink", "alert_ids": ["B100", "B101"],
            "reason": "批量"}, "zhangsan"))
        self.assertEqual(r.code, 0)
        self.assertEqual(r.data["affected_count"], 2)

    def test_ip_sink_creates_temp_rule(self):
        """IP 沉底 + create_rule：应写入规则文件（回归：移除装饰性 reload 后仍生效）"""
        r = _run(actions.ip_sink(_fake_request(), {
            "src_ip": "9.9.9.9", "reason": "扫描器", "create_rule": True}, "zhangsan"))
        self.assertEqual(r.code, 0)
        self.assertIsNotNone(r.data.get("rule_id"))
        self.assertTrue((self.cfg / "sink_rules.json").exists())

    def test_history_shape(self):
        r = _run(actions.get_history("zhangsan"))
        self.assertEqual(r.code, 0)
        self.assertIn("items", r.data)


# ============================================================
# /api/audit
# ============================================================
class AuditContractTest(_ApiCase):
    def test_rules_audit_shape(self):
        # 先造一条规则审计
        _run(rules.handle_rules(_fake_request(), {
            "action": "create", "field": "uri", "operator": "contains",
            "value": "/health", "scope": "personal", "reason": "t",
            "expire_at": (datetime.now() + timedelta(hours=1)).isoformat(),
        }, "zhangsan"))
        r = _run(audit.list_audit({"action": "list"}, "admin"))
        self.assertEqual(r.code, 0)
        for k in ("total", "page", "size", "items"):
            self.assertIn(k, r.data)
        self.assertGreaterEqual(r.data["total"], 1)

    def test_assets_audit_shape(self):
        r = _run(audit.list_asset_audit({"action": "list"}, "admin"))
        self.assertEqual(r.code, 0)
        self.assertIn("items", r.data)


# ============================================================
# /api/promotions
# ============================================================
class PromotionsContractTest(_ApiCase):
    def _seed_signal(self):
        rd = {"field": "uri", "operator": "contains", "value": "/health",
              "scope": "personal", "creator": "x", "enabled": True}
        for u in ("zhangsan", "zhangsan", "lisi", "lisi"):
            saudit.insert_rule_audit(u, "create", "temp_x", rd, source="manual")

    def call(self, payload, user="admin"):
        return _run(promotions.handle_promotions(_fake_request(), payload, user))

    def test_non_admin_forbidden(self):
        r = self.call({"action": "list"}, user="zhangsan")
        self.assertEqual(r.code, 403)

    def test_list_then_ack_suppresses(self):
        self._seed_signal()
        lst = self.call({"action": "list"})
        self.assertEqual(lst.code, 0)
        self.assertGreaterEqual(lst.data["total"], 1)
        fp = lst.data["items"][0]["fingerprint"]
        self.assertEqual(self.call({"action": "ack", "fingerprint": fp}).code, 0)
        after = self.call({"action": "list"})
        self.assertEqual(after.data["total"], 0)


# ============================================================
# 统一错误处理
# ============================================================
class ErrorHandlingTest(_ApiCase):
    def test_db_error_returns_500_with_unified_msg(self):
        """数据库故障应被统一收敛为 code=500 + 「数据库错误」口径"""
        self.conn.execute("DROP TABLE modsec_alerts")
        self.conn.commit()
        r = _run(alerts.handle_alerts(_fake_request(), {"action": "list"}, "admin"))
        self.assertEqual(r.code, 500)
        self.assertTrue(r.msg.startswith("数据库错误"), r.msg)


# ============================================================
# 参数校验
# ============================================================
class ValidationContractTest(_ApiCase):
    def _payload(self, value):
        return {
            "action": "create", "field": "src_ip", "operator": "exact", "value": value,
            "scope": "personal", "reason": "r",
            "expire_at": (datetime.now() + timedelta(hours=1)).isoformat(),
        }

    def test_valid_cidr_accepted(self):
        rules.RuleCreateRequest(**self._payload("10.0.0.0/8"))  # 不抛异常即通过

    def test_invalid_cidr_rejected_and_mapped_to_400(self):
        from pydantic import ValidationError
        with self.assertRaises(ValidationError) as ctx:
            rules.RuleCreateRequest(**self._payload("10.0.0.0/99"))
        resp = validation_error(ctx.exception)
        self.assertEqual(resp.code, 400)
        self.assertIn("参数校验失败", resp.msg)
        self.assertIn("CIDR", resp.msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
