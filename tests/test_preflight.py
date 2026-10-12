#!/usr/bin/env python3
"""
启动自检（lib/preflight.py）的单元测试。

覆盖：api / collector 两个角色的目录、权限、关键配置校验，
以及致命项（errors）与非致命项（warnings）的区分。

运行： python tests/test_preflight.py
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings as S
from lib import preflight


class PreflightTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.root = root
        for d in ("logs", "config", "static", "remote"):
            (root / d).mkdir()

        self._orig = {}

        def pat(name, val):
            self._orig[name] = getattr(S, name)
            setattr(S, name, val)

        pat("LOG_DIR", root / "logs")
        pat("CONFIG_DIR", root / "config")
        pat("STATIC_DIR", root / "static")
        pat("DB_PATH", root / "logs" / "t.db")
        pat("SINK_RULES_FILE", root / "config" / "sink_rules.json")
        pat("FINANCIAL_FACTORS_FILE", root / "config" / "financial_factors.yaml")
        pat("OFFSET_FILE", root / "logs" / "offset.txt")
        pat("SYSLOG_DIR", root / "remote")

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(S, k, v)
        self.tmp.cleanup()

    def _write_rules(self, text='{"rules": []}'):
        (self.root / "config" / "sink_rules.json").write_text(text, encoding="utf-8")

    # ---- 用例 ----
    def test_api_ok(self):
        self._write_rules()
        errors, warnings = preflight.run_preflight("api")
        self.assertEqual(errors, [], errors)

    def test_api_missing_static_dir(self):
        self._write_rules()
        os.rmdir(self.root / "static")
        errors, _ = preflight.run_preflight("api")
        self.assertTrue(any("静态目录" in e for e in errors), errors)

    def test_malformed_rules_json_is_error(self):
        self._write_rules("{ not json")
        errors, _ = preflight.run_preflight("api")
        self.assertTrue(any("合法 JSON" in e for e in errors), errors)

    def test_missing_rules_file_is_warning(self):
        errors, warnings = preflight.run_preflight("api")
        self.assertEqual(errors, [], errors)
        self.assertTrue(any("不存在" in w for w in warnings), warnings)

    def test_collector_missing_factors_is_error(self):
        self._write_rules()
        errors, _ = preflight.run_preflight("collector")
        self.assertTrue(any("评分配置" in e for e in errors), errors)

    def test_collector_ok(self):
        self._write_rules()
        (self.root / "config" / "financial_factors.yaml").write_text("base_asset_value: 10000\n", encoding="utf-8")
        errors, warnings = preflight.run_preflight("collector")
        self.assertEqual(errors, [], errors)

    def test_assert_preflight_raises_on_error(self):
        os.rmdir(self.root / "static")
        with self.assertRaises(RuntimeError):
            preflight.assert_preflight("api")


if __name__ == "__main__":
    unittest.main(verbosity=2)
