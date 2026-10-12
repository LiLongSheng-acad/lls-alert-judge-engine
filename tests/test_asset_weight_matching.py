#!/usr/bin/env python3
"""
资产权重 → 优先级分数 的回归测试（入库时按「目的 IP」匹配）。

核心：权重按告警的「目的 IP / Host」（被攻击目标）匹配，而非源 IP（攻击者）——
      这决定了「哪些告警会被赋予资产权重」。分数在入库时算定，不回溯历史。

隔离：临时配置目录，不触碰真实 config/assets.json。

运行： python tests/test_asset_weight_matching.py
"""
import os
import sys
import json
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import scorer as scorer_mod
from engine.scorer import Scorer, normalize_host


def _schema(dest_ip, attack_type="RCE", severity="CRITICAL"):
    return types.SimpleNamespace(dest_ip=dest_ip, attack_type=attack_type, severity=severity)


class _Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Path(self.tmp.name) / "config"
        self.cfg.mkdir(parents=True)
        self._orig = scorer_mod.CONFIG_DIR
        scorer_mod.CONFIG_DIR = self.cfg

    def tearDown(self):
        scorer_mod.CONFIG_DIR = self._orig
        self.tmp.cleanup()

    def write_assets(self, *assets):
        (self.cfg / "assets.json").write_text(
            json.dumps({"assets": list(assets)}, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def expected(weight):
        """按评分公式独立算出期望分数（RCE/CRITICAL）。"""
        s = Scorer()
        base = float(s.config.get("base_asset_value", 100000))
        hazard = s._get_hazard_index("RCE", "CRITICAL")
        cost = s._get_cost_per_alert()
        return round(base * weight * hazard / cost, 2)


class DestIpMatchingTest(_Case):
    def test_weight_applied_by_dest_ip(self):
        self.write_assets({"id": "a1", "identifier": "10.8.0.1", "base_weight": 2.0, "enabled": True})
        self.assertEqual(Scorer().compute(_schema("10.8.0.1")), self.expected(2.0))

    def test_source_ip_is_ignored(self):
        # 资产标识恰好等于攻击者 IP；目的 IP 不同 → 不套用权重
        # （回归：早期版本用源 IP 匹配资产，导致「改权重完全没效果」）
        self.write_assets({"id": "a1", "identifier": "203.0.113.9", "base_weight": 5.0, "enabled": True})
        self.assertEqual(Scorer().compute(_schema("8.8.8.8")), self.expected(1.0))

    def test_host_with_port_is_normalized(self):
        self.write_assets({"id": "a1", "identifier": "10.8.0.1", "base_weight": 2.0, "enabled": True})
        self.assertEqual(Scorer().compute(_schema("10.8.0.1:8080")), self.expected(2.0))

    def test_cidr_identifier(self):
        self.write_assets({"id": "a1", "identifier": "10.0.0.0/8", "base_weight": 3.0, "enabled": True})
        self.assertEqual(Scorer().compute(_schema("10.1.2.3")), self.expected(3.0))

    def test_domain_identifier(self):
        self.write_assets({"id": "a1", "identifier": "supplier.com", "base_weight": 4.0, "enabled": True})
        self.assertEqual(Scorer().compute(_schema("api.supplier.com")), self.expected(4.0))

    def test_disabled_asset_is_ignored(self):
        self.write_assets({"id": "a1", "identifier": "10.8.0.1", "base_weight": 2.0, "enabled": False})
        self.assertEqual(Scorer().compute(_schema("10.8.0.1")), self.expected(1.0))

    def test_exact_match_beats_cidr(self):
        self.write_assets(
            {"id": "cidr", "identifier": "10.0.0.0/8", "base_weight": 3.0, "enabled": True},
            {"id": "exact", "identifier": "10.8.0.1", "base_weight": 2.0, "enabled": True},
        )
        self.assertEqual(Scorer().compute(_schema("10.8.0.1")), self.expected(2.0))

    def test_no_asset_uses_default_weight(self):
        self.assertEqual(Scorer().compute(_schema("1.2.3.4")), self.expected(1.0))


class NormalizeHostTest(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(normalize_host("Example.COM"), "example.com")
        self.assertEqual(normalize_host("10.8.0.1:8080"), "10.8.0.1")
        self.assertEqual(normalize_host(" 10.8.0.1 "), "10.8.0.1")
        self.assertEqual(normalize_host("[::1]:8000"), "[::1]")
        self.assertEqual(normalize_host(""), "")
        self.assertEqual(normalize_host(None), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
