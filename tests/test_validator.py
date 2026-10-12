#!/usr/bin/env python3
"""
输入校验（lib/validator.py）的单元测试。

重点：validate_and_clean **不再删除**输入子串（如 -- / SQL 关键字 / <script>），
      否则会破坏「规则值本身就是攻击载荷」这类合法用法。

运行： python tests/test_validator.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.validator import InputValidator


class ValidateAndCleanTest(unittest.TestCase):
    def test_no_substring_deletion(self):
        """--、SQL 关键字、<script> 都应原样保留"""
        raw = {
            "value": "' OR 1=1--",
            "reason": "UNION SELECT test",
            "uri": "/x?q=<script>alert(1)</script>",
        }
        rules = {"value": "str", "reason": "str", "uri": "str"}
        out = InputValidator.validate_and_clean(raw, rules)
        self.assertEqual(out["value"], "' OR 1=1--")
        self.assertEqual(out["reason"], "UNION SELECT test")
        self.assertEqual(out["uri"], "/x?q=<script>alert(1)</script>")

    def test_none_preserved(self):
        out = InputValidator.validate_and_clean({"value": None}, {"value": "str"})
        self.assertIsNone(out["value"])

    def test_type_coercion(self):
        raw = {"page": "3", "size": "x", "flag": "yes", "ratio": "1.5"}
        rules = {"page": "int", "size": "int", "flag": "bool", "ratio": "float"}
        out = InputValidator.validate_and_clean(raw, rules)
        self.assertEqual(out["page"], 3)
        self.assertEqual(out["size"], 0)          # 非法 int -> 0
        self.assertTrue(out["flag"])
        self.assertEqual(out["ratio"], 1.5)

    def test_unknown_key_passthrough(self):
        out = InputValidator.validate_and_clean({"other": "keep"}, {"value": "str"})
        self.assertEqual(out["other"], "keep")


class ValidateIpTest(unittest.TestCase):
    def test_valid_ip(self):
        self.assertEqual(InputValidator.validate_ip("10.0.0.1"), "10.0.0.1")
        self.assertEqual(InputValidator.validate_ip("::1"), "::1")

    def test_invalid_ip_returns_empty(self):
        self.assertEqual(InputValidator.validate_ip("not-an-ip"), "")
        self.assertEqual(InputValidator.validate_ip(""), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
