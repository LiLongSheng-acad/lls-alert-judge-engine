#!/usr/bin/env python3
"""
scorer.py - 优先级评分引擎（金钱驱动模型）

核心公式：
    优先级分数 = (资产价值 × 攻击危害指数) / 单条告警处置成本

资产价值 = base_asset_value × weight
    - base_asset_value: 从配置文件读取，默认 100000
    - weight: 用户通过 Web 配置的资产权重，未配置则使用 default_weight
"""
import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml
import ipaddress
import logging
from typing import Dict, Any, Optional, List, Tuple, Union

from config.settings import FINANCIAL_FACTORS_FILE

logger = logging.getLogger(__name__)


class Scorer:
    """基于金钱驱动模型的评分引擎"""

    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = str(FINANCIAL_FACTORS_FILE)

        self.config_path = config_path
        self.config = self._load_config(config_path)
        # 编译攻击危害指数矩阵
        self._compile_hazard_matrix()
        self._log_config_summary()

    # ==================== 配置加载 ====================

    def _load_config(self, path: str) -> Dict:
        default_config = {
            "attack_hazard": {"DEFAULT": {"DEFAULT": 0.5}},
            "base_asset_value": 100000,
            "default_weight": 1.0,
            "labor_cost": {"monthly_salary": 20000, "hours_per_month": 160, "minutes_per_alert": 15},
            "ignore_threshold": 0.01,
            "max_score": 1000000,
        }
        try:
            with open(path, 'r') as f:
                config = yaml.safe_load(f)
                if not config:
                    logger.warning(f"配置文件 {path} 为空，使用默认配置")
                    return default_config
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
        except FileNotFoundError:
            logger.warning(f"配置文件 {path} 不存在，使用默认配置")
            return default_config
        except yaml.YAMLError as e:
            logger.error(f"YAML 解析失败: {e}，使用默认配置")
            return default_config

    # ==================== 规则编译 ====================

    def _compile_hazard_matrix(self):
        hazard_config = self.config.get("attack_hazard", {})
        self.hazard_matrix: Dict[str, Dict[str, float]] = {}
        for attack_type, severity_map in hazard_config.items():
            if attack_type == "DEFAULT":
                continue
            if isinstance(severity_map, dict):
                self.hazard_matrix[attack_type.upper()] = {
                    k.upper(): float(v) for k, v in severity_map.items()
                }
            else:
                self.hazard_matrix[attack_type.upper()] = {"DEFAULT": float(severity_map)}
        default_config = hazard_config.get("DEFAULT", {})
        if isinstance(default_config, dict):
            self.default_hazard = {k.upper(): float(v) for k, v in default_config.items()}
        else:
            self.default_hazard = {"DEFAULT": float(default_config) if default_config else 0.5}
        logger.info(f"加载了 {len(self.hazard_matrix)} 种攻击类型的危害指数配置")

    def _log_config_summary(self):
        labor = self.config.get("labor_cost", {})
        logger.info(f"人力成本: 月薪{labor.get('monthly_salary', 20000)}元, "
                    f"月工时{labor.get('hours_per_month', 160)}小时, "
                    f"平均处理{labor.get('minutes_per_alert', 15)}分钟/条")
        logger.info(f"忽略阈值: {self.config.get('ignore_threshold', 0.01)}, "
                    f"最大分数: {self.config.get('max_score', 1000000)}")
        logger.info(f"基础资产价值: {self.config.get('base_asset_value', 100000)}, "
                    f"默认权重: {self.config.get('default_weight', 1.0)}")

    # ==================== 核心计算 ====================

    def compute(self, schema) -> float:
        asset_value = self._get_asset_value(schema.src_ip)
        hazard_index = self._get_hazard_index(schema.attack_type, schema.severity)
        potential_loss = asset_value * hazard_index
        cost_per_alert = self._get_cost_per_alert()
        if potential_loss <= 0 or cost_per_alert <= 0:
            return 0.0
        score = potential_loss / cost_per_alert
        threshold = self.config.get("ignore_threshold", 0.01)
        if score < threshold:
            return 0.0
        max_score = self.config.get("max_score", 1000000)
        return round(min(score, max_score), 2)

    # ==================== 辅助方法 ====================

    def _load_assets(self) -> List[Dict]:
        """从 assets.json 加载用户配置的资产"""
        assets_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "assets.json")
        if not os.path.exists(assets_file):
            logger.debug("assets.json 不存在")
            return []
        try:
            with open(assets_file, 'r') as f:
                data = json.load(f)
                assets = data.get('assets', [])
                logger.debug(f"加载了 {len(assets)} 条资产配置")
                return assets
        except Exception as e:
            logger.warning(f"加载资产失败: {e}")
            return []

    def _match_asset(self, src_ip: str, assets: List[Dict]) -> Optional[Dict]:
        """
        匹配资产配置
        优先级：精确匹配 > CIDR匹配 > 域名匹配
        """
        if not src_ip or not assets:
            return None

        # 1. 精确匹配
        for asset in assets:
            if not asset.get('enabled', True):
                continue
            if asset.get('identifier') == src_ip:
                return asset

        # 2. CIDR 匹配
        try:
            ip_obj = ipaddress.ip_address(src_ip)
            for asset in assets:
                if not asset.get('enabled', True):
                    continue
                identifier = asset.get('identifier', '')
                try:
                    network = ipaddress.ip_network(identifier, strict=False)
                    if ip_obj in network:
                        return asset
                except:
                    continue
        except:
            pass

        # 3. 域名匹配（简单后缀）
        for asset in assets:
            if not asset.get('enabled', True):
                continue
            identifier = asset.get('identifier', '')
            if '.' in identifier and identifier in src_ip:
                return asset

        return None

    def _get_asset_value(self, src_ip: str) -> float:
        """
        计算资产价值 = base_asset_value × weight
        weight 优先使用用户配置的资产权重，否则使用 default_weight
        """
        base_value = float(self.config.get("base_asset_value", 100000))

        assets = self._load_assets()
        matched = self._match_asset(src_ip, assets)
        if matched:
            weight = matched.get('base_weight', 1.0)
            # 检查临时权重
            temp_weight = matched.get('temp_weight')
            temp_expire_at = matched.get('temp_expire_at')
            if temp_weight is not None and temp_expire_at:
                try:
                    if datetime.fromisoformat(temp_expire_at) > datetime.now():
                        weight = temp_weight
                except:
                    pass
        else:
            weight = self.config.get("default_weight", 1.0)

        return base_value * float(weight)

    def _get_hazard_index(self, attack_type: str, severity: str) -> float:
        attack_key = attack_type.upper() if attack_type else "UNKNOWN"
        severity_key = severity.upper() if severity else "INFO"

        if attack_key in self.hazard_matrix:
            if severity_key in self.hazard_matrix[attack_key]:
                return self.hazard_matrix[attack_key][severity_key]
            if "DEFAULT" in self.hazard_matrix[attack_key]:
                return self.hazard_matrix[attack_key]["DEFAULT"]

        if severity_key in self.default_hazard:
            return self.default_hazard[severity_key]

        return self.default_hazard.get("DEFAULT", 0.5)

    def _get_cost_per_alert(self) -> float:
        labor = self.config.get("labor_cost", {})
        monthly_salary = float(labor.get("monthly_salary", 20000))
        hours_per_month = float(labor.get("hours_per_month", 160))
        minutes_per_alert = float(labor.get("minutes_per_alert", 15))
        if hours_per_month <= 0:
            return 0.0
        hourly_rate = monthly_salary / hours_per_month
        return hourly_rate * (minutes_per_alert / 60)

    # ==================== 调试与统计 ====================

    def explain_score(self, schema) -> Dict[str, Any]:
        asset_value = self._get_asset_value(schema.src_ip)
        hazard_index = self._get_hazard_index(schema.attack_type, schema.severity)
        potential_loss = asset_value * hazard_index
        cost_per_alert = self._get_cost_per_alert()
        raw_score = potential_loss / cost_per_alert if cost_per_alert > 0 else 0
        threshold = self.config.get("ignore_threshold", 0.01)
        max_score = self.config.get("max_score", 1000000)
        final_score = max(raw_score, 0)
        is_ignored = raw_score < threshold
        if not is_ignored:
            final_score = min(final_score, max_score)
        return {
            "asset_value": round(asset_value, 2),
            "attack_type": schema.attack_type,
            "severity": schema.severity,
            "hazard_index": round(hazard_index, 4),
            "potential_loss": round(potential_loss, 2),
            "cost_per_alert": round(cost_per_alert, 2),
            "raw_score": round(raw_score, 2),
            "ignore_threshold": threshold,
            "max_score": max_score,
            "final_score": round(final_score, 2),
            "is_ignored": is_ignored,
        }

    def get_hazard_matrix(self) -> Dict[str, Dict[str, float]]:
        return self.hazard_matrix

    def reload_config(self):
        logger.info("正在重新加载配置文件...")
        self.config = self._load_config(self.config_path)
        self._compile_hazard_matrix()
        self._log_config_summary()
        logger.info("配置重载完成")



'''
# ==================== 独立测试 ====================
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

    class MockSchema:
        def __init__(self, src_ip: str, attack_type: str, severity: str):
            self.src_ip = src_ip
            self.attack_type = attack_type
            self.severity = severity

    scorer = Scorer()
    test_cases = [
        ("1.2.3.4", "XSS", "CRITICAL", "公网 IP，未配置资产，默认权重"),
        ("10.8.0.1", "XSS", "CRITICAL", "配置了权重 1.7 的 10.8.0.1"),
        ("127.0.0.1", "XSS", "CRITICAL", "本机 IP，未配置资产，默认权重"),
    ]
    print("\n" + "=" * 80)
    print("评分引擎测试（统一资产价值模型）")
    print("=" * 80)
    for src_ip, attack_type, severity, desc in test_cases:
        schema = MockSchema(src_ip, attack_type, severity)
        score = scorer.compute(schema)
        exp = scorer.explain_score(schema)
        print(f"\n📌 {desc}")
        print(f"   攻击类型: {attack_type} | 严重等级: {severity}")
        print(f"   资产价值: {exp['asset_value']:,.0f} 元")
        print(f"   优先级分数: {score}")
    print("\n" + "=" * 80)
'''