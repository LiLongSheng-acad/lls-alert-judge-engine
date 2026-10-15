#!/usr/bin/env python3
"""
scorer.py - 优先级评分引擎（金钱驱动模型）

核心公式：
    优先级分数 = 单次漏洞损失(元) × 目标权重

    - 单次漏洞损失：查配置 attack_loss 表（攻击类型 × 等级 → 元）
    - 目标权重：仅表达系统重要性，约定在 0.5 ~ 3 之间小幅摆动；
      按「目的 IP / Host」（dest_ip）匹配，未配置则用 default_weight

红线：优先级 < red_line → 「看了就亏」——可以不看，但告警照常入库、照常展示（仅标绿）
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

from config.settings import FINANCIAL_FACTORS_FILE, CONFIG_DIR

logger = logging.getLogger(__name__)


def normalize_host(value: str) -> str:
    """归一化 Host / 目标标识：去空白、转小写、去掉端口。

    Host 头可能形如 ``10.8.0.1:8080``、``Example.COM`` 或 IPv6 字面量 ``[::1]:80``。
    """
    if not value:
        return ""
    host = str(value).strip().lower()
    if host.startswith("["):  # IPv6 字面量 [::1]:8080
        end = host.find("]")
        if end != -1:
            return host[:end + 1]
        return host
    if host.count(":") == 1:  # host:port（IPv6 非字面量含多个冒号，不在此处理）
        return host.split(":", 1)[0]
    return host


def load_red_line() -> float:
    """独立读取红线（供读取层归类用）；文件缺失/非法时回退 30。

    读取层用它把「潜在损失 < 红线」的告警标记为「看了就亏」——
    分数本身照实存盘，因此调整红线不会改写历史。
    """
    try:
        with open(str(FINANCIAL_FACTORS_FILE), 'r') as f:
            cfg = yaml.safe_load(f) or {}
        return float(cfg.get("red_line", 30))
    except Exception:
        return 30.0


def load_loss_table_keys() -> set:
    """独立读取损失表里已配置的攻击类型（供读取层识别「未分类类型」）。

    每次调用都重新读取文件，因此甲方改完 yaml 立即生效，无需重启。
    """
    try:
        with open(str(FINANCIAL_FACTORS_FILE), 'r') as f:
            cfg = yaml.safe_load(f) or {}
        table = cfg.get("attack_loss", {}) or {}
        return {str(k).upper() for k in table.keys() if str(k).upper() != "DEFAULT"}
    except Exception:
        return set()


class Scorer:
    """基于金钱驱动模型的评分引擎"""

    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = str(FINANCIAL_FACTORS_FILE)

        self.config_path = config_path
        self.config = self._load_config(config_path)
        self._config_mtime = self._get_mtime()
        # 编译单次损失表
        self._compile_loss_table()
        self._log_config_summary()

    # ==================== 配置加载 ====================

    def _load_config(self, path: str) -> Dict:
        default_config = {
            "attack_loss": {"DEFAULT": {"DEFAULT": 0.5}},
            "default_weight": 1.0,
            "labor_cost": {"monthly_salary": 20000, "hours_per_month": 160, "minutes_per_alert": 15},
            "red_line": 30,
            "max_score": 10000000,
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

    # ==================== 热加载 ====================

    def _get_mtime(self) -> float:
        try:
            return os.path.getmtime(self.config_path)
        except OSError:
            return 0.0

    def _maybe_reload(self):
        """配置文件被改动时自动重载（改 yaml 后无需重启服务）。"""
        mtime = self._get_mtime()
        if mtime and mtime != self._config_mtime:
            self.config = self._load_config(self.config_path)
            self._compile_loss_table()
            self._config_mtime = mtime
            logger.info(f"评分配置已热加载: {self.config_path}")

    # ==================== 规则编译 ====================

    def _compile_loss_table(self):
        loss_config = self.config.get("attack_loss", {})
        self.loss_table: Dict[str, Dict[str, float]] = {}
        for attack_type, severity_map in loss_config.items():
            if attack_type == "DEFAULT":
                continue
            if isinstance(severity_map, dict):
                self.loss_table[attack_type.upper()] = {
                    k.upper(): float(v) for k, v in severity_map.items()
                }
            else:
                self.loss_table[attack_type.upper()] = {"DEFAULT": float(severity_map)}
        default_config = loss_config.get("DEFAULT", {})
        if isinstance(default_config, dict):
            self.default_loss = {k.upper(): float(v) for k, v in default_config.items()}
        else:
            self.default_loss = {"DEFAULT": float(default_config) if default_config else 0.5}
        logger.info(f"加载了 {len(self.loss_table)} 种攻击类型的单次损失配置")

    def _log_config_summary(self):
        labor = self.config.get("labor_cost", {})
        logger.info(f"人力成本: 月薪{labor.get('monthly_salary', 20000)}元, "
                    f"月工时{labor.get('hours_per_month', 160)}小时, "
                    f"平均处理{labor.get('minutes_per_alert', 15)}分钟/条")
        logger.info(f"红线(看了就亏): {self._get_red_line()}, "
                    f"最大分数: {self.config.get('max_score', 10000000)}")
        logger.info(f"默认权重: {self.config.get('default_weight', 1.0)}")

    # ==================== 核心计算 ====================

    def compute(self, schema) -> float:
        """计算优先级分数 = 单次漏洞损失(元) × 目标权重（入库时算定）。

        是否「看了就亏」由读取层用红线比对（见 load_red_line），
        因此分数入库即定，事后调整红线不会改写历史分数。
        """
        self._maybe_reload()
        loss = self._get_loss(schema.attack_type, schema.severity)
        weight = self._get_target_weight(getattr(schema, "dest_ip", ""))
        score = loss * weight
        if score <= 0:
            return 0.0
        max_score = self.config.get("max_score", 10000000)
        return round(min(score, max_score), 2)

    # ==================== 辅助方法 ====================

    def _load_assets(self) -> List[Dict]:
        """从 assets.json 加载用户配置的资产"""
        assets_file = os.path.join(str(CONFIG_DIR), "assets.json")
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

    def _match_asset(self, host: str, assets: List[Dict]) -> Optional[Dict]:
        """
        按目标主机匹配资产配置
        优先级：精确匹配 > CIDR匹配 > 域名匹配
        """
        target = normalize_host(host)
        if not target or not assets:
            return None

        # 1. 精确匹配
        for asset in assets:
            if not asset.get('enabled', True):
                continue
            if normalize_host(asset.get('identifier', '')) == target:
                return asset

        # 2. CIDR 匹配
        try:
            ip_obj = ipaddress.ip_address(target)
            for asset in assets:
                if not asset.get('enabled', True):
                    continue
                identifier = asset.get('identifier', '')
                try:
                    network = ipaddress.ip_network(identifier, strict=False)
                    if ip_obj in network:
                        return asset
                except ValueError:
                    continue
        except ValueError:
            pass

        # 3. 域名匹配（简单后缀）
        for asset in assets:
            if not asset.get('enabled', True):
                continue
            identifier = normalize_host(asset.get('identifier', ''))
            if '.' in identifier and identifier in target:
                return asset

        return None

    def _get_target_weight(self, host: str) -> float:
        """目标权重：仅表达系统重要性（临时权重在有效期内优先）；未匹配则用 default_weight。"""
        assets = self._load_assets()
        matched = self._match_asset(host, assets)
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

        return float(weight)

    def _get_loss(self, attack_type: str, severity: str) -> float:
        """单次漏洞损失(元)：二维查表，两级兜底（类型 DEFAULT → 全局 DEFAULT）。"""
        attack_key = attack_type.upper() if attack_type else "UNKNOWN"
        severity_key = severity.upper() if severity else "INFO"

        if attack_key in self.loss_table:
            if severity_key in self.loss_table[attack_key]:
                return self.loss_table[attack_key][severity_key]
            if "DEFAULT" in self.loss_table[attack_key]:
                return self.loss_table[attack_key]["DEFAULT"]

        if severity_key in self.default_loss:
            return self.default_loss[severity_key]

        return self.default_loss.get("DEFAULT", 0.5)

    def _get_cost_per_alert(self) -> float:
        labor = self.config.get("labor_cost", {})
        monthly_salary = float(labor.get("monthly_salary", 20000))
        hours_per_month = float(labor.get("hours_per_month", 160))
        minutes_per_alert = float(labor.get("minutes_per_alert", 15))
        if hours_per_month <= 0:
            return 0.0
        hourly_rate = monthly_salary / hours_per_month
        return hourly_rate * (minutes_per_alert / 60)

    def _get_red_line(self) -> float:
        """红线：优先级(潜在损失) 低于该值视为「看了就亏」；缺省 30，可按现场调整。"""
        try:
            return float(self.config.get("red_line", 30))
        except (TypeError, ValueError):
            return 30.0

    # ==================== 调试与统计 ====================

    def explain_score(self, schema) -> Dict[str, Any]:
        loss = self._get_loss(schema.attack_type, schema.severity)
        weight = self._get_target_weight(getattr(schema, "dest_ip", ""))
        score = loss * weight
        max_score = self.config.get("max_score", 10000000)
        final_score = round(min(max(score, 0), max_score), 2)
        red_line = self._get_red_line()
        return {
            "attack_type": schema.attack_type,
            "severity": schema.severity,
            "loss": round(loss, 2),
            "target_weight": round(weight, 3),
            "score": round(score, 2),
            "cost_per_alert": round(self._get_cost_per_alert(), 2),
            "red_line": red_line,
            "below_red_line": score < red_line,
            "max_score": max_score,
            "final_score": final_score,
        }

    def get_loss_table(self) -> Dict[str, Dict[str, float]]:
        return self.loss_table

    def reload_config(self):
        logger.info("正在重新加载配置文件...")
        self.config = self._load_config(self.config_path)
        self._compile_loss_table()
        self._log_config_summary()
        logger.info("配置重载完成")



'''
# ==================== 独立测试 ====================
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

    class MockSchema:
        def __init__(self, dest_ip: str, attack_type: str, severity: str):
            self.dest_ip = dest_ip
            self.attack_type = attack_type
            self.severity = severity

    scorer = Scorer()
    test_cases = [
        ("1.2.3.4", "XSS", "CRITICAL", "未配置资产的目标，默认权重"),
        ("10.8.0.1", "XSS", "CRITICAL", "配置了权重 2.0 的 10.8.0.1"),
        ("127.0.0.1", "XSS", "CRITICAL", "本机回环（测试环境）"),
    ]
    print("\n" + "=" * 80)
    print("评分引擎测试（统一资产价值模型，按目的 IP 匹配）")
    print("=" * 80)
    for dest_ip, attack_type, severity, desc in test_cases:
        schema = MockSchema(dest_ip, attack_type, severity)
        score = scorer.compute(schema)
        exp = scorer.explain_score(schema)
        print(f"\n📌 {desc}")
        print(f"   攻击类型: {attack_type} | 严重等级: {severity}")
        print(f"   资产价值: {exp['asset_value']:,.0f} 元")
        print(f"   优先级分数: {score}")
    print("\n" + "=" * 80)
'''