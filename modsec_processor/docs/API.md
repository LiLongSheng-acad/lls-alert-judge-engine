# API 接口文档

## 概述

- **基础路径**：`/api`
- **认证方式**：HTTP Basic Auth
- **请求方法**：所有业务接口均为 `POST`
- **统一返回格式**：

```json
{
  "code": 0,
  "msg": "success",
  "data": { ... }
}
code = 0 表示成功，其他值表示错误

msg 为提示信息

data 为返回数据

一、告警接口 (/api/alerts)
1. 查询告警列表
json
POST /api/alerts

{
  "action": "list",
  "page": 1,
  "size": 25,
  "ignore_filters": false,   // true=调查模式，跳过所有过滤
  "aggregate": true,          // true=聚合模式
  "time_from": "2026-08-20 00:00:00",
  "time_to": "2026-08-31 23:59:59",
  "filters": {
    "src_ip": "127.0.0.1",
    "dst_ip": "192.168.1.1",
    "attack_type": "XSS",
    "severity": "CRITICAL"
  }
}
聚合模式返回示例：

json
{
  "code": 0,
  "msg": "success",
  "data": {
    "total": 1,
    "page": 1,
    "size": 25,
    "aggregated": true,
    "items": [{
      "fingerprint": "127.0.0.1|10.0.0.1|XSS|/test",
      "src_ip": "127.0.0.1",
      "dest_ip": "10.0.0.1",
      "uri": "/test",
      "attack_type": "XSS",
      "severity": "CRITICAL",
      "count": 12,
      "max_priority_score": 20800.0,
      "first_log_time": "2026-08-30 21:45:16",
      "last_log_time": "2026-08-30 21:48:49",
      "sample_alert_id": "A20260830000011"
    }]
  }
}
明细模式返回示例：

json
{
  "code": 0,
  "msg": "success",
  "data": {
    "total": 168,
    "page": 1,
    "size": 25,
    "aggregated": false,
    "items": [{
      "alert_id": "A20260830000011",
      "src_ip": "127.0.0.1",
      "dest_ip": "10.0.0.1",
      "uri": "/test",
      "method": "POST",
      "attack_type": "XSS",
      "severity": "CRITICAL",
      "priority_score": 20800.0,
      "is_blocked": 0,
      "log_time": "2026-08-30 21:48:49"
    }]
  }
}
2. 获取告警详情
json
POST /api/alerts

{
  "action": "detail",
  "alert_id": "A20260830000011"
}
3. 获取统计概览
json
POST /api/alerts

{
  "action": "stats"
}
返回示例：

json
{
  "code": 0,
  "msg": "success",
  "data": {
    "total": 168,
    "today": 33,
    "top_attack_types": [
      {"attack_type": "XSS", "count": 45},
      {"attack_type": "SQLI", "count": 23}
    ]
  }
}
二、规则管理 (/api/rules)
1. 查询规则列表
json
POST /api/rules

{
  "action": "list",
  "page": 1,
  "size": 20
}
2. 创建规则
json
POST /api/rules

{
  "action": "create",
  "field": "uri",           // uri | src_ip | user_agent | method | attack_type
  "operator": "contains",   // contains | startswith | endswith | exact | regex
  "value": "/health",
  "scope": "personal",      // personal | global
  "reason": "健康检查误报",
  "expire_at": "2026-08-31T10:00:00"
}
⚠️ expire_at 必须在当前时间的 24 小时内（个人规则限制）。

3. 删除规则
json
POST /api/rules

{
  "action": "delete",
  "rule_id": "rule_20260901025704_eff2eb"
}
4. 启用/禁用规则
json
POST /api/rules

{
  "action": "toggle",
  "rule_id": "rule_20260901025704_eff2eb",
  "enabled": true
}
三、资产管理 (/api/assets)
1. 查询资产列表
json
POST /api/assets

{
  "action": "list",
  "page": 1,
  "size": 20
}
2. 创建资产（仅 admin）
json
POST /api/assets

{
  "action": "create",
  "identifier": "10.8.0.1",
  "name": "核心数据库",
  "base_weight": 5.0,
  "temp_weight": null,
  "temp_expire_at": null,
  "owner": "张三",
  "remark": "生产环境",
  "enabled": true
}
3. 更新资产（仅 admin）
json
POST /api/assets

{
  "action": "update",
  "asset_id": "asset_20260901025704_eff2eb",
  "base_weight": 3.0,
  "owner": "李四"
}
4. 删除资产（仅 admin）
json
POST /api/assets

{
  "action": "delete",
  "asset_id": "asset_20260901025704_eff2eb"
}
5. 获取单条资产详情
json
POST /api/assets

{
  "action": "detail",
  "asset_id": "asset_20260901025704_eff2eb"
}
四、动作接口 (/api/actions)
1. 沉底操作
json
POST /api/actions/sink

{
  "action": "sink",
  "alert_id": "A20260830000011",
  "mode": "single",          // single | ip_temp
  "reason": "确认攻击",
  "create_rule": false       // 是否同步到临时规则（24小时）
}
2. 批量沉底
json
POST /api/actions/batch

{
  "action": "batch_sink",
  "alert_ids": ["A20260830000011", "A20260830000012"],
  "reason": "批量沉底"
}
3. 聚合沉底
json
POST /api/actions/aggregate_sink

{
  "src_ip": "127.0.0.1",
  "attack_type": "XSS",
  "uri": "/test",
  "reason": "聚合沉底"
}
4. IP批量沉底
json
POST /api/actions/ip_sink

{
  "src_ip": "127.0.0.1",
  "reason": "确认攻击源",
  "create_rule": true
}
五、审计接口 (/api/audit)
查询审计日志
json
POST /api/audit/rules

{
  "action": "list",
  "page": 1,
  "size": 20,
  "filter_action": "create"   // create | delete | enable | disable | sink
}
通用错误码
错误码	说明
0	成功
400	请求参数错误
401	认证失败
403	权限不足
404	资源不存在
500	服务器内部错误
