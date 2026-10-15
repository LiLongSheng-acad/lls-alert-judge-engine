# 部署与验证 Runbook

> 目标：把本项目部署到 Linux（推荐 Ubuntu 22.04 / 24.04）云服务器，并完成一次端到端验证。
> 适用版本：MVP 0.4.0。当前仅供功能验证，**请勿直接暴露公网**。

---

## 0. 前置条件

- 一台 Ubuntu 22.04 / 24.04，具备 `sudo`
- 安全组 / 防火墙放行：**8000**（Web/API）、**5514**（rsyslog 接收 WAF 日志）
- 本机已装 `rsync`（或可用 `scp`）

---

## A. 传输代码

本机可能没有 git、改动也未提交，因此**整包上传**，排除运行期产物：

```bash
# 在【本地】执行（替换 <user>@<server>）
rsync -av --exclude 'logs/' --exclude '__pycache__/' --exclude 'venv/' \
  ./lls-alert-judge-engine/ <user>@<server>:/tmp/lls-alert-judge-engine/
```

> 没有 rsync 时用 `scp -r ./lls-alert-judge-engine <user>@<server>:/tmp/`，再在服务器上删掉 `logs/`。

---

## B. 一键部署

```bash
# 在【服务器】执行
sudo mkdir -p /opt/lls-alert-judge-engine
sudo cp -r /tmp/lls-alert-judge-engine/. /opt/lls-alert-judge-engine/
cd /opt/lls-alert-judge-engine
sudo bash install.sh
```

`install.sh` 会完成：

1. 安装系统依赖（python3 / venv / apache2 / libapache2-mod-security2 / rsyslog / sqlite3 等）
2. 创建专用用户 `lls-alert-judge-engine`，并加入 **adm** 组（用于读取 rsyslog 日志）
3. 创建项目目录与 Python 虚拟环境，安装 [requirements.txt](../requirements.txt)
4. 配置 rsyslog（UDP/TCP 5514）与 ModSecurity 审计日志、日志轮转
5. 创建并启动两个 systemd 服务：`lls-alert-judge-engine-collector`、`lls-alert-judge-engine-api`

---

## C. 冒烟验证（先做这 4 条）

```bash
cd /opt/lls-alert-judge-engine

# 1) 单元测试（应 50 项全过）
sudo -u lls-alert-judge-engine venv/bin/python -m unittest discover -s tests -v

# 2) API 启动自检（应见「[Preflight] 启动自检（api）：通过」）
sudo journalctl -u lls-alert-judge-engine-api --no-pager | grep Preflight

# 3) 健康检查（应返回 {"status":"healthy"}）
curl -s http://127.0.0.1:8000/api/health

# 4) 采集器启动自检 + 是否有权限报错
sudo journalctl -u lls-alert-judge-engine-collector --no-pager | grep -E "Preflight|Permission|ERROR"
```

**取登录密码**（未设环境变量时，启动会随机生成并打印）：

```bash
sudo journalctl -u lls-alert-judge-engine-api | grep -A2 "临时密码"
```

浏览器访问：`http://<公网IP>:8000/static/index.html`，用户名 `admin`。

> 想固定密码：`sudo systemctl edit lls-alert-judge-engine-api`，加入
> `Environment=BASIC_AUTH_USERNAME=admin` 与 `Environment=BASIC_AUTH_PASSWORD=你的密码`，然后 `sudo systemctl restart lls-alert-judge-engine-api`。

---

## D. 采集链路验证（二选一）

### D1. 真实 WAF（推荐）

`install.sh` 已配好 Apache + ModSecurity。触发一次攻击：

```bash
curl "http://localhost/?q=<script>alert(1)</script>"
```

然后确认采集器日志与页面出现告警。

### D2. 无 WAF 时，用伪造日志

项目支持用环境变量覆盖日志目录，便于本地/服务器脱离 WAF 验证：

```bash
sudo mkdir -p /tmp/fakelog
printf '%s\n' '203.0.113.1 2026-10-04T10:00:00+08:00 localhost modsec {"transaction":{"time":"04/Oct/2026:10:00:00.000000 +0800","remote_address":"203.0.113.9"},"request":{"headers":{"Host":"x"},"request_line":"GET /a HTTP/1.1","body":[]},"response":{"status":200,"body":""},"audit_data":{"messages":["[id \"941100\"] [severity \"CRITICAL\"] [msg \"XSS\"] [tag \"attack-xss\"] Matched Data: <script>"]}}' \
  | sudo tee /tmp/fakelog/modsec_$(date +%F).log >/dev/null

sudo systemctl edit lls-alert-judge-engine-collector   # 加入：Environment=MODSEC_SYSLOG_DIR=/tmp/fakelog
sudo systemctl restart lls-alert-judge-engine-collector
```

相关环境变量：`MODSEC_SYSLOG_DIR`（日志源目录）、`MODSEC_OFFSET_FILE`（偏移量文件）。

---

## E. 功能点验证清单

- [ ] **启动自检**：两个服务日志均有 `[Preflight] … ：通过`
- [ ] **日志读取权限**：`sudo -u lls-alert-judge-engine test -r /var/log/remote/modsec_$(date +%F).log && echo OK`
- [ ] **偏移量落点**：`ls -l /opt/lls-alert-judge-engine/logs/lls-alert-judge-engine-offset.txt`（应在项目内，而非 `/opt`）
- [ ] **告警列表 / 聚合**：等级显示为 `CRITICAL`，不被 `MEDIUM` 覆盖
- [ ] **详情弹窗**：点「详情」→「🔎 关联该攻击 IP 的报文」可跳转、结果含已沉底
- [ ] **日报**：「📊 日报」默认当天，总/沉底/剩余三数正确
- [ ] **沉底**：单条沉底、勾选多条批量沉底均生效
- [ ] **CIDR 规则**：建 `src_ip = 10.0.0.0/8` 后同网段告警被隐去；填 `10.0.0.0/99` 应返回 **400**
- [ ] **升格通知**：切 admin，用两个用户名各建两次同名规则 → 出现候选；点「知晓」后 15 天内不再出现

---

## F. 可能踩的坑

1. **采集器读不到日志**（Permission denied）
   → `sudo usermod -aG adm lls-alert-judge-engine && sudo systemctl restart lls-alert-judge-engine-collector`
   说明：启动自检报「日志源目录不存在」只是 warning，属正常等待 rsyslog。
2. **密码每次重启都变**：见 C 节「想固定密码」。
3. **端口未放行**：8000 / 5514，注意云安全组与系统防火墙。
4. **`scripts/generate_test_data.py`**：要求 `modsec_alerts` 表已存在——先启动过一次采集器再运行它。
   （其 DB 路径硬编码为 `/opt/lls-alert-judge-engine/logs/lls-alert-judge-engine.db`，与部署路径一致。）

---

## G. 回滚 / 清理

```bash
sudo systemctl stop lls-alert-judge-engine-collector lls-alert-judge-engine-api
sudo systemctl disable lls-alert-judge-engine-collector lls-alert-judge-engine-api
sudo rm -f /etc/systemd/system/lls-alert-judge-engine-{collector,api}.service
sudo systemctl daemon-reload
```

配置备份（install.sh 已自动生成）：

- `/etc/modsecurity/modsecurity.conf.bak`
- `/etc/rsyslog.d/remote.conf.bak.<时间戳>`
