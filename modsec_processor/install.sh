#!/bin/bash
# ============================================================
# install.sh - 一键部署告警研判引擎
# 用法: sudo bash install.sh
# ============================================================

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_err() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ============================================================
# 0. 检查运行环境
# ============================================================

echo "============================================================"
echo "  告警研判引擎 - 一键部署脚本"
echo "============================================================"

if [ "$EUID" -ne 0 ]; then
    print_err "请使用 sudo 运行此脚本: sudo bash install.sh"
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ "$ID" != "ubuntu" ]] && [[ "$ID" != "debian" ]]; then
        print_warn "当前系统: $ID $VERSION_ID"
        print_warn "脚本主要为 Ubuntu 设计，其他系统可能需要额外配置"
    else
        print_ok "系统: $ID $VERSION_ID"
    fi
fi

PROJECT_DIR="/opt/modsec_processor"
SERVICE_USER="modsec"
SERVICE_GROUP="modsec"
RSYSLOG_PORT="5514"  # 改用 5514 端口（无需 root）

# ============================================================
# 1. 安装系统依赖
# ============================================================

echo ""
echo "[1/9] 安装系统依赖..."
apt update -qq
apt install -y -qq python3 python3-venv python3-pip apache2 \
    libapache2-mod-security2 rsyslog curl sqlite3 jq
print_ok "系统依赖安装完成"

# ============================================================
# 2. 创建专用用户
# ============================================================

echo ""
echo "[2/9] 创建专用用户 $SERVICE_USER..."
if id "$SERVICE_USER" &>/dev/null; then
    print_warn "用户 $SERVICE_USER 已存在，跳过创建"
else
    useradd -r -s /bin/false -d "$PROJECT_DIR" "$SERVICE_USER"
    print_ok "用户 $SERVICE_USER 创建完成"
fi

# ============================================================
# 3. 创建项目目录
# ============================================================

echo ""
echo "[3/9] 创建项目目录..."
mkdir -p "$PROJECT_DIR"/{adapters,api/routes,engine,providers,storage,config,static,scripts,lib,logs}
mkdir -p "$PROJECT_DIR"/static/{css,js}
mkdir -p "$PROJECT_DIR"/static/js/alerts
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$PROJECT_DIR"
chmod 755 "$PROJECT_DIR"
print_ok "项目目录创建完成: $PROJECT_DIR"

# ============================================================
# 4. 创建虚拟环境
# ============================================================

echo ""
echo "[4/9] 创建虚拟环境..."
cd "$PROJECT_DIR"
sudo -u "$SERVICE_USER" python3 -m venv venv
print_ok "虚拟环境创建完成"

echo "[5/9] 安装 Python 依赖..."
cat > requirements.txt << 'EOF'
fastapi
uvicorn
pydantic
pyyaml
python-multipart
EOF
sudo -u "$SERVICE_USER" venv/bin/pip install -q -r requirements.txt
print_ok "Python 依赖安装完成"

# ============================================================
# 5. 配置 rsyslog（备份 + 新建）
# ============================================================

echo ""
echo "[6/9] 配置 rsyslog..."

RSYSLOG_CONF="/etc/rsyslog.d/remote.conf"

# 备份现有配置
if [ -f "$RSYSLOG_CONF" ]; then
    BACKUP_FILE="${RSYSLOG_CONF}.bak.$(date +%Y%m%d_%H%M%S)"
    cp "$RSYSLOG_CONF" "$BACKUP_FILE"
    print_warn "现有配置已备份到: $BACKUP_FILE"
fi

# 写入新配置（使用 5514 端口）
cat > "$RSYSLOG_CONF" << EOF
# 统一日志模板
template(name="RemoteLog" type="string"
     string="/var/log/remote/modsec_%\$YEAR%-%\$MONTH%-%\$DAY%.log")

# 加载 UDP/TCP 模块
module(load="imudp")
input(type="imudp" port="$RSYSLOG_PORT")
module(load="imtcp")
input(type="imtcp" port="$RSYSLOG_PORT")

# 转发 ModSecurity 日志
if \$programname == 'modsec' then {
    action(type="omfile" dynaFile="RemoteLog")
    stop
}
EOF

mkdir -p /var/log/remote
chown syslog:adm /var/log/remote
systemctl restart rsyslog
print_ok "rsyslog 配置完成（端口: $RSYSLOG_PORT）"

# ============================================================
# 6. 配置日志轮转
# ============================================================

echo ""
echo "[7/9] 配置日志轮转..."

cat > /etc/logrotate.d/modsec_remote << 'EOF'
/var/log/remote/modsec_*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 syslog adm
    sharedscripts
    postrotate
        systemctl kill -s HUP rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

print_ok "日志轮转配置完成（保留 7 天）"

# 读取 ModSecurity 本地日志并转发
cat > /etc/rsyslog.d/50-modsec-local.conf << 'EOF'
# 加载 imfile 模块（读取文件）
module(load="imfile")

# 监控 ModSecurity 审计日志
input(type="imfile"
      File="/var/log/apache2/modsec_audit.log"
      Tag="modsec"
      Severity="info"
      Facility="local5")
EOF
systemctl restart rsyslog

# ---------- 新增：配置 ModSecurity 审计日志 ----------
if [ -f /etc/modsecurity/modsecurity.conf ]; then
    cp /etc/modsecurity/modsecurity.conf /etc/modsecurity/modsecurity.conf.bak
fi

cat > /etc/modsecurity/modsecurity.conf << 'EOF'
SecRuleEngine DetectionOnly
SecRequestBodyAccess On
SecResponseBodyAccess On
SecAuditEngine RelevantOnly
SecAuditLog /var/log/apache2/modsec_audit.log
EOF

# 确保日志目录存在且权限正确
touch /var/log/apache2/modsec_audit.log
chown www-data:adm /var/log/apache2/modsec_audit.log
chmod 640 /var/log/apache2/modsec_audit.log
# ---------------------------------------------------

# 启用 ModSecurity 模块（如果未启用）
a2enmod security2

# 重启 Apache
systemctl restart apache2

# ============================================================
# 7. 创建配置模板
# ============================================================

echo ""
echo "[8/9] 创建配置模板..."

#cat > config/settings.py << 'EOF'
# 默认配置（可自定义）
# 当前源码包中都已有这些配置，就别乱动了，不然容易出事的
#BASIC_AUTH_USERNAME = "admin"
#BASIC_AUTH_PASSWORD = "changeme123"
#COOKIE_USER_KEY = "alert_user"
#RSYSLOG_PORT = 5514
#EOF

#echo '{"assets": []}' > config/assets.json
#echo '{"rules": []}' > config/sink_rules.json

chown -R "$SERVICE_USER:$SERVICE_GROUP" "$PROJECT_DIR"/config
print_ok "配置模板创建完成"

# ============================================================
# 8. 创建 systemd 服务（使用专用用户）
# ============================================================

echo ""
echo "[9/9] 创建 systemd 服务..."

cat > /etc/systemd/system/modsec-collector.service << 'EOF'
[Unit]
Description=ModSecurity Alert Collector
After=network.target rsyslog.service

[Service]
Type=simple
User=modsec
Group=modsec
WorkingDirectory=/opt/modsec_processor
ExecStart=/opt/modsec_processor/venv/bin/python3 /opt/modsec_processor/main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/modsec-api.service << 'EOF'
[Unit]
Description=ModSecurity Alert API
After=network.target

[Service]
Type=simple
User=modsec
Group=modsec
WorkingDirectory=/opt/modsec_processor
ExecStart=/opt/modsec_processor/venv/bin/python3 /opt/modsec_processor/api/run.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable modsec-collector modsec-api
print_ok "systemd 服务创建完成"

# ============================================================
# 9. 启动服务
# ============================================================

echo ""
echo "[10/10] 启动服务..."
systemctl start modsec-collector
systemctl start modsec-api
print_ok "服务已启动"

# ============================================================
# 10. 输出信息
# ============================================================

echo ""
echo "============================================================"
echo "  🎉 安装完成！"
echo "============================================================"
echo ""
echo "  📍 项目目录:  $PROJECT_DIR"
echo "  📍 配置文件:  $PROJECT_DIR/config/"
echo ""
echo "  🔑 默认账号:  admin"
echo "  🔑 默认密码:  启动后命令行随机生成，暂不支持修改密码，重启程序后重置"
echo ""
echo "  🌐 访问地址:  http://$(hostname -I | awk '{print $1}'):8000/static/index.html"
echo ""
echo "  📊 服务状态:"
echo "     采集引擎:  systemctl status modsec-collector"
echo "     API 服务:  systemctl status modsec-api"
echo ""
echo "  📋 查看日志:"
echo "     journalctl -u modsec-collector -f"
echo "     journalctl -u modsec-api -f"
echo ""
echo "  ⚡ rsyslog 端口: $RSYSLOG_PORT"
echo ""
echo "============================================================"