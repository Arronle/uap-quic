#!/bin/bash

# ==================================================
# UAP 自动化运维脚本 (完整版)
# ==================================================

# 遇到错误立即停止
set -e

# 配置信息
APP_NAME="uap-server"
# ⚠️ 请确保这里是你的真实域名
DOMAIN="uaptest.org"
EMAIL="admin@uaptest.org"

# 1. 检查并安装 Go 环境
if ! command -v go &> /dev/null; then
    echo ">>> 检测到未安装 Go，开始安装..."
    rm -rf /usr/local/go
    curl -L https://go.dev/dl/go1.21.5.linux-amd64.tar.gz -o go.tar.gz
    tar -C /usr/local -xzf go.tar.gz
    rm go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
fi
export PATH=$PATH:/usr/local/go/bin

# 2. 检查并安装 acme.sh
if [ ! -f "$HOME/.acme.sh/acme.sh" ]; then
    echo ">>> 安装 acme.sh..."
    apt-get install -y socat cron
    curl https://get.acme.sh | sh
    source ~/.bashrc
fi

# 3. 申请证书 (如果证书不存在)
CERT_DIR="/etc/uap-cert"
if [ ! -f "$CERT_DIR/cert.pem" ]; then
    echo ">>> 申请 SSL 证书 ($DOMAIN)..."
    # 先停止可能占用的服务
    systemctl stop uap || true
    
    mkdir -p $CERT_DIR
    ~/.acme.sh/acme.sh --register-account -m $EMAIL
    ~/.acme.sh/acme.sh --issue -d $DOMAIN --standalone --force
    ~/.acme.sh/acme.sh --install-cert -d $DOMAIN \
        --key-file       $CERT_DIR/key.pem  \
        --fullchain-file $CERT_DIR/cert.pem
else
    echo ">>> 证书已存在，跳过申请。"
fi

# 4. 编译代码
echo ">>> 开始编译服务端..."
go mod tidy
go build -o $APP_NAME cmd/server/main.go
mv $APP_NAME /usr/local/bin/

# 5. 配置 Systemd 服务 (这一步之前缺了，现在补上！)
echo ">>> 配置系统服务..."
cat > /etc/systemd/system/uap.service <<EOF
[Unit]
Description=UAP Server Service
After=network.target

[Service]
Type=simple
User=root
Restart=always
# 这里的路径必须和证书路径一致
ExecStart=/usr/local/bin/$APP_NAME -cert $CERT_DIR/cert.pem -key $CERT_DIR/key.pem

[Install]
WantedBy=multi-user.target
EOF

# 6. 开启 BBR
if ! grep -q "bbr" /etc/sysctl.conf; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
fi

# 7. 重启服务
echo ">>> 重启 UAP 服务..."
systemctl daemon-reload
systemctl enable uap
systemctl restart uap
systemctl status uap --no-pager

echo "=========================================="
echo "   ✅ UAP 部署完成！服务已启动"
echo "=========================================="