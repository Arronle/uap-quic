#!/bin/bash

# ==================================================
# UAP Admin 自动化部署脚本 (GitOps)
# ==================================================

# 遇到错误立即停止
set -e

# 获取脚本所在目录（作为工作目录）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_NAME="uap-admin-linux"
SERVICE_NAME="uap-admin"

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

# 验证 Go 版本（需要 1.21+）
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
GO_MAJOR=$(echo $GO_VERSION | cut -d. -f1)
GO_MINOR=$(echo $GO_VERSION | cut -d. -f2)
if [ "$GO_MAJOR" -lt 1 ] || ([ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 21 ]); then
    echo "❌ Go 版本过低，需要 1.21+，当前版本: $GO_VERSION"
    exit 1
fi

echo "✅ Go 环境检查通过: $(go version)"

# 2. 编译代码
echo ">>> 开始编译 uap-admin..."
cd "$SCRIPT_DIR"
go mod tidy
go build -o "$APP_NAME" main.go

if [ ! -f "$APP_NAME" ]; then
    echo "❌ 编译失败，二进制文件不存在"
    exit 1
fi

echo "✅ 编译成功: $APP_NAME"

# 3. 配置 Systemd 服务
echo ">>> 配置系统服务..."
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# 检查服务文件是否存在或需要更新
NEED_UPDATE=false
if [ ! -f "$SERVICE_FILE" ]; then
    echo ">>> 服务文件不存在，创建新配置..."
    NEED_UPDATE=true
else
    # 检查 WorkingDirectory 是否正确
    if ! grep -q "WorkingDirectory=$SCRIPT_DIR" "$SERVICE_FILE"; then
        echo ">>> 服务文件配置已过期，更新配置..."
        NEED_UPDATE=true
    fi
fi

if [ "$NEED_UPDATE" = true ]; then
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=UAP Admin Service
After=network.target

[Service]
Type=simple
User=root
Restart=always
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/$APP_NAME

[Install]
WantedBy=multi-user.target
EOF
    echo "✅ 服务文件已更新: $SERVICE_FILE"
else
    echo "✅ 服务文件已存在且配置正确，跳过更新"
fi

# 4. 重启服务
echo ">>> 重启 UAP Admin 服务..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" || true
systemctl restart "$SERVICE_NAME"

# 等待服务启动
sleep 2

# 检查服务状态
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "✅ 服务启动成功"
    systemctl status "$SERVICE_NAME" --no-pager -l
else
    echo "❌ 服务启动失败"
    systemctl status "$SERVICE_NAME" --no-pager -l
    exit 1
fi

# 5. 环境检查
echo ""
echo ">>> 环境检查..."
WARNINGS=0

if [ ! -f "$SCRIPT_DIR/private_key.pem" ]; then
    echo -e "\033[33m⚠️  警告: private_key.pem 不存在（这是新部署，JWT 密钥对将自动生成）\033[0m"
    WARNINGS=$((WARNINGS + 1))
fi

if [ ! -f "$SCRIPT_DIR/uap_admin.db" ]; then
    echo -e "\033[33m⚠️  警告: uap_admin.db 不存在（这是新部署，数据库将自动创建）\033[0m"
    WARNINGS=$((WARNINGS + 1))
fi

if [ $WARNINGS -eq 0 ]; then
    echo "✅ 环境检查通过，所有必需文件存在"
else
    echo -e "\033[33m⚠️  检测到 $WARNINGS 个警告，请确认这是新部署\033[0m"
fi

echo ""
echo "=========================================="
echo "   ✅ UAP Admin 部署完成！"
echo "   工作目录: $SCRIPT_DIR"
echo "   服务名称: $SERVICE_NAME"
echo "=========================================="

