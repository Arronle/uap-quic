#!/bin/bash
set -e

# 配置你的域名
DOMAIN="uaptest.org"
APP_NAME="uap-server"

# 1. 安装 Go (如果没装)
if ! command -v go &> /dev/null; then
    echo ">>> 安装 Go..."
    rm -rf /usr/local/go
    curl -L https://go.dev/dl/go1.21.5.linux-amd64.tar.gz -o go.tar.gz
    tar -C /usr/local -xzf go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
fi
export PATH=$PATH:/usr/local/go/bin

# 2. 申请证书 (acme.sh)
if [ ! -f "/root/.acme.sh/acme.sh" ]; then
    echo ">>> 安装 acme.sh..."
    curl https://get.acme.sh | sh
fi
# 简单证书申请逻辑... (此处省略，保持之前逻辑即可，或者手动申请一次)

# 3. 编译服务端
echo ">>> 编译代码..."
go mod tidy
go build -o $APP_NAME cmd/server/main.go
mv $APP_NAME /usr/local/bin/

# 4. 配置 Systemd 并重启
echo ">>> 重启服务..."
# (写入 systemd 配置，同上文)
# 这里为了演示简洁，直接重启
systemctl restart uap || echo "服务尚未安装，请手动配置 uap.service"

echo ">>> 部署完成！"