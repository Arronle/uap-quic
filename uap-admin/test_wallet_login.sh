#!/bin/bash

# 钱包登录测试脚本
# 需要先安装 Go 和 crypto/ed25519 支持

echo "🧪 测试钱包登录接口"
echo ""

# 服务端地址
API_URL="https://admin.uap.io/api/v1/auth/wallet"

# 生成测试密钥对（使用 Go 脚本）
cat > /tmp/gen_key.go << 'EOF'
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

func main() {
	// 生成密钥对
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	
	// 生成时间戳
	timestamp := time.Now().Unix()
	
	// 构造签名消息
	message := fmt.Sprintf("uap-login:%d", timestamp)
	messageBytes := []byte(message)
	
	// 签名
	signature := ed25519.Sign(priv, messageBytes)
	
	// 输出 JSON
	fmt.Printf(`{
  "public_key": "%s",
  "signature": "%s",
  "timestamp": %d
}
`, hex.EncodeToString(pub), hex.EncodeToString(signature), timestamp)
}
EOF

# 生成测试数据
TEST_DATA=$(go run /tmp/gen_key.go)

echo "📝 测试数据："
echo "$TEST_DATA" | jq . 2>/dev/null || echo "$TEST_DATA"
echo ""

# 发送请求
echo "🚀 发送 POST 请求..."
RESPONSE=$(curl -s -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -d "$TEST_DATA")

echo "📥 服务器响应："
echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
echo ""

# 清理
rm -f /tmp/gen_key.go

