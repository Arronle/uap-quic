# 🌐 UAP (Universal Acceleration Protocol) 云平台

UAP 是一个去中心化、抗审查、专注于游戏加速的下一代网络隧道协议平台。本项目采用 Monorepo 结构，包含核心协议实现 (uap-quic) 以及分布式节点管理后台 (uap-admin)。

## 🏗️ 系统架构 (System Architecture)

我们采用 "控制面 (Control Plane) 与 数据面 (Data Plane) 分离" 的双塔架构：

```graph TD
    User[👤 终端用户 (iOS/Android/PC)]
    
    subgraph Control_Plane [🏢 控制中心 (uap-admin)]
        API[API Server]
        DB[(用户/节点数据库)]
        Auth[JWT 鉴权中心]
    end
    
    subgraph Data_Plane [🌍 全球加速网络 (uap-server)]
        Node_US[🇺🇸 美国节点]
        Node_JP[🇯🇵 日本节点]
        Node_HK[🇭🇰 香港节点]
    end

User -- "1. 注册/登录 (HTTPS)" --> API
API -- "2. 下发 JWT & 节点列表" --> User
Node_US -- "3. 自动上报心跳/负载" --> API
User == "4. 智能测速 & QUIC 连接" ==> Node_US
```

## 📦 项目组件 (Components)

| 组件 | 目录 | 描述 | 技术栈 |
|------|------|------|--------|
| 管理后台 | `uap-admin/` | 用户管理、节点注册、计费结算 | Gin, GORM, SQLite |
| 核心协议 | `uap-quic/` | 客户端与服务端核心传输引擎 | Go, QUIC-Go, SuffixTrie |
| 移动端 SDK | `uap-quic/pkg/sdk/` | iOS/Android 底层库 | Gomobile |

## 🚀 快速开始 (Quick Start)

### 1. 启动管理后台 (Control Plane)

```bash
cd uap-admin
go run .

# 服务将监听 :8080，并自动生成公私钥对
```

### 2. 启动客户端 (Data Plane)

```bash
cd uap-quic
go run cmd/client/main.go

# 客户端会自动向后台拉取节点列表并测速连接
```

## 📱 移动端集成 (Mobile SDK)

iOS/Android 通过 Gomobile 调用 `uap-quic/pkg/sdk`。

编译 iOS Framework:

```bash
cd uap-quic
gomobile bind -target=ios -o Uap.xcframework ./pkg/sdk
```

## 🛠️ 开发者调试指南 (Developer Guide)

本地开发时，如何测试后台 API 和账户体系？请按以下步骤操作。

### 1. 启动管理后台

```bash
cd uap-admin
go run .

# 保持终端开启，观察日志输出
```

### 2. 测试账户注册/登录

#### 方式 A：私钥一键注册 (Web3 风格)

我们提供了一个自动化脚本，模拟客户端生成私钥、签名并获取 Token。

```bash
cd uap-admin
./test_wallet_login.sh
```

成功标志: 返回 code: 200 并显示生成的 token 和 uuid。

#### 方式 B：邮箱验证码登录 (Web2 风格)

目前开发环境未对接真实邮件服务，验证码将打印在后台日志中。

**步骤 1：请求验证码**

```bash
curl -X POST http://localhost:8080/api/v1/auth/email/code \
  -H "Content-Type: application/json" \
  -d '{"email": "dev@uap.com"}'
```

👉 关键动作: 切换到后台运行的终端，查看日志，找到类似 `====== 验证码: 123456 ======` 的输出。

**步骤 2：登录获取 Token**

```bash
# 将 123456 替换为你看到的验证码
curl -X POST http://localhost:8080/api/v1/auth/email/login \
  -H "Content-Type: application/json" \
  -d '{"email": "dev@uap.com", "code": "123456"}'
```

### 3. 验证 Token 有效性 (拉取节点)

拿到 Token 后，验证它是否能成功拉取节点列表（这也是客户端启动时的核心动作）。

```bash
# 替换 <YOUR_TOKEN> 为刚才获取的 eyJ... 开头的字符串
curl -H "Authorization: Bearer <YOUR_TOKEN>" http://localhost:8080/api/v1/client/nodes
```

成功: 返回包含节点信息的 JSON 列表。

失败: 返回 401 Unauthorized，说明 Token 无效或过期。
