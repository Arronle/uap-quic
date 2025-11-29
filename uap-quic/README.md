# 🚀 UAP (Universal Acceleration Protocol)

[可疑链接已删除] [可疑链接已删除] [可疑链接已删除]

UAP (Universal Acceleration Protocol) 是一款下一代轻量级、抗审查、专注于游戏加速的网络隧道协议。

它基于 QUIC (HTTP/3) 构建，旨在解决传统 VPN 在移动端（iOS/Android）内存占用高、握手慢、UDP 游戏体验差以及易被防火墙识别等痛点。

English: UAP is a next-generation lightweight, censorship-resistant network tunnel protocol focused on gaming acceleration. Built on QUIC, it solves memory overhead and latency issues common in traditional VPNs.

## ✨ 核心特性 (Key Features)

- 🛡️ **深度伪装 (Stealth)**: 模拟标准 HTTP/3 流量，配合 TLS 1.3 全链证书，抗主动探测。
- 🎮 **游戏加速 (Gaming First)**: 基于 QUIC Datagram 实现 UDP 0-RTT 转发，完美支持 MOBA/FPS 游戏。
- ⚡️ **极致轻量 (Zero-Alloc)**: 全局 sync.Pool 内存复用，针对 iOS Network Extension (15MB 限制) 深度优化。
- 🧠 **智能分流 (Smart Routing)**: 内置后缀树 (Suffix Trie) 路由算法，毫秒级判断直连/代理。
- 🔒 **安全鉴权 (Secure)**: 强制 UUID Token 鉴权，防止未授权访问。

## 🏗️ 技术架构 (Architecture)

UAP 采用经典的 Client-Server 架构，客户端在本地开启 SOCKS5 监听，将流量封装进 QUIC 隧道发送至服务端。

```graph
graph TD
    User[用户应用 (Browser/Game)] -->|SOCKS5 TCP/UDP| Client[UAP Client (Local)]
    
    subgraph Client_Side [客户端核心]
        Client -->|解析| SmartRoute{智能路由 Trie}
        SmartRoute -- 白名单 --> Tunnel[QUIC 隧道]
        SmartRoute -- 其他 --> Direct[本地直连]
    end
    
    Tunnel -->|HTTP/3 (UDP 443)| FW((防火墙/GFW))
    FW -->|HTTP/3 (UDP 443)| Server[UAP Server]
    
    subgraph Server_Side [服务端核心]
        Server -->|解包 & 鉴权| ProxyCore
        ProxyCore -- Stream --> Web[目标网站]
        ProxyCore -- Datagram --> GameServer[游戏服务器]
    end
```

## 📂 目录结构 (Directory Structure)

```
.
├── cmd/
│   ├── client/          # 客户端入口 (CLI / Desktop)
│   └── server/          # 服务端入口
├── pkg/
│   ├── router/          # 智能路由模块 (Suffix Trie)
│   └── sdk/             # [WIP] 移动端 SDK 封装 (供 iOS/Android 调用)
├── tests/               # 测试脚本 (UDP Ping 等)
├── whitelist.txt        # 路由规则文件
├── ops.sh               # 服务端一键部署/运维脚本
└── README.md            # 项目文档
```

## 🚀 快速开始 (Quick Start)

### 1. 环境准备

- **Go**: 1.21 或更高版本
- **服务端**: Ubuntu 20.04/22.04 (推荐)

### 2. 服务端部署 (Server Deployment)

我们提供了一键全自动化部署脚本，支持自动申请 Let's Encrypt 证书、编译、配置 Systemd 服务。

```bash
# 在服务器上执行
git clone [https://github.com/YourName/uap-quic.git](https://github.com/YourName/uap-quic.git)
cd uap-quic
chmod +x ops.sh
./ops.sh
```

部署成功后，服务将监听 UDP/TCP 443 端口。

### 3. 客户端运行 (Client Run)

在本地电脑（Mac/Linux/Windows）运行：

```bash
# 1. 修改配置 (cmd/client/main.go)
# 确保 serverAddr 指向你的域名，Token 与服务端一致

# 2. 运行
go run cmd/client/main.go
```

此时，本地 SOCKS5 代理已启动：`127.0.0.1:1080`。

### 4. 验证测试

```bash
# 测试网页 (走代理)
curl -v -x socks5h://127.0.0.1:1080 [https://www.google.com](https://www.google.com) -I

# 测试直连 (不走代理)
curl -v -x socks5h://127.0.0.1:1080 [可疑链接已删除]
```

-----

## 📱 移动端集成指南 (For Mobile Devs)

🚧 **正在施工中 (Work In Progress)**: SDK 封装位于 `pkg/sdk`。

### 接口定义 (Interface)

移动端不直接调用 main 函数，而是通过 Gomobile 绑定以下接口：

```go
package sdk

// 初始化并启动 VPN 核心
// token: 鉴权密钥
// host: 服务器地址 (e.g., "uap.example.com:443")
// rules: 路由规则字符串 (换行符分隔)
func Start(token string, host string, rules string)

// 停止 VPN 并释放资源
func Stop()
```

### iOS 集成步骤 (预告)

1. 使用 `gomobile bind -target=ios` 生成 `Uap.xcframework`。
2. 在 Xcode 中引入 Framework。
3. 在 NetworkExtension 的 PacketTunnelProvider 中调用 `Uap.Start(...)`。

## 🔧 常见问题 (FAQ)

**Q: 为什么报错 certificate signed by unknown authority?**  
A: 服务端未正确加载 Let's Encrypt 全链证书。请在服务端重新运行 `./ops.sh` 确保 acme.sh 部署成功。客户端必须设置 ServerName 与证书域名一致。

**Q: 游戏加速原理是什么？**  
A: 我们利用 QUIC 的 Datagram 帧（不可靠传输）来封装 SOCKS5 UDP 数据包。相比 TCP 隧道，它没有队头阻塞（Head-of-Line Blocking），丢包重传由游戏层控制，实现了真正的低延迟。

---

Copyright © 2025 UAP Team. All Rights Reserved.
