# UAP QUIC Tunnel

基于 QUIC (HTTP/3) 协议的轻量级代理隧道项目，支持游戏加速和抗审查。

## 项目结构

```
uap-quic/
├── cmd/
│   ├── server/        # 服务端程序
│   └── client/        # 客户端程序
├── pkg/
│   └── cert/          # 证书生成模块
├── go.mod
└── README.md
```

## 安装依赖

```bash
go mod download
```

或者直接运行程序，Go 会自动下载依赖：

```bash
go run cmd/server/main.go
```

## 运行方式

### 1. 启动服务端

在一个终端窗口中运行：

```bash
go run cmd/server/main.go
```

服务端将在 `0.0.0.0:4433` (UDP) 上监听 QUIC 连接。

**服务端功能：**
- 接受 QUIC 连接和流
- 解析客户端发送的目标地址（协议：1字节长度 + 地址字符串）
- 连接目标服务器（TCP）
- 双向转发数据

### 2. 启动客户端（SOCKS5 代理）

在另一个终端窗口中运行：

```bash
go run cmd/client/main.go
```

客户端会：
- 连接到 QUIC 服务端 `127.0.0.1:4433`
- 在 `127.0.0.1:1080` 启动 SOCKS5 代理服务器
- 自动重连机制：如果 QUIC 连接断开，会自动尝试重连

### 3. 配置浏览器使用代理

在浏览器或系统代理设置中配置：
- **代理类型**: SOCKS5
- **代理地址**: `127.0.0.1`
- **代理端口**: `1080`

然后就可以通过 QUIC 隧道访问网站了！

## 编译二进制文件

### 编译服务端

```bash
go build -o bin/server cmd/server/main.go
./bin/server
```

### 编译客户端

```bash
go build -o bin/client cmd/client/main.go
./bin/client
```

## 功能说明

### 核心功能

- **证书生成**: 服务端启动时自动在内存中生成自签名 TLS 证书
- **QUIC 连接**: 使用 QUIC 协议建立加密连接（UDP 4433 端口）
- **SOCKS5 代理**: 客户端提供标准 SOCKS5 代理接口（TCP 1080 端口）
- **多流支持**: 每个 QUIC 连接可以建立多个流，支持并发请求
- **自动重连**: 客户端具备 QUIC 连接断开自动重连机制
- **双向转发**: 完整的 TCP 到 QUIC 双向数据转发

### 协议说明

**客户端 → 服务端协议：**
1. 1 字节：目标地址字符串长度 N
2. N 字节：目标地址字符串（格式：`host:port`，如 `www.google.com:443`）

**服务端响应：**
- `0x00`: 连接成功
- `0x01`: 连接失败

### 支持的地址类型

- IPv4 地址
- IPv6 地址
- 域名（Domain）

## 测试代理

可以使用 `curl` 测试代理：

```bash
# 通过 SOCKS5 代理访问网站
curl -x socks5://127.0.0.1:1080 https://www.google.com
```

## 下一步开发

- [ ] 添加流量加密和混淆
- [ ] 性能优化和连接池管理
- [ ] 配置管理（配置文件支持）
- [ ] 日志和监控
- [ ] 多服务器负载均衡

