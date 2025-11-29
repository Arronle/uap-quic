package sdk

import (
	"log"
	"sync"

	"uap-quic/pkg/core"
)

var (
	client     *core.Client
	clientLock sync.Mutex
)

// StartWithHost 初始化并启动 VPN 核心（指定服务器地址版本）
// token: 鉴权密钥
// host: 服务器地址 (e.g., "uap.example.com:443")
// port: 本地 SOCKS5 监听端口 (e.g., 1080)
// mode: 代理模式 ("smart" 或 "global")
// rules: 路由规则字符串 (换行符分隔，空字符串表示使用默认文件)
func StartWithHost(token string, host string, port int, mode string, rules string) error {
	clientLock.Lock()
	defer clientLock.Unlock()

	// 如果已经启动，先停止
	if client != nil {
		client.Stop()
		client = nil
	}

	// 创建客户端实例
	client = core.NewClient(host, token, port, mode)

	// 如果提供了规则字符串，写入临时文件
	whitelistFile := "whitelist.txt"
	if rules != "" {
		// 这里可以扩展为写入临时文件，暂时使用默认文件
		// 实际使用时，可以通过 core.Client 的接口扩展来支持直接传入规则
		whitelistFile = "whitelist.txt"
	}

	// 在 goroutine 中启动（非阻塞）
	go func() {
		if err := client.Start(whitelistFile); err != nil {
			log.Printf("❌ SDK 启动失败: %v", err)
		}
	}()

	return nil
}

// Stop 停止 VPN 并释放资源
func Stop() {
	clientLock.Lock()
	defer clientLock.Unlock()

	if client != nil {
		client.Stop()
		client = nil
	}
}

// IsRunning 检查 VPN 是否正在运行
func IsRunning() bool {
	clientLock.Lock()
	defer clientLock.Unlock()
	return client != nil
}

