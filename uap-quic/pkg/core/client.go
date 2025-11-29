package core

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"uap-quic/pkg/router"

	"github.com/quic-go/quic-go"
)

// Client UAP 客户端核心
type Client struct {
	// QUIC 连接状态
	quicConn     quic.Connection
	quicConnLock sync.RWMutex

	// 生命周期控制
	ctx    context.Context
	cancel context.CancelFunc

	// 配置
	serverAddr  string
	token       string
	localPort   int
	mode        string // "smart" 或 "global"
	proxyRouter *router.Router

	// SOCKS5 监听器
	listener     net.Listener
	listenerLock sync.Mutex

	// 缓冲池
	bufPool sync.Pool
}

// NewClient 创建新的客户端实例
func NewClient(serverAddr, token string, localPort int, mode string) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		serverAddr: serverAddr,
		token:      token,
		localPort:  localPort,
		mode:       mode,
		ctx:        ctx,
		cancel:     cancel,
		bufPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024) // 32KB
			},
		},
	}

	return client
}

// copyBuffer 使用缓冲池进行数据复制
func (c *Client) copyBuffer(dst io.Writer, src io.Reader) (int64, error) {
	buf := c.bufPool.Get().([]byte)
	defer c.bufPool.Put(buf)
	return io.CopyBuffer(dst, src, buf)
}

// Start 启动客户端
func (c *Client) Start(whitelistFile string) error {
	// 1. 初始化路由
	c.proxyRouter = router.NewRouter()
	if err := c.proxyRouter.LoadRules(whitelistFile); err != nil {
		log.Printf("⚠️ 路由规则加载失败: %v (默认空规则)", err)
	} else {
		log.Printf("✅ 路由器加载成功，规则数: %d", c.proxyRouter.GetRuleCount())
	}

	// 2. 初始化 QUIC 连接
	if err := c.ensureQuicConnection(); err != nil {
		log.Printf("⚠️ 初始化连接失败 (后台重试): %v", err)
	}
	go c.monitorConnection()

	// 3. 启动 SOCKS5 监听
	socksAddr := fmt.Sprintf("127.0.0.1:%d", c.localPort)
	listener, err := net.Listen("tcp", socksAddr)
	if err != nil {
		return fmt.Errorf("SOCKS5 启动失败: %w", err)
	}

	c.listenerLock.Lock()
	c.listener = listener
	c.listenerLock.Unlock()

	log.Printf("🚀 SOCKS5 代理已就绪: %s", socksAddr)
	log.Printf("🔗 目标服务器: %s", c.serverAddr)
	log.Printf("当前运行模式: %s", c.mode)

	// 4. 主循环：处理 SOCKS5 连接
	// 使用 goroutine + channel 模式，以便能够响应 ctx.Done()
	connChan := make(chan net.Conn, 10)
	errChan := make(chan error, 1)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				errChan <- err
				return
			}
			select {
			case connChan <- conn:
			case <-c.ctx.Done():
				conn.Close()
				return
			}
		}
	}()

	for {
		select {
		case <-c.ctx.Done():
			return nil
		case conn := <-connChan:
			go c.handleSOCKS5Client(conn)
		case err := <-errChan:
			// 如果是因为关闭导致的错误，直接返回
			if c.ctx.Err() != nil {
				return nil
			}
			// 其他错误，记录并继续（实际应该很少发生）
			log.Printf("⚠️ Accept 错误: %v", err)
			return err
		}
	}
}

// Stop 停止客户端
func (c *Client) Stop() {
	log.Println("🛑 正在停止客户端...")

	// 1. 取消所有 goroutine
	c.cancel()

	// 2. 关闭 SOCKS5 监听器
	c.listenerLock.Lock()
	if c.listener != nil {
		c.listener.Close()
		c.listener = nil
	}
	c.listenerLock.Unlock()

	// 3. 关闭 QUIC 连接
	c.quicConnLock.Lock()
	if c.quicConn != nil {
		c.quicConn.CloseWithError(0, "client shutdown")
		c.quicConn = nil
	}
	c.quicConnLock.Unlock()

	log.Println("✅ 客户端已停止")
}

// ensureQuicConnection 确保连接可用
func (c *Client) ensureQuicConnection() error {
	c.quicConnLock.Lock()
	defer c.quicConnLock.Unlock()

	if c.quicConn != nil {
		select {
		case <-c.quicConn.Context().Done():
			c.quicConn = nil
		default:
			return nil
		}
	}
	return c.reconnectQuic()
}

// reconnectQuic 建立连接 (核心)
func (c *Client) reconnectQuic() error {
	log.Printf("正在连接服务端: %s ...", c.serverAddr)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,            // 🔒 开启真证书验证
		NextProtos:         []string{"h3"},   // 伪装 HTTP/3
		ServerName:         "uaptest.org",    // 显式指定域名
		MinVersion:         tls.VersionTLS13, // 强制 TLS 1.3
	}

	quicConfig := &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  time.Hour * 24 * 365,
		KeepAlivePeriod: 10 * time.Second,
		// 1. 恢复 MTU 探测 (iperf 证明大包能过，开启它能提速)
		DisablePathMTUDiscovery: false,
		// 2. 并发流适中 (既不拥堵也不受限)
		MaxIncomingStreams:    5000,
		MaxIncomingUniStreams: 5000,
		// 3. 黄金窗口参数 (Sweet Spot)
		// 针对跨国高延迟 + 轻微丢包环境的最优解
		InitialStreamReceiveWindow:     1024 * 1024 * 2,  // 2MB 起步
		MaxStreamReceiveWindow:         1024 * 1024 * 6,  // 单流最大 6MB (足够跑满 100M+)
		InitialConnectionReceiveWindow: 1024 * 1024 * 6,  // 连接起步 6MB
		MaxConnectionReceiveWindow:     1024 * 1024 * 15, // 连接最大 15MB
	}

	conn, err := quic.DialAddr(c.ctx, c.serverAddr, tlsConfig, quicConfig)
	if err != nil {
		return err
	}

	c.quicConn = conn
	log.Printf("✅ QUIC 隧道建立成功")
	return nil
}

// monitorConnection 断线重连守护
func (c *Client) monitorConnection() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			needsReconnect := false
			c.quicConnLock.RLock()
			if c.quicConn == nil || c.quicConn.Context().Err() != nil {
				needsReconnect = true
			}
			c.quicConnLock.RUnlock()

			if needsReconnect {
				c.quicConnLock.Lock()
				// 双重检查 (Double-Checked Locking)
				if c.quicConn == nil || c.quicConn.Context().Err() != nil {
					log.Println("🔄 连接断开，正在重连...")
					if err := c.reconnectQuic(); err != nil {
						log.Printf("❌ 重连失败: %v", err)
					}
				}
				c.quicConnLock.Unlock()
			}
		}
	}
}

// getQuicConnection 获取 QUIC 连接
func (c *Client) getQuicConnection() quic.Connection {
	c.quicConnLock.RLock()
	defer c.quicConnLock.RUnlock()
	return c.quicConn
}

// handleSOCKS5Client 处理 SOCKS5 握手
func (c *Client) handleSOCKS5Client(clientConn net.Conn) {
	defer clientConn.Close()

	// 协商版本
	buf := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}

	// 读取方法
	numMethods := int(buf[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		return
	}

	// 回复无需认证
	clientConn.Write([]byte{0x05, 0x00})

	// 读取请求
	head := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, head); err != nil {
		return
	}

	switch head[1] {
	case 0x01: // CONNECT
		c.handleTCPConnect(clientConn, head[3])
	case 0x03: // UDP ASSOCIATE
		c.handleUDPAssociate(clientConn, head[3])
	default:
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

// parseAddress 读取目标地址
func (c *Client) parseAddress(conn net.Conn, addrType byte) (string, error) {
	var host string
	switch addrType {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	default:
		return "", fmt.Errorf("unknown address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

// handleTCPConnect 处理 TCP 转发
func (c *Client) handleTCPConnect(clientConn net.Conn, addrType byte) {
	targetAddr, err := c.parseAddress(clientConn, addrType)
	if err != nil {
		return
	}

	host, _, _ := net.SplitHostPort(targetAddr)

	// 分流判断
	shouldProxy := false
	if c.mode == "global" {
		// 全局模式：强制走代理 (除非是 localhost)
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			shouldProxy = true
		}
	} else if c.proxyRouter != nil {
		// 智能模式：查白名单
		shouldProxy = c.proxyRouter.ShouldProxy(host)
	}

	if shouldProxy {
		log.Printf("[分流] 🚀 代理: %s", host)
		c.proxyTCP(clientConn, targetAddr)
	} else {
		log.Printf("[分流] 🏠 直连: %s", host)
		c.directTCP(clientConn, targetAddr)
	}
}

// proxyTCP 走 QUIC 隧道
func (c *Client) proxyTCP(clientConn net.Conn, target string) {
	conn := c.getQuicConnection()
	if conn == nil {
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	stream, err := conn.OpenStreamSync(c.ctx)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()
	defer stream.CancelRead(0) // 立即释放读取相关资源，防止流变成僵尸

	// 1. 鉴权
	if _, err := stream.Write([]byte(c.token + "\n")); err != nil {
		return
	}

	// 2. 验证
	status := make([]byte, 1)
	if _, err := io.ReadFull(stream, status); err != nil || status[0] != 0x00 {
		log.Printf("⛔ 鉴权被拒")
		return
	}

	// 3. 发送目标
	addrBytes := []byte(target)
	stream.Write([]byte{byte(len(addrBytes))})
	stream.Write(addrBytes)

	// 4. 等待连接
	if _, err := io.ReadFull(stream, status); err != nil || status[0] != 0x00 {
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// 5. 成功
	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// 6. 转发
	go func() { c.copyBuffer(stream, clientConn) }()
	c.copyBuffer(clientConn, stream)
}

// directTCP 直连
func (c *Client) directTCP(clientConn net.Conn, target string) {
	targetConn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetConn.Close()

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	go func() { c.copyBuffer(targetConn, clientConn) }()
	c.copyBuffer(clientConn, targetConn)
}

// handleUDPAssociate 处理 UDP 转发
func (c *Client) handleUDPAssociate(clientConn net.Conn, addrType byte) {
	c.parseAddress(clientConn, addrType) // 读掉头部

	// 启动本地 UDP
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return
	}
	defer udpConn.Close()

	localPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	log.Printf("[UDP] 端口开启: %d", localPort)

	// 回复 TCP
	resp := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(resp[8:], uint16(localPort))
	clientConn.Write(resp)

	conn := c.getQuicConnection()
	if conn == nil {
		return
	}

	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()

	var currentAddr atomic.Value

	// 1. Read Loop (App -> LocalUDP -> QUIC)
	go func() {
		buf := make([]byte, 2048)
		for {
			if ctx.Err() != nil {
				return
			}
			udpConn.SetReadDeadline(time.Now().Add(5 * time.Second)) // 超时机制

			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				// 超时继续，错误退出
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			if n > 0 {
				currentAddr.Store(addr)
				conn.SendDatagram(buf[:n])
			}
		}
	}()

	// 2. Write Loop (QUIC -> LocalUDP -> App)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				data, err := conn.ReceiveDatagram(ctx)
				if err != nil {
					return
				}

				if addr := currentAddr.Load(); addr != nil {
					udpConn.WriteToUDP(data, addr.(*net.UDPAddr))
				}
			}
		}
	}()

	// 3. TCP 保活监控
	io.Copy(io.Discard, clientConn) // 阻塞等待 TCP 断开
	cancel()
}

