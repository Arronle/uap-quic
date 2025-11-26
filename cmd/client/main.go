package main

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

// UAP_TOKEN 鉴权 Token（必须与服务端一致）
const UAP_TOKEN = "uap-secret-token-8888"

var (
	quicConn     quic.Connection
	quicConnLock sync.RWMutex
	// ⚠️ 核心配置：连接真实域名和标准 HTTPS 端口
	serverAddr  = "uaptest.org:443"
	proxyRouter *router.Router
)

// bufPool 全局缓冲池 (32KB)
var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}

func copyBuffer(dst io.Writer, src io.Reader) (int64, error) {
	buf := bufPool.Get().([]byte)
	defer bufPool.Put(buf)
	return io.CopyBuffer(dst, src, buf)
}

func main() {
	// 1. 初始化路由
	proxyRouter = router.NewRouter()
	if err := proxyRouter.LoadRules("whitelist.txt"); err != nil {
		log.Printf("⚠️ 路由规则加载失败: %v (默认空规则)", err)
	} else {
		log.Printf("✅ 路由器加载成功，规则数: %d", proxyRouter.GetRuleCount())
	}

	// 2. 初始化 QUIC 连接
	if err := ensureQuicConnection(); err != nil {
		log.Printf("⚠️ 初始化连接失败 (后台重试): %v", err)
	}
	go monitorConnection()

	// 3. 启动 SOCKS5 监听
	socksAddr := "127.0.0.1:1080"
	listener, err := net.Listen("tcp", socksAddr)
	if err != nil {
		log.Fatalf("❌ SOCKS5 启动失败: %v", err)
	}
	defer listener.Close()

	log.Printf("🚀 SOCKS5 代理已就绪: %s", socksAddr)
	log.Printf("🔗 目标服务器: %s", serverAddr)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleSOCKS5Client(clientConn)
	}
}

// ensureQuicConnection 确保连接可用
func ensureQuicConnection() error {
	quicConnLock.Lock()
	defer quicConnLock.Unlock()

	if quicConn != nil {
		select {
		case <-quicConn.Context().Done():
			quicConn = nil
		default:
			return nil
		}
	}
	return reconnectQuic()
}

// reconnectQuic 建立连接 (核心)
func reconnectQuic() error {
	log.Printf("正在连接服务端: %s ...", serverAddr)

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
	}

	conn, err := quic.DialAddr(context.Background(), serverAddr, tlsConfig, quicConfig)
	if err != nil {
		return err
	}

	quicConn = conn
	log.Printf("✅ QUIC 隧道建立成功")
	return nil
}

// monitorConnection 断线重连守护
func monitorConnection() {
	for {
		time.Sleep(5 * time.Second)

		needsReconnect := false
		quicConnLock.RLock()
		if quicConn == nil || quicConn.Context().Err() != nil {
			needsReconnect = true
		}
		quicConnLock.RUnlock()

		if needsReconnect {
			quicConnLock.Lock()
			// 双重检查 (Double-Checked Locking)
			if quicConn == nil || quicConn.Context().Err() != nil {
				log.Println("🔄 连接断开，正在重连...")
				if err := reconnectQuic(); err != nil {
					log.Printf("❌ 重连失败: %v", err)
				}
			}
			quicConnLock.Unlock()
		}
	}
}

func getQuicConnection() quic.Connection {
	quicConnLock.RLock()
	defer quicConnLock.RUnlock()
	return quicConn
}

// handleSOCKS5Client 处理 SOCKS5 握手
func handleSOCKS5Client(clientConn net.Conn) {
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
		handleTCPConnect(clientConn, head[3])
	case 0x03: // UDP ASSOCIATE
		handleUDPAssociate(clientConn, head[3])
	default:
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

// parseAddress 读取目标地址
func parseAddress(conn net.Conn, addrType byte) (string, error) {
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
func handleTCPConnect(clientConn net.Conn, addrType byte) {
	targetAddr, err := parseAddress(clientConn, addrType)
	if err != nil {
		return
	}

	host, _, _ := net.SplitHostPort(targetAddr)

	// 分流判断
	shouldProxy := false
	if proxyRouter != nil {
		shouldProxy = proxyRouter.ShouldProxy(host)
	}

	if shouldProxy {
		log.Printf("[分流] 🚀 代理: %s", host)
		proxyTCP(clientConn, targetAddr)
	} else {
		log.Printf("[分流] 🏠 直连: %s", host)
		directTCP(clientConn, targetAddr)
	}
}

// proxyTCP 走 QUIC 隧道
func proxyTCP(clientConn net.Conn, target string) {
	conn := getQuicConnection()
	if conn == nil {
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	// 1. 鉴权
	if _, err := stream.Write([]byte(UAP_TOKEN + "\n")); err != nil {
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
	go func() { copyBuffer(stream, clientConn) }()
	copyBuffer(clientConn, stream)
}

// directTCP 直连
func directTCP(clientConn net.Conn, target string) {
	targetConn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetConn.Close()

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	go func() { copyBuffer(targetConn, clientConn) }()
	copyBuffer(clientConn, targetConn)
}

// handleUDPAssociate 处理 UDP 转发
func handleUDPAssociate(clientConn net.Conn, addrType byte) {
	parseAddress(clientConn, addrType) // 读掉头部

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

	conn := getQuicConnection()
	if conn == nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
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
