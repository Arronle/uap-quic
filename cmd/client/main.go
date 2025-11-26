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
	// ⚠️ 修正 1: 这里改为你的真实域名和 443 端口
	serverAddr  = "104.194.81.96:443"
	proxyRouter *router.Router
)

// bufPool 全局缓冲池，用于复用传输缓冲区（32KB 是 iOS 网络传输的黄金尺寸）
var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32*1024)
	},
}

// copyBuffer 使用缓冲池复用的数据传输函数
func copyBuffer(dst io.Writer, src io.Reader) (int64, error) {
	// 从池子里借一个 buffer
	buf := bufPool.Get().([]byte)
	// 用完必须还回去
	defer bufPool.Put(buf)
	// 使用官方的 CopyBuffer 接口
	return io.CopyBuffer(dst, src, buf)
}

func main() {
	// 初始化路由器并加载规则
	proxyRouter = router.NewRouter()
	if err := proxyRouter.LoadRules("whitelist.txt"); err != nil {
		log.Printf("⚠️ 加载规则文件失败: %v (将使用空规则列表)", err)
	} else {
		ruleCount := proxyRouter.GetRuleCount()
		log.Printf("✅ 路由器已初始化，加载了 %d 条规则", ruleCount)
	}

	// 初始化全局 QUIC 连接
	if err := ensureQuicConnection(); err != nil {
		log.Printf("⚠️ 初始化 QUIC 连接失败 (将在后台重试): %v", err)
	}

	// 启动重连监控
	go monitorConnection()

	// SOCKS5 监听：在 127.0.0.1:1080 启动 TCP 监听
	socksAddr := "127.0.0.1:1080"
	listener, err := net.Listen("tcp", socksAddr)
	if err != nil {
		log.Fatalf("❌ 启动 SOCKS5 监听失败: %v", err)
	}
	defer listener.Close()

	log.Printf("🚀 SOCKS5 代理已启动，监听地址: %s", socksAddr)
	log.Printf("🔗 QUIC 服务端目标: %s", serverAddr)

	// 循环接受连接
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("接受客户端连接失败: %v", err)
			continue
		}
		// 为每个客户端连接启动一个 goroutine 处理
		go handleSOCKS5Client(clientConn)
	}
}

// ensureQuicConnection 确保全局 QUIC 连接存在
func ensureQuicConnection() error {
	quicConnLock.Lock()
	defer quicConnLock.Unlock()

	if quicConn != nil {
		// 检查连接是否存活
		select {
		case <-quicConn.Context().Done():
			quicConn = nil // 已死
		default:
			return nil // 活着
		}
	}
	return reconnectQuic()
}

// reconnectQuic 重新连接 QUIC 服务端
func reconnectQuic() error {
	log.Printf("正在连接到 QUIC 服务端: %s ...", serverAddr)

	// 配置 TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false, // 开启安全验证
		NextProtos:         []string{"h3"},
		ServerName:         "uaptest.org", // 👈 关键！告诉 TLS 我要验证这个域名
	}

	// 配置 QUIC（启用数据报以支持 UDP 转发，并配置 Keep-Alive）
	quicConfig := &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  time.Hour * 24 * 365, // 允许连接闲置 1 年
		KeepAlivePeriod: 10 * time.Second,     // 每 10 秒发送一次心跳
	}

	conn, err := quic.DialAddr(context.Background(), serverAddr, tlsConfig, quicConfig)
	if err != nil {
		return err
	}

	quicConn = conn
	log.Printf("✅ 已成功建立 QUIC 隧道")
	return nil
}

// getQuicConnection 获取全局 QUIC 连接
func getQuicConnection() quic.Connection {
	quicConnLock.RLock()
	defer quicConnLock.RUnlock()
	return quicConn
}

// monitorConnection 监控连接状态，断开时自动重连
func monitorConnection() {
	for {
		time.Sleep(5 * time.Second)

		needsReconnect := false
		quicConnLock.RLock()
		if quicConn == nil {
			needsReconnect = true
		} else {
			select {
			case <-quicConn.Context().Done():
				needsReconnect = true
			default:
			}
		}
		quicConnLock.RUnlock()

		if needsReconnect {
			quicConnLock.Lock()
			// 双重检查
			if quicConn == nil || quicConn.Context().Err() != nil {
				log.Println("🔄 QUIC 连接断开，尝试重连...")
				if err := reconnectQuic(); err != nil {
					log.Printf("❌ 重连失败: %v", err)
				}
			}
			quicConnLock.Unlock()
		}
	}
}

// handleSOCKS5Client 处理 SOCKS5 客户端连接
func handleSOCKS5Client(clientConn net.Conn) {
	defer clientConn.Close()

	// 握手：处理 SOCKS5 认证
	handshakeBuf := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, handshakeBuf); err != nil {
		return
	}

	if handshakeBuf[0] != 0x05 {
		return
	}

	// 读取认证方法数量
	methodCount := int(handshakeBuf[1])
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		return
	}

	// 响应：0x05 0x00 (无需认证)
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 解析：读取请求包
	requestBuf := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, requestBuf); err != nil {
		return
	}

	if requestBuf[0] != 0x05 {
		return
	}

	command := requestBuf[1]
	addrType := requestBuf[3]

	// 根据命令类型处理
	switch command {
	case 0x01: // CONNECT - TCP 连接
		handleTCPConnect(clientConn, addrType)
	case 0x03: // UDP ASSOCIATE - UDP 关联
		handleUDPAssociate(clientConn, addrType)
	default:
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}
}

// parseAddress 解析 SOCKS5 地址
func parseAddress(clientConn net.Conn, addrType byte) (string, error) {
	switch addrType {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(clientConn, ipBuf); err != nil {
			return "", err
		}
		ip := net.IP(ipBuf)
		var port uint16
		if err := binary.Read(clientConn, binary.BigEndian, &port); err != nil {
			return "", err
		}
		return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil

	case 0x03: // Domain
		domainLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, domainLenBuf); err != nil {
			return "", err
		}
		domainLen := int(domainLenBuf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(clientConn, domainBuf); err != nil {
			return "", err
		}
		domain := string(domainBuf)
		var port uint16
		if err := binary.Read(clientConn, binary.BigEndian, &port); err != nil {
			return "", err
		}
		return net.JoinHostPort(domain, fmt.Sprintf("%d", port)), nil

	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(clientConn, ipBuf); err != nil {
			return "", err
		}
		ip := net.IP(ipBuf)
		var port uint16
		if err := binary.Read(clientConn, binary.BigEndian, &port); err != nil {
			return "", err
		}
		return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil

	default:
		return "", fmt.Errorf("不支持的地址类型: %d", addrType)
	}
}

// handleTCPConnect 处理 TCP CONNECT 命令
func handleTCPConnect(clientConn net.Conn, addrType byte) {
	targetAddress, err := parseAddress(clientConn, addrType)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	hostname, _, err := net.SplitHostPort(targetAddress)
	if err != nil {
		hostname = targetAddress
	}

	// 分流逻辑
	shouldProxy := false
	if proxyRouter != nil {
		shouldProxy = proxyRouter.ShouldProxy(hostname)
	}

	if shouldProxy {
		log.Printf("[分流] 🚀 代理: %s", hostname)
		handleProxyConnection(clientConn, targetAddress)
	} else {
		log.Printf("[分流] 🏠 直连: %s", hostname)
		handleDirectConnection(clientConn, targetAddress)
	}
}

// handleProxyConnection 处理代理连接
func handleProxyConnection(clientConn net.Conn, targetAddress string) {
	conn := getQuicConnection()
	if conn == nil {
		quicConnLock.Lock()
		if err := reconnectQuic(); err != nil {
			log.Printf("❌ 重连失败: %v", err)
			clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			quicConnLock.Unlock()
			return
		}
		conn = quicConn
		quicConnLock.Unlock()
	}

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Printf("❌ 打开流失败: %v", err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer stream.Close()

	// 1. 发送 Token
	tokenWithNewline := UAP_TOKEN + "\n"
	if _, err := stream.Write([]byte(tokenWithNewline)); err != nil {
		return
	}

	// 2. 验证 Token
	statusBuf := make([]byte, 1)
	if _, err := io.ReadFull(stream, statusBuf); err != nil {
		return
	}
	if statusBuf[0] != 0x00 {
		log.Printf("⛔ Token 鉴权失败")
		return
	}

	// 3. 发送目标地址
	addressBytes := []byte(targetAddress)
	if len(addressBytes) > 255 {
		return
	}
	stream.Write([]byte{byte(len(addressBytes))})
	stream.Write(addressBytes)

	// 4. 等待连接确认
	if _, err := io.ReadFull(stream, statusBuf); err != nil {
		return
	}
	if statusBuf[0] != 0x00 {
		// 服务端连不上目标
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// 5. 响应浏览器成功
	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// 6. 双向转发
	errChan := make(chan error, 2)
	go func() {
		_, err := copyBuffer(stream, clientConn)
		errChan <- err
	}()
	go func() {
		_, err := copyBuffer(clientConn, stream)
		errChan <- err
	}()
	<-errChan
}

// handleDirectConnection 处理直连
func handleDirectConnection(clientConn net.Conn, targetAddress string) {
	targetConn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		log.Printf("直连失败 %s: %v", targetAddress, err)
		clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer targetConn.Close()

	clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	errChan := make(chan error, 2)
	go func() {
		_, err := copyBuffer(targetConn, clientConn)
		errChan <- err
	}()
	go func() {
		_, err := copyBuffer(clientConn, targetConn)
		errChan <- err
	}()
	<-errChan
}

// handleUDPAssociate 处理 UDP 关联
func handleUDPAssociate(clientConn net.Conn, addrType byte) {
	parseAddress(clientConn, addrType) // 消耗掉请求中的无用地址

	// 开启本地 UDP 监听
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("UDP 监听失败: %v", err)
		return
	}
	defer udpConn.Close()

	localUDPAddr := udpConn.LocalAddr().(*net.UDPAddr)
	log.Printf("[UDP] 开启加速通道 端口: %d", localUDPAddr.Port)

	// 回复 TCP 告知端口
	response := make([]byte, 10)
	response[0], response[1], response[3] = 0x05, 0x00, 0x01
	response[4], response[5], response[6], response[7] = 127, 0, 0, 1
	binary.BigEndian.PutUint16(response[8:10], uint16(localUDPAddr.Port))
	if _, err := clientConn.Write(response); err != nil {
		return
	}

	conn := getQuicConnection()
	if conn == nil {
		return
	}

	var currentClientAddr atomic.Value
	// 使用 Context 管理生命周期，当 TCP 断开时，通知所有 UDP 协程退出
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// 1. Read Loop (本地 UDP -> QUIC)
	// ⚠️ 修正 3: 移除了这里面冗余的 TCP 检查代码，让它专心读 UDP
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			// 如果 Context 已取消（TCP 断了），退出循环
			if ctx.Err() != nil {
				return
			}

			udpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, clientAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				// 仅处理超时，忽略其他错误
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			if n > 0 {
				currentClientAddr.Store(clientAddr)
				if err := conn.SendDatagram(buf[:n]); err != nil {
					// 发送失败可能是临时拥塞，不退出
				}
			}
		}
	}()

	// 2. Write Loop (QUIC -> 本地 UDP)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done(): // 收到退出信号
				return
			default:
				// 继续
			}

			// 使用 Context 控制接收超时/取消
			data, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				return
			}

			addrVal := currentClientAddr.Load()
			if addrVal != nil {
				clientAddr := addrVal.(*net.UDPAddr)
				udpConn.WriteToUDP(data, clientAddr)
			}
		}
	}()

	// 3. TCP 监控协程 (这才是正确的保活方式)
	// 只要 TCP 连接断开 (Read 返回 EOF)，就取消 Context，强制结束上面的循环
	go func() {
		io.Copy(io.Discard, clientConn)
		cancel()        // 通知大家下班
		udpConn.Close() // 强制中断 UDP Read
	}()

	wg.Wait()
	log.Printf("[UDP] 会话结束")
}
