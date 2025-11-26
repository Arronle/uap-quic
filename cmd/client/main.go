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

	"github.com/quic-go/quic-go"
	"uap-quic/pkg/router"
)

// UAP_TOKEN 鉴权 Token（必须与服务端一致）
const UAP_TOKEN = "uap-secret-token-8888"

var (
	quicConn     quic.Connection
	quicConnLock sync.RWMutex
	serverAddr   = "127.0.0.1:4433"
	proxyRouter  *router.Router
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
		log.Printf("加载规则文件失败: %v (将使用空规则列表)", err)
	} else {
		ruleCount := proxyRouter.GetRuleCount()
		log.Printf("✅ 路由器已初始化，加载了 %d 条规则", ruleCount)
	}

	// 初始化全局 QUIC 连接
	if err := ensureQuicConnection(); err != nil {
		log.Fatalf("初始化 QUIC 连接失败: %v", err)
	}

	// 启动重连监控
	go monitorConnection()

	// SOCKS5 监听：在 127.0.0.1:1080 启动 TCP 监听
	socksAddr := "127.0.0.1:1080"
	listener, err := net.Listen("tcp", socksAddr)
	if err != nil {
		log.Fatalf("启动 SOCKS5 监听失败: %v", err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 代理已启动，监听地址: %s", socksAddr)
	log.Printf("QUIC 服务端地址: %s", serverAddr)

	// 循环接受连接
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("接受客户端连接失败: %v", err)
			continue
		}

		log.Printf("新客户端连接: %s", clientConn.RemoteAddr())

		// 为每个客户端连接启动一个 goroutine 处理
		go handleSOCKS5Client(clientConn)
	}
}

// ensureQuicConnection 确保全局 QUIC 连接存在
func ensureQuicConnection() error {
	quicConnLock.Lock()
	defer quicConnLock.Unlock()

	if quicConn != nil {
		return nil
	}

	return reconnectQuic()
}

// reconnectQuic 重新连接 QUIC 服务端
func reconnectQuic() error {
	log.Printf("正在连接到 QUIC 服务端: %s", serverAddr)

	// 配置 TLS（跳过证书验证，因为是自签名证书，并伪装成标准的 HTTP/3 流量）
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"}, // h3 是国际标准的 HTTP/3 协议代号
	}

	// 配置 QUIC（启用数据报以支持 UDP 转发，并配置 Keep-Alive）
	quicConfig := &quic.Config{
		EnableDatagrams:  true,
		MaxIdleTimeout:   time.Hour * 24 * 365, // 允许连接闲置 1 年
		KeepAlivePeriod:  10 * time.Second,      // 每 10 秒发送一次心跳
	}

	conn, err := quic.DialAddr(context.Background(), serverAddr, tlsConfig, quicConfig)
	if err != nil {
		return err
	}

	quicConn = conn
	log.Printf("已成功连接到 QUIC 服务端")
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
		conn := getQuicConnection()
		if conn == nil {
			log.Println("QUIC 连接不存在，尝试重连...")
			quicConnLock.Lock()
			if err := reconnectQuic(); err != nil {
				log.Printf("重连失败: %v", err)
			}
			quicConnLock.Unlock()
		}
	}
}

// handleSOCKS5Client 处理 SOCKS5 客户端连接
func handleSOCKS5Client(clientConn net.Conn) {
	defer clientConn.Close()

	// 握手：处理 SOCKS5 认证（读取第一个包，回 0x05 0x00）
	handshakeBuf := make([]byte, 2)
	_, err := io.ReadFull(clientConn, handshakeBuf)
	if err != nil {
		log.Printf("读取 SOCKS5 握手失败: %v", err)
		return
	}

	if handshakeBuf[0] != 0x05 {
		log.Printf("不支持的 SOCKS 版本: %d", handshakeBuf[0])
		return
	}

	// 读取认证方法数量
	methodCount := int(handshakeBuf[1])
	methods := make([]byte, methodCount)
	_, err = io.ReadFull(clientConn, methods)
	if err != nil {
		log.Printf("读取认证方法失败: %v", err)
		return
	}

	// 响应：0x05 0x00 (无需认证)
	_, err = clientConn.Write([]byte{0x05, 0x00})
	if err != nil {
		log.Printf("发送 SOCKS5 握手响应失败: %v", err)
		return
	}

	// 解析：读取请求包，解析出命令和地址
	requestBuf := make([]byte, 4)
	_, err = io.ReadFull(clientConn, requestBuf)
	if err != nil {
		log.Printf("读取 SOCKS5 请求失败: %v", err)
		return
	}

	if requestBuf[0] != 0x05 {
		log.Printf("不支持的 SOCKS 版本: %d", requestBuf[0])
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
		log.Printf("不支持的命令: %d", command)
		// 发送 SOCKS5 错误响应
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	}
}

// parseAddress 解析 SOCKS5 地址（用于 CONNECT 命令）
func parseAddress(clientConn net.Conn, addrType byte) (string, error) {
	switch addrType {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		_, err := io.ReadFull(clientConn, ipBuf)
		if err != nil {
			return "", err
		}
		ip := net.IP(ipBuf)
		var port uint16
		err = binary.Read(clientConn, binary.BigEndian, &port)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil

	case 0x03: // Domain
		domainLenBuf := make([]byte, 1)
		_, err := io.ReadFull(clientConn, domainLenBuf)
		if err != nil {
			return "", err
		}
		domainLen := int(domainLenBuf[0])
		domainBuf := make([]byte, domainLen)
		_, err = io.ReadFull(clientConn, domainBuf)
		if err != nil {
			return "", err
		}
		domain := string(domainBuf)
		var port uint16
		err = binary.Read(clientConn, binary.BigEndian, &port)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(domain, fmt.Sprintf("%d", port)), nil

	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		_, err := io.ReadFull(clientConn, ipBuf)
		if err != nil {
			return "", err
		}
		ip := net.IP(ipBuf)
		var port uint16
		err = binary.Read(clientConn, binary.BigEndian, &port)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)), nil

	default:
		return "", fmt.Errorf("不支持的地址类型: %d", addrType)
	}
}

// handleTCPConnect 处理 TCP CONNECT 命令
func handleTCPConnect(clientConn net.Conn, addrType byte) {
	// 解析目标地址
	targetAddress, err := parseAddress(clientConn, addrType)
	if err != nil {
		log.Printf("解析地址失败: %v", err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// 提取 hostname（用于路由判断）
	hostname, _, err := net.SplitHostPort(targetAddress)
	if err != nil {
		// 如果没有端口，直接使用整个地址作为 hostname
		hostname = targetAddress
	}

	log.Printf("[SOCKS5 TCP] 请求连接: %s (hostname: %s)", targetAddress, hostname)

	// 分流逻辑：调用 router.ShouldProxy(hostname) 判断是否需要走代理
	shouldProxy := proxyRouter.ShouldProxy(hostname)

	if shouldProxy {
		// 如果 ShouldProxy 返回 true：走 QUIC 隧道 (现有的逻辑)
		log.Printf("[路由] %s -> 走 QUIC 隧道", hostname)
		handleProxyConnection(clientConn, targetAddress)
	} else {
		// 如果 ShouldProxy 返回 false：直接本地 net.Dial 连接目标地址 (实现直连)
		log.Printf("[路由] %s -> 直连", hostname)
		handleDirectConnection(clientConn, targetAddress)
	}
}

// handleProxyConnection 处理代理连接（走 QUIC 隧道）
func handleProxyConnection(clientConn net.Conn, targetAddress string) {
	// 隧道传输：调用全局 QUIC 连接的 conn.OpenStreamSync 打开一个新流
	conn := getQuicConnection()
	if conn == nil {
		log.Println("QUIC 连接不存在，尝试重连...")
		quicConnLock.Lock()
		if err := reconnectQuic(); err != nil {
			log.Printf("重连失败: %v", err)
			clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
			quicConnLock.Unlock()
			return
		}
		conn = quicConn
		quicConnLock.Unlock()
	}

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Printf("打开 QUIC 流失败: %v", err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer stream.Close()

	// 鉴权：在打开 QUIC Stream 后，第一个动作是发送这个 Token (字符串 + 换行符)
	tokenWithNewline := UAP_TOKEN + "\n"
	_, err = stream.Write([]byte(tokenWithNewline))
	if err != nil {
		log.Printf("发送 Token 失败: %v", err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// 等待服务端验证结果（读取 1 字节，0x00 成功，0x01 失败）
	statusBuf := make([]byte, 1)
	_, err = io.ReadFull(stream, statusBuf)
	if err != nil {
		log.Printf("读取 Token 验证结果失败: %v", err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	if statusBuf[0] != 0x00 {
		log.Printf("Token 验证失败，状态码: %d", statusBuf[0])
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	log.Printf("[鉴权] Token 验证成功，开始发送数据")

	// 验证成功后，才开始发送 SOCKS5/UDP 数据
	// 写入协议：先写 1 字节长度，再写地址字符串
	addressBytes := []byte(targetAddress)
	if len(addressBytes) > 255 {
		log.Printf("目标地址过长: %s", targetAddress)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// 写入地址长度（1字节）
	_, err = stream.Write([]byte{byte(len(addressBytes))})
	if err != nil {
		log.Printf("写入地址长度失败: %v", err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// 写入地址字符串
	_, err = stream.Write(addressBytes)
	if err != nil {
		log.Printf("写入目标地址失败: %v", err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// 等待确认：读取服务端回的 1 个字节。如果是 0x00，代表服务端连上了
	_, err = io.ReadFull(stream, statusBuf)
	if err != nil {
		log.Printf("读取服务端状态失败: %v", err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	if statusBuf[0] != 0x00 {
		log.Printf("服务端连接失败，状态码: %d", statusBuf[0])
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// 响应浏览器：此时才给浏览器发 SOCKS5 成功包 (0x05 0x00 ...)
	// SOCKS5 成功响应格式: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(4) + BND.PORT(2)
	response := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err = clientConn.Write(response)
	if err != nil {
		log.Printf("发送 SOCKS5 成功响应失败: %v", err)
		return
	}

	log.Printf("[SOCKS5 TCP] 代理连接 %s 已建立，开始转发数据", targetAddress)

	// 转发：使用缓冲池复用的 copyBuffer
	errChan := make(chan error, 2)

	// 从客户端复制到 QUIC 流
	go func() {
		_, err := copyBuffer(stream, clientConn)
		errChan <- err
	}()

	// 从 QUIC 流复制到客户端
	go func() {
		_, err := copyBuffer(clientConn, stream)
		errChan <- err
	}()

	// 等待任一方向完成
	<-errChan
	log.Printf("[SOCKS5 TCP] 代理连接 %s 已关闭", targetAddress)
}

// handleDirectConnection 处理直连（不走代理）
func handleDirectConnection(clientConn net.Conn, targetAddress string) {
	// 直接本地 net.Dial 连接目标地址
	targetConn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		log.Printf("直连目标失败 %s: %v", targetAddress, err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer targetConn.Close()

	// 响应浏览器：发送 SOCKS5 成功包
	// SOCKS5 成功响应格式: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(4) + BND.PORT(2)
	response := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err = clientConn.Write(response)
	if err != nil {
		log.Printf("发送 SOCKS5 成功响应失败: %v", err)
		return
	}

	log.Printf("[SOCKS5 TCP] 直连 %s 已建立，开始转发数据", targetAddress)

	// 转发：使用缓冲池复用的 copyBuffer
	errChan := make(chan error, 2)

	// 从客户端复制到目标连接
	go func() {
		_, err := copyBuffer(targetConn, clientConn)
		errChan <- err
	}()

	// 从目标连接复制到客户端
	go func() {
		_, err := copyBuffer(clientConn, targetConn)
		errChan <- err
	}()

	// 等待任一方向完成
	<-errChan
	log.Printf("[SOCKS5 TCP] 直连 %s 已关闭", targetAddress)
}

// handleUDPAssociate 处理 UDP ASSOCIATE 命令
func handleUDPAssociate(clientConn net.Conn, addrType byte) {
	// 跳过地址解析（UDP ASSOCIATE 请求中的地址通常被忽略）
	// 但为了完整性，我们还是读取它
	_, err := parseAddress(clientConn, addrType)
	if err != nil {
		log.Printf("解析 UDP ASSOCIATE 地址失败: %v", err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	log.Printf("[SOCKS5 UDP] 收到 UDP ASSOCIATE 请求")

	// 开启一个本地 UDP 监听 (net.ListenUDP)，假设地址是 127.0.0.1:UDP_PORT
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		log.Printf("解析 UDP 地址失败: %v", err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("启动 UDP 监听失败: %v", err)
		clientConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer udpConn.Close()

	localUDPAddr := udpConn.LocalAddr().(*net.UDPAddr)
	log.Printf("[SOCKS5 UDP] 本地 UDP 监听已启动: %s", localUDPAddr)

	// 回复 TCP：告诉游戏客户端 BND.ADDR=127.0.0.1, BND.PORT=UDP_PORT
	// SOCKS5 UDP ASSOCIATE 响应格式: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(4) + BND.PORT(2)
	response := make([]byte, 10)
	response[0] = 0x05 // VER
	response[1] = 0x00 // REP (成功)
	response[2] = 0x00 // RSV
	response[3] = 0x01 // ATYP (IPv4)
	// BND.ADDR (127.0.0.1)
	response[4] = 127
	response[5] = 0
	response[6] = 0
	response[7] = 1
	// BND.PORT
	binary.BigEndian.PutUint16(response[8:10], uint16(localUDPAddr.Port))

	_, err = clientConn.Write(response)
	if err != nil {
		log.Printf("发送 UDP ASSOCIATE 响应失败: %v", err)
		return
	}

	log.Printf("[SOCKS5 UDP] 已告知客户端使用 UDP 端口: %d", localUDPAddr.Port)

	// 获取 QUIC 连接
	conn := getQuicConnection()
	if conn == nil {
		log.Println("QUIC 连接不存在，尝试重连...")
		quicConnLock.Lock()
		if err := reconnectQuic(); err != nil {
			log.Printf("重连失败: %v", err)
			quicConnLock.Unlock()
			return
		}
		conn = quicConn
		quicConnLock.Unlock()
	}

	// 定义一个线程安全的变量来存储 UDP 客户端地址
	var currentClientAddr atomic.Value // 存储 *net.UDPAddr

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: Read 循环 (本地 -> QUIC)
	// 循环读取本地 UDP Socket，读到的数据是包含 SOCKS5 头部的，直接透传
	go func() {
		defer wg.Done()
		log.Printf("[SOCKS5 UDP] 启动本地 UDP 读取循环 (Local -> Remote)")

		buffer := make([]byte, 65535)
		for {
			// 设置 UDP 读取超时，以便可以检查 TCP 连接状态
			udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, clientAddr, err := udpConn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// 超时，检查 TCP 连接是否还活着
					clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
					oneByte := make([]byte, 1)
					_, err := clientConn.Read(oneByte)
					if err == nil {
						// TCP 连接还活着，继续
						continue
					}
					// TCP 连接已断开
					log.Printf("[SOCKS5 UDP] TCP 控制连接已断开")
					return
				}
				log.Printf("[SOCKS5 UDP] 读取本地 UDP 数据失败: %v", err)
				return
			}

			if n > 0 {
				// 关键动作：每次收到包，都更新 currentClientAddr = addr
				currentClientAddr.Store(clientAddr)

				// 读到的数据是包含 SOCKS5 头部的完整数据包
				packetData := buffer[:n]
				// 日志打印：收到 UDP 包，来源: [addr]
				log.Printf("[SOCKS5 UDP] 收到 UDP 包，来源: %s，长度: %d", clientAddr, n)

				// 直接透传：不要修改任何字节，直接调用 quicConnection.SendDatagram(packet) 扔进隧道
				err = conn.SendDatagram(packetData)
				if err != nil {
					log.Printf("[SOCKS5 UDP] 发送数据报到服务端失败: %v", err)
					continue
				}

				log.Printf("[SOCKS5 UDP] 已透传数据包到服务端")
			}
		}
	}()

	// Goroutine 2: Write 循环 (QUIC -> 本地)
	// 启动 goroutine 循环 quicConnection.ReceiveDatagram()，收到数据后直接回写
	go func() {
		defer wg.Done()
		log.Printf("[SOCKS5 UDP] 启动服务端 UDP 数据包接收循环 (Remote -> Local)")

		for {
			// 循环调用 quicConnection.ReceiveDatagram()
			data, err := conn.ReceiveDatagram(context.Background())
			if err != nil {
				log.Printf("[SOCKS5 UDP] 接收服务端数据报失败: %v", err)
				// 如果连接关闭，退出循环
				if err == io.EOF || err == context.Canceled {
					return
				}
				continue
			}

			if len(data) > 0 {
				log.Printf("[SOCKS5 UDP] 收到服务端数据报，长度: %d", len(data))

				// 关键动作：获取当前的 addr := currentClientAddr
				addrInterface := currentClientAddr.Load()
				if addrInterface == nil {
					// 检查：如果 addr 是 nil (还没收到过包)，丢弃数据或打印警告
					log.Printf("[SOCKS5 UDP] 警告：收到回包但还没有客户端地址，丢弃数据包")
					continue
				}

				addr, ok := addrInterface.(*net.UDPAddr)
				if !ok || addr == nil {
					log.Printf("[SOCKS5 UDP] 警告：客户端地址无效，丢弃数据包")
					continue
				}

				// 收到数据（服务端封装好的 SOCKS5 UDP 包）
				// 发送：udpConn.WriteToUDP(data, addr) (注意一定要用这个 addr)
				_, err = udpConn.WriteToUDP(data, addr)
				if err != nil {
					log.Printf("[SOCKS5 UDP] 写入本地 UDP Socket 失败: %v", err)
					continue
				}

				// 日志打印：回复 UDP 包给: [addr]
				log.Printf("[SOCKS5 UDP] 回复 UDP 包给: %s", addr)
			}
		}
	}()

	// 保持 TCP 连接：此时 TCP 连接不能断（断了代表会话结束），要挂起等待
	// 等待两个 goroutine 完成（当 TCP 连接断开时，UDP 读取循环会退出）
	wg.Wait()
	log.Printf("[SOCKS5 UDP] UDP ASSOCIATE 会话已结束")
}
