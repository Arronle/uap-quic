package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// UAP_TOKEN 鉴权 Token（实际使用时应从配置读取）
const UAP_TOKEN = "uap-secret-token-8888"

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
	// 解析命令行参数
	certFile := flag.String("cert", "", "TLS 证书文件路径（必需）")
	keyFile := flag.String("key", "", "TLS 私钥文件路径（必需）")
	flag.Parse()

	// 强制检查证书和私钥参数
	if *certFile == "" || *keyFile == "" {
		log.Fatal("❌ 错误: 必须提供 -cert 和 -key 参数")
	}

	// 强制加载证书文件：如果加载失败，必须直接 log.Fatal 退出程序
	tlsCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("❌ 加载 TLS 证书失败: %v (请检查文件路径和权限)", err)
	}

	// 成功加载证书后，打印日志
	log.Printf("✅ 成功加载 TLS 证书: %s", *certFile)

	// 配置 TLS（伪装成标准的 HTTP/3 流量）
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h3"}, // h3 是国际标准的 HTTP/3 协议代号
	}

	// 配置 QUIC（启用数据报以支持 UDP 转发，并配置 Keep-Alive）
	quicConfig := &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  time.Hour * 24 * 365, // 允许连接闲置 1 年
		KeepAlivePeriod: 10 * time.Second,     // 每 10 秒发送一次心跳
	}

	// 监听地址
	addr := "0.0.0.0:443"
	listener, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	defer listener.Close()

	log.Printf("QUIC 服务端已启动，监听地址: %s", addr)

	// 循环接受连接
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}

		log.Printf("新连接已建立: %s", conn.RemoteAddr())

		// 为每个连接启动一个 goroutine 处理
		go handleConnection(conn)
	}
}

func handleConnection(conn quic.Connection) {
	defer conn.CloseWithError(0, "连接关闭")

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: 处理 QUIC Stream（TCP 连接）
	go func() {
		defer wg.Done()
		// 循环接受流
		for {
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				log.Printf("接受流失败: %v", err)
				return
			}

			log.Printf("新流已建立: StreamID=%d", stream.StreamID())

			// 为每个流启动一个 goroutine 处理
			go handleStream(stream)
		}
	}()

	// Goroutine 2: 处理 QUIC Datagram（UDP 数据包）
	// 这个函数内部会创建 UDP Socket 并启动两个子循环：接收循环和发送循环
	go func() {
		defer wg.Done()
		handleDatagrams(conn)
	}()

	// 等待所有 goroutine 完成
	wg.Wait()
	log.Printf("[QUIC] 连接 %s 已关闭", conn.RemoteAddr())
}

func handleStream(stream quic.Stream) {
	defer stream.Close()

	// 鉴权：在 AcceptStream 后，先读取 Token
	if !verifyToken(stream) {
		// 验证失败，不继续处理
		return
	}

	// 协议解析：读取 1 个字节（长度 N）
	lengthBuf := make([]byte, 1)
	_, err := io.ReadFull(stream, lengthBuf)
	if err != nil {
		log.Printf("读取地址长度失败: %v", err)
		return
	}

	addressLen := int(lengthBuf[0])
	if addressLen <= 0 || addressLen > 255 {
		log.Printf("无效的地址长度: %d", addressLen)
		stream.Write([]byte{0x01}) // 失败信号
		return
	}

	// 读取 N 个字节（目标地址字符串）
	addressBuf := make([]byte, addressLen)
	_, err = io.ReadFull(stream, addressBuf)
	if err != nil {
		log.Printf("读取目标地址失败: %v", err)
		stream.Write([]byte{0x01}) // 失败信号
		return
	}

	targetAddress := string(addressBuf)
	log.Printf("[QUIC TCP] 请求连接: %s", targetAddress)

	// 连接目标：使用 net.Dial("tcp", target_address) 连接目标网站
	targetConn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		log.Printf("连接目标失败 %s: %v", targetAddress, err)
		stream.Write([]byte{0x01}) // 失败信号
		return
	}
	defer targetConn.Close()

	// 连接成功，向流写入 0x00 (成功信号)
	_, err = stream.Write([]byte{0x00})
	if err != nil {
		log.Printf("发送成功信号失败: %v", err)
		return
	}

	// 双向转发：使用缓冲池复用的 copyBuffer
	errChan := make(chan error, 2)

	// 从 QUIC 流复制到目标连接
	go func() {
		_, err := copyBuffer(targetConn, stream)
		errChan <- err
	}()

	// 从目标连接复制到 QUIC 流
	go func() {
		_, err := copyBuffer(stream, targetConn)
		errChan <- err
	}()

	// 等待任一方向完成
	<-errChan
	log.Printf("[QUIC TCP] 连接 %s 已关闭", targetAddress)
}

// verifyToken 验证客户端 Token
// 如果 Token 匹配：回复 0x00，继续后续逻辑
// 如果 Token 不匹配：延迟后回复随机 HTML，伪装成网页服务器
func verifyToken(stream quic.Stream) bool {
	// 设置读取超时
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))

	// 读取 Token（字符串 + 换行符）
	reader := bufio.NewReader(stream)
	token, err := reader.ReadString('\n')
	if err != nil {
		// 读取失败，可能是探测
		log.Printf("[鉴权] 读取 Token 失败: %v", err)
		handleInvalidToken(stream)
		return false
	}

	// 去除换行符并验证
	token = strings.TrimSpace(token)
	if token == UAP_TOKEN {
		// Token 匹配：回复 0x00，继续后续逻辑
		stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = stream.Write([]byte{0x00})
		if err != nil {
			log.Printf("[鉴权] 发送验证成功信号失败: %v", err)
			return false
		}
		log.Printf("[鉴权] Token 验证成功")
		return true
	}

	// Token 不匹配
	log.Printf("[鉴权] Token 验证失败: 收到 '%s'", token)
	handleInvalidToken(stream)
	return false
}

// handleInvalidToken 处理无效 Token（防探测）
// 不要立即断开！使用随机延迟后回复随机 HTML，伪装成网页服务器
func handleInvalidToken(stream quic.Stream) {
	// 关键点 (防探测)：如果 Token 不匹配，或者数据格式不对：
	// 不要立即断开！(立即断开也是特征)
	// 甚至不要回复错误！
	// 而是使用 time.Sleep 随机延迟几秒，然后回复一段随机的 HTML 代码（伪装成网页服务器报错），最后关闭连接

	// 随机延迟 2-5 秒
	delay := time.Duration(2+rand.Intn(3)) * time.Second
	time.Sleep(delay)

	// 回复随机的 HTML 代码（伪装成网页服务器报错）
	htmlResponses := []string{
		"HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n<html><body><h1>400 Bad Request</h1></body></html>",
		"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<html><body><h1>404 Not Found</h1></body></html>",
		"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<html><body><h1>500 Internal Server Error</h1></body></html>",
		"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/html\r\n\r\n<html><body><h1>503 Service Unavailable</h1></body></html>",
	}

	response := htmlResponses[rand.Intn(len(htmlResponses))]
	stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	stream.Write([]byte(response))

	// 最后关闭连接
	time.Sleep(100 * time.Millisecond)
}

// handleDatagrams 处理来自客户端的 QUIC Datagram（UDP 数据包）
// 这个函数包含两个循环：
// 1. 接收循环：从 QUIC 接收 Datagram，解析 SOCKS5 头部，转发到目标服务器
// 2. 发送循环：从 UDP Socket 接收回包，封装 SOCKS5 头部，发送回客户端
func handleDatagrams(conn quic.Connection) {
	log.Printf("[UDP] 启动 Datagram 处理")

	// 创建 UDP 出口：在 handleDatagrams 开始时，创建一个 net.ListenUDP("udp", nil)，这是该用户的专用出口
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Printf("[UDP] 创建 UDP Socket 失败: %v", err)
		return
	}
	defer udpConn.Close()

	log.Printf("[UDP] 已创建 UDP 出口: %s", udpConn.LocalAddr())

	var wg sync.WaitGroup
	wg.Add(2)

	// 发送流程 (Client -> Server -> Target)：循环读取 sess.ReceiveDatagram
	go func() {
		defer wg.Done()
		log.Printf("[UDP] 启动发送流程 (Client -> Server -> Target)")

		for {
			// 循环调用 conn.ReceiveDatagram()
			data, err := conn.ReceiveDatagram(context.Background())
			if err != nil {
				log.Printf("[UDP] 接收 Datagram 失败: %v", err)
				// 如果连接关闭，退出循环
				if err == io.EOF || err == context.Canceled {
					return
				}
				continue
			}

			if len(data) == 0 {
				continue
			}

			log.Printf("[UDP] 收到 Datagram，长度: %d", len(data))

			// 解析 SOCKS5 头部（关键）
			// SOCKS5 UDP 数据包格式: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(variable) + DST.PORT(2) + DATA(variable)
			targetAddr, payload, err := parseSOCKS5UDPHeader(data)
			if err != nil {
				log.Printf("[UDP] 解析 SOCKS5 头部失败: %v", err)
				continue
			}

			// 日志：打印 [UDP] 转发 N 字节到 目标地址
			log.Printf("[UDP] 转发 %d 字节到 %s", len(payload), targetAddr)

			// 使用刚才创建的 UDP Socket，只把 payload 发送给目标地址
			_, err = udpConn.WriteToUDP(payload, targetAddr)
			if err != nil {
				log.Printf("[UDP] 发送 UDP 数据包失败: %v", err)
				continue
			}
		}
	}()

	// 接收流程 (Target -> Server -> Client)：启动一个 goroutine 负责读取回包
	go func() {
		defer wg.Done()
		log.Printf("[UDP] 启动接收流程 (Target -> Server -> Client)")

		buffer := make([]byte, 65535)
		for {
			// 循环读取 UDP Socket
			n, sourceAddr, err := udpConn.ReadFromUDP(buffer)
			if err != nil {
				log.Printf("[UDP] 读取 UDP 数据失败: %v", err)
				// 如果 UDP Socket 关闭，退出循环
				if err == io.EOF {
					return
				}
				continue
			}

			if n > 0 {
				data := buffer[:n]
				log.Printf("[UDP] 收到来自 %s 的回包，长度: %d", sourceAddr, n)

				// 封装 SOCKS5 头部（关键）
				// 为了简化，可以硬编码 ATYP=0x01, IP=0.0.0.0, Port=0
				// 或者正确填入源地址
				socks5Packet := buildSOCKS5UDPHeader(sourceAddr, data)

				log.Printf("[UDP] 构建 SOCKS5 数据包，总长度: %d", len(socks5Packet))

				// 调用 conn.SendDatagram 发回给客户端
				err = conn.SendDatagram(socks5Packet)
				if err != nil {
					log.Printf("[UDP] 发送 Datagram 到客户端失败: %v", err)
					continue
				}

				log.Printf("[UDP] 已转发回包给客户端")
			}
		}
	}()

	// 等待两个循环完成
	wg.Wait()
	log.Printf("[UDP] Datagram 处理已停止")
}

// parseSOCKS5UDPHeader 解析 SOCKS5 UDP 数据包头部
// 返回目标地址和载荷数据
// SOCKS5 UDP 数据包格式: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(variable) + DST.PORT(2) + DATA(variable)
func parseSOCKS5UDPHeader(data []byte) (*net.UDPAddr, []byte, error) {
	// 最小长度检查：RSV(2) + FRAG(1) + ATYP(1) = 4 字节
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("数据包太短，至少需要 4 字节，实际: %d", len(data))
	}

	// 跳过前 3 个字节 (RSV, FRAG)
	// RSV[0] = data[0]
	// RSV[1] = data[1]
	// FRAG = data[2]

	// 第 4 个字节是 ATYP
	atyp := data[3]

	var targetAddr *net.UDPAddr
	var dataStart int

	switch atyp {
	case 0x01: // IPv4
		// IPv4: 读取接下来的 4 字节 IP + 2 字节 Port
		// 总长度: 3(RSV+FRAG) + 1(ATYP) + 4(IP) + 2(PORT) = 10 字节
		if len(data) < 10 {
			return nil, nil, fmt.Errorf("IPv4 数据包太短，需要至少 10 字节，实际: %d", len(data))
		}
		ip := net.IP(data[4:8])
		port := binary.BigEndian.Uint16(data[8:10])
		targetAddr = &net.UDPAddr{IP: ip, Port: int(port)}
		dataStart = 10

	case 0x03: // Domain
		// Domain: 读取 1 字节长度 -> 读取域名 -> 读取 2 字节 Port
		if len(data) < 5 {
			return nil, nil, fmt.Errorf("Domain 数据包太短，需要至少 5 字节，实际: %d", len(data))
		}
		domainLen := int(data[4])
		if domainLen == 0 || domainLen > 255 {
			return nil, nil, fmt.Errorf("无效的域名长度: %d", domainLen)
		}
		// 总长度: 3(RSV+FRAG) + 1(ATYP) + 1(LEN) + domainLen + 2(PORT) = 7 + domainLen
		if len(data) < 7+domainLen {
			return nil, nil, fmt.Errorf("Domain 数据包太短，需要至少 %d 字节，实际: %d", 7+domainLen, len(data))
		}
		domain := string(data[5 : 5+domainLen])
		port := binary.BigEndian.Uint16(data[5+domainLen : 7+domainLen])
		// 解析域名
		ip, err := net.ResolveIPAddr("ip", domain)
		if err != nil {
			return nil, nil, fmt.Errorf("解析域名失败 %s: %v", domain, err)
		}
		targetAddr = &net.UDPAddr{IP: ip.IP, Port: int(port)}
		dataStart = 7 + domainLen

	case 0x04: // IPv6
		// IPv6: 读取 16 字节 IP + 2 字节 Port
		// 总长度: 3(RSV+FRAG) + 1(ATYP) + 16(IP) + 2(PORT) = 22 字节
		if len(data) < 22 {
			return nil, nil, fmt.Errorf("IPv6 数据包太短，需要至少 22 字节，实际: %d", len(data))
		}
		ip := net.IP(data[4:20])
		port := binary.BigEndian.Uint16(data[20:22])
		targetAddr = &net.UDPAddr{IP: ip, Port: int(port)}
		dataStart = 22

	default:
		return nil, nil, fmt.Errorf("不支持的地址类型: %d", atyp)
	}

	// 提取载荷：剩下的字节才是真正的 payload
	if dataStart > len(data) {
		return nil, nil, fmt.Errorf("数据包长度不足，需要至少 %d 字节，实际: %d", dataStart, len(data))
	}

	payload := data[dataStart:]
	return targetAddr, payload, nil
}

// buildSOCKS5UDPHeader 构建 SOCKS5 UDP 数据包头部
// 封装 SOCKS5 头部：构造一个虚拟的 SOCKS5 头部
// 为了简化，可以硬编码 ATYP=0x01, IP=0.0.0.0, Port=0
// 或者正确填入源地址
func buildSOCKS5UDPHeader(sourceAddr *net.UDPAddr, payload []byte) []byte {
	var socks5Header []byte

	// RSV(2) + FRAG(1) = 3 字节
	socks5Header = append(socks5Header, 0x00, 0x00, 0x00)

	// 根据源地址类型构建头部
	// 如果源地址有效，使用源地址；否则使用 0.0.0.0:0
	if sourceAddr != nil && sourceAddr.IP != nil {
		ip := sourceAddr.IP
		if ip.To4() != nil {
			// IPv4
			socks5Header = append(socks5Header, 0x01) // ATYP
			socks5Header = append(socks5Header, ip.To4()...)
			portBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(portBytes, uint16(sourceAddr.Port))
			socks5Header = append(socks5Header, portBytes...)
		} else {
			// IPv6
			socks5Header = append(socks5Header, 0x04) // ATYP
			socks5Header = append(socks5Header, ip.To16()...)
			portBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(portBytes, uint16(sourceAddr.Port))
			socks5Header = append(socks5Header, portBytes...)
		}
	} else {
		// 简化处理：硬编码 ATYP=0x01, IP=0.0.0.0, Port=0
		socks5Header = append(socks5Header, 0x01)                   // ATYP (IPv4)
		socks5Header = append(socks5Header, 0x00, 0x00, 0x00, 0x00) // IP (0.0.0.0)
		socks5Header = append(socks5Header, 0x00, 0x00)             // Port (0)
	}

	// 拼接：Header + Data
	return append(socks5Header, payload...)
}
