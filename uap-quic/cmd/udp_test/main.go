package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

func main() {
	log.Println("=== SOCKS5 UDP 隧道测试程序 ===")
	log.Println("正在连接 SOCKS5 代理: 127.0.0.1:1080")

	// TCP 协商：连接 127.0.0.1:1080
	tcpConn, err := net.Dial("tcp", "127.0.0.1:1080")
	if err != nil {
		log.Fatalf("连接 SOCKS5 代理失败: %v", err)
	}
	defer tcpConn.Close()

	log.Println("✅ TCP 连接已建立")

	// SOCKS5 握手
	// 发送: VER(1) + NMETHODS(1) + METHODS(NMETHODS)
	handshake := []byte{0x05, 0x01, 0x00} // VER=5, NMETHODS=1, METHOD=0 (无认证)
	_, err = tcpConn.Write(handshake)
	if err != nil {
		log.Fatalf("发送握手失败: %v", err)
	}

	// 读取握手响应: VER(1) + METHOD(1)
	handshakeResp := make([]byte, 2)
	_, err = io.ReadFull(tcpConn, handshakeResp)
	if err != nil {
		log.Fatalf("读取握手响应失败: %v", err)
	}

	if handshakeResp[0] != 0x05 {
		log.Fatalf("不支持的 SOCKS 版本: %d", handshakeResp[0])
	}

	if handshakeResp[1] != 0x00 {
		log.Fatalf("不支持的认证方法: %d", handshakeResp[1])
	}

	log.Println("✅ SOCKS5 握手成功")

	// 发送 UDP ASSOCIATE 请求
	// 格式: VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR(variable) + DST.PORT(2)
	// UDP ASSOCIATE 的地址通常被忽略，我们发送 0.0.0.0:0
	udpAssociateReq := []byte{
		0x05, // VER
		0x03, // CMD (UDP ASSOCIATE)
		0x00, // RSV
		0x01, // ATYP (IPv4)
		0x00, 0x00, 0x00, 0x00, // DST.ADDR (0.0.0.0)
		0x00, 0x00, // DST.PORT (0)
	}

	_, err = tcpConn.Write(udpAssociateReq)
	if err != nil {
		log.Fatalf("发送 UDP ASSOCIATE 请求失败: %v", err)
	}

	log.Println("✅ UDP ASSOCIATE 请求已发送")

	// 读取 UDP ASSOCIATE 响应
	// 格式: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(variable) + BND.PORT(2)
	response := make([]byte, 10)
	_, err = io.ReadFull(tcpConn, response)
	if err != nil {
		log.Fatalf("读取 UDP ASSOCIATE 响应失败: %v", err)
	}

	if response[0] != 0x05 {
		log.Fatalf("不支持的 SOCKS 版本: %d", response[0])
	}

	if response[1] != 0x00 {
		log.Fatalf("UDP ASSOCIATE 失败，错误码: %d", response[1])
	}

	// 解析 BND.ADDR 和 BND.PORT
	atyp := response[3]
	var bndAddr net.IP
	var bndPort uint16

	if atyp == 0x01 { // IPv4
		bndAddr = net.IP(response[4:8])
		bndPort = binary.BigEndian.Uint16(response[8:10])
	} else {
		log.Fatalf("不支持的地址类型: %d", atyp)
	}

	log.Printf("✅ 获取到 BND 地址: %s:%d", bndAddr, bndPort)

	// 构造 DNS 查询包（查询 google.com）
	dnsQuery := buildDNSQuery("google.com")
	log.Printf("✅ DNS 查询包已构造，长度: %d 字节", len(dnsQuery))

	// 封装 SOCKS5 UDP 头部
	// 格式: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(4) + DST.PORT(2) + DATA
	// 目标地址: 8.8.8.8:53
	targetIP := net.ParseIP("8.8.8.8")
	if targetIP == nil {
		log.Fatalf("无效的目标 IP: 8.8.8.8")
	}
	targetPort := uint16(53)

	socks5Header := make([]byte, 10)
	socks5Header[0] = 0x00 // RSV[0]
	socks5Header[1] = 0x00 // RSV[1]
	socks5Header[2] = 0x00 // FRAG
	socks5Header[3] = 0x01 // ATYP (IPv4)
	copy(socks5Header[4:8], targetIP.To4())
	binary.BigEndian.PutUint16(socks5Header[8:10], targetPort)

	// 组合 SOCKS5 头部 + DNS 查询
	udpPacket := append(socks5Header, dnsQuery...)
	log.Printf("✅ SOCKS5 UDP 数据包已封装，总长度: %d 字节", len(udpPacket))

	// 创建 UDP 连接
	udpConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   bndAddr,
		Port: int(bndPort),
	})
	if err != nil {
		log.Fatalf("创建 UDP 连接失败: %v", err)
	}
	defer udpConn.Close()

	log.Printf("✅ UDP 连接已建立，目标: %s:%d", bndAddr, bndPort)

	// 发送 UDP 数据包
	_, err = udpConn.Write(udpPacket)
	if err != nil {
		log.Fatalf("发送 UDP 数据包失败: %v", err)
	}

	log.Println("✅ UDP 数据包已发送，等待回复...")

	// 设置读取超时
	udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// 接收 UDP 回复
	recvBuffer := make([]byte, 65535)
	n, err := udpConn.Read(recvBuffer)
	if err != nil {
		log.Fatalf("接收 UDP 回复失败: %v", err)
	}

	log.Printf("✅ 收到 UDP 回复，长度: %d 字节", n)

	recvData := recvBuffer[:n]

	// 去掉 SOCKS5 头部
	if len(recvData) < 10 {
		log.Fatalf("回复数据包太短，无法解析 SOCKS5 头部")
	}

	// 验证 SOCKS5 头部
	if recvData[0] != 0x00 || recvData[1] != 0x00 || recvData[2] != 0x00 {
		log.Fatalf("无效的 SOCKS5 UDP 头部")
	}

	// 提取 DNS 响应（跳过 SOCKS5 头部）
	dnsResponse := recvData[10:]
	log.Printf("✅ DNS 响应已提取，长度: %d 字节", len(dnsResponse))

	// 解析 DNS 响应
	ips, err := parseDNSResponse(dnsResponse, "google.com")
	if err != nil {
		log.Fatalf("解析 DNS 响应失败: %v", err)
	}

	if len(ips) == 0 {
		log.Fatalf("DNS 响应中没有找到 IP 地址")
	}

	log.Printf("✅ DNS 解析成功，找到 %d 个 IP 地址:", len(ips))
	for i, ip := range ips {
		log.Printf("   %d. %s", i+1, ip)
	}

	// 输出成功信息
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("  ✅ UDP 隧道测试通过！游戏加速模式就绪！")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()
}

// buildDNSQuery 构造 DNS 查询包（查询指定域名）
func buildDNSQuery(domain string) []byte {
	// DNS 消息格式:
	// Header (12 bytes) + Question Section
	query := make([]byte, 0, 512)

	// DNS Header
	// ID (2 bytes) - 随机 ID
	query = append(query, 0x12, 0x34)
	// Flags (2 bytes) - 标准查询，递归查询
	query = append(query, 0x01, 0x00)
	// Questions (2 bytes) - 1 个问题
	query = append(query, 0x00, 0x01)
	// Answer RRs (2 bytes) - 0
	query = append(query, 0x00, 0x00)
	// Authority RRs (2 bytes) - 0
	query = append(query, 0x00, 0x00)
	// Additional RRs (2 bytes) - 0
	query = append(query, 0x00, 0x00)

	// Question Section
	// QNAME - 域名编码
	parts := splitDomain(domain)
	for _, part := range parts {
		query = append(query, byte(len(part)))
		query = append(query, []byte(part)...)
	}
	query = append(query, 0x00) // 结束标记

	// QTYPE (2 bytes) - A 记录
	query = append(query, 0x00, 0x01)
	// QCLASS (2 bytes) - IN
	query = append(query, 0x00, 0x01)

	return query
}

// splitDomain 分割域名
func splitDomain(domain string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if i > start {
				parts = append(parts, domain[start:i])
			}
			start = i + 1
		}
	}
	if start < len(domain) {
		parts = append(parts, domain[start:])
	}
	return parts
}

// parseDNSResponse 解析 DNS 响应，提取 IP 地址
func parseDNSResponse(data []byte, domain string) ([]net.IP, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("DNS 响应太短")
	}

	// 检查响应码
	flags := binary.BigEndian.Uint16(data[2:4])
	rcode := flags & 0x0F
	if rcode != 0 {
		return nil, fmt.Errorf("DNS 响应错误，RCODE: %d", rcode)
	}

	// 检查是否是响应
	if (flags&0x8000) == 0 {
		return nil, fmt.Errorf("不是 DNS 响应")
	}

	// 读取 Answer Count
	answerCount := binary.BigEndian.Uint16(data[6:8])
	if answerCount == 0 {
		return nil, fmt.Errorf("DNS 响应中没有答案")
	}

	var ips []net.IP

	// 跳过 Header (12 bytes) 和 Question Section
	offset := 12

	// 跳过 Question Section
	// 跳过 QNAME
	for offset < len(data) && data[offset] != 0 {
		if (data[offset] & 0xC0) == 0xC0 {
			// 压缩指针
			offset += 2
			break
		}
		offset += int(data[offset]) + 1
	}
	if offset < len(data) {
		offset++ // 跳过结束标记
	}
	// 跳过 QTYPE 和 QCLASS (4 bytes)
	offset += 4

	// 解析 Answer Section
	for i := 0; i < int(answerCount) && offset < len(data); i++ {
		// 跳过 NAME (可能是压缩指针)
		if offset >= len(data) {
			break
		}
		if (data[offset] & 0xC0) == 0xC0 {
			// 压缩指针
			offset += 2
		} else {
			// 跳过域名
			for offset < len(data) && data[offset] != 0 {
				offset += int(data[offset]) + 1
			}
			if offset < len(data) {
				offset++
			}
		}

		if offset+10 > len(data) {
			break
		}

		// 读取 TYPE (2 bytes)
		rrType := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		// 跳过 CLASS (2 bytes)
		offset += 2

		// 读取 TTL (4 bytes)
		offset += 4

		// 读取 RDLENGTH (2 bytes)
		rdLength := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		// 如果是 A 记录 (TYPE=1)，提取 IP
		if rrType == 1 && rdLength == 4 {
			if offset+4 <= len(data) {
				ip := net.IP(data[offset : offset+4])
				ips = append(ips, ip)
			}
		}

		offset += int(rdLength)
	}

	return ips, nil
}

