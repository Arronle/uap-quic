package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"

	"uap-quic/pkg/core"
)

// UAP_TOKEN 鉴权 Token（必须与服务端一致）
const UAP_TOKEN = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NjQ5NzI2OTgsImlhdCI6MTc2NDM2Nzg5OCwidXVpZCI6ImRhOThlNTQ4LTVjZTctNGY1ZC1iNGU3LTVmZDFhZjMwZDQzYyJ9.sWlvo33C9BgGmM0wI3XsYk03r2uPKrSwqkTwNzMBVlwijx7phWhALiwk3DXFmRqf5JGn6vhN_WtRO9LBXmVvDg"

// Node 节点结构体
type Node struct {
	Name    string        `json:"name"`
	Address string        `json:"address"`
	Latency time.Duration `json:"-"` // 延迟（不序列化到 JSON）
	// 其他字段暂时忽略
}

// APIResponse API 响应结构体
type APIResponse struct {
	Code int    `json:"code"`
	Data []Node `json:"data"`
	Msg  string `json:"msg,omitempty"`
}

// fetchNodeList 从 API 获取节点列表
func fetchNodeList() []Node {
	// 构建请求
	req, err := http.NewRequest("GET", "http://localhost:8080/api/v1/client/nodes", nil)
	if err != nil {
		log.Printf("❌ 创建请求失败: %v", err)
		return nil
	}

	// 设置 Authorization Header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", UAP_TOKEN))

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("❌ 请求失败: %v", err)
		return nil
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("❌ 读取响应失败: %v", err)
		return nil
	}

	// 检查状态码
	if resp.StatusCode != http.StatusOK {
		log.Printf("❌ API 返回错误状态码: %d, 响应: %s", resp.StatusCode, string(body))
		return nil
	}

	// 解析 JSON
	var apiResp APIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		log.Printf("❌ 解析 JSON 失败: %v, 响应: %s", err, string(body))
		return nil
	}

	// 检查响应码
	if apiResp.Code != 200 {
		log.Printf("❌ API 返回错误: code=%d, msg=%s", apiResp.Code, apiResp.Msg)
		return nil
	}

	// 检查节点列表是否为空
	if len(apiResp.Data) == 0 {
		log.Printf("⚠️  节点列表为空")
		return nil
	}

	return apiResp.Data
}

// PingNodes 并发测速所有节点
func PingNodes(nodes []Node) []Node {
	if len(nodes) == 0 {
		return nodes
	}

	log.Printf("🚀 开始测速，共 %d 个节点...", len(nodes))

	var wg sync.WaitGroup
	var mu sync.Mutex
	const timeout = 2 * time.Second
	const maxLatency = time.Duration(1<<63 - 1) // 无穷大（最大 time.Duration 值）

	// 并发测速所有节点
	for i := range nodes {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			node := &nodes[idx]
			start := time.Now()

			// 尝试建立 TCP 连接
			conn, err := net.DialTimeout("tcp", node.Address, timeout)
			if err != nil {
				// 连接失败或超时，设置为无穷大
				mu.Lock()
				node.Latency = maxLatency
				mu.Unlock()
				return
			}
			conn.Close()

			// 记录延迟
			latency := time.Since(start)
			mu.Lock()
			node.Latency = latency
			mu.Unlock()
		}(i)
	}

	// 等待所有测速完成
	wg.Wait()

	// 根据延迟排序（从小到大）
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Latency < nodes[j].Latency
	})

	// 打印测速结果
	log.Printf("[测速结果]")
	for _, node := range nodes {
		if node.Latency == maxLatency {
			log.Printf("  %s: 超时/失败", node.Name)
		} else {
			latencyMs := node.Latency.Round(time.Millisecond)
			log.Printf("  %s: %v", node.Name, latencyMs)
		}
	}

	return nodes
}

func main() {
	// 解析命令行参数
	var mode string
	var serverAddr string
	var localPort int
	var whitelistFile string

	flag.StringVar(&mode, "mode", "smart", "代理模式: smart (白名单) 或 global (全局)")
	flag.StringVar(&serverAddr, "server", "uaptest.org:52222", "服务端地址")
	flag.IntVar(&localPort, "port", 1080, "本地 SOCKS5 监听端口")
	flag.StringVar(&whitelistFile, "whitelist", "whitelist.txt", "白名单文件路径")
	flag.Parse()

	// 尝试动态获取节点列表
	log.Println("🔍 正在从 API 获取节点列表...")
	nodes := fetchNodeList()

	if len(nodes) > 0 {
		// 对节点进行测速并排序
		nodes = PingNodes(nodes)

		// 选择延迟最低的节点（排序后的第一个）
		bestNode := nodes[0]
		if bestNode.Latency == time.Duration(1<<63-1) {
			// 所有节点都超时，使用默认地址
			log.Printf("⚠️  所有节点测速失败，使用默认地址: %s", serverAddr)
		} else {
			// 使用最快的节点
			serverAddr = bestNode.Address
			log.Printf("✅ 智能选路完成，当前连接: [%s] -> [%s] (延迟: %v)", bestNode.Name, serverAddr, bestNode.Latency.Round(time.Millisecond))
		}
	} else {
		// 获取失败，使用默认的备用地址
		log.Printf("⚠️  获取节点列表失败，使用默认地址: %s", serverAddr)
	}

	// 创建客户端实例
	client := core.NewClient(serverAddr, UAP_TOKEN, localPort, mode)

	// 处理信号，优雅退出
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// 启动客户端（阻塞）
	go func() {
		if err := client.Start(whitelistFile); err != nil {
			log.Fatalf("❌ 客户端启动失败: %v", err)
		}
	}()

	// 等待退出信号
	<-sigChan
	log.Println("\n🛑 收到退出信号，正在关闭...")
	client.Stop()
}
