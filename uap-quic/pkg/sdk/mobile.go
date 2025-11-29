package sdk

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"uap-quic/pkg/core"
)

// API 服务器地址（可根据需要修改）
const apiBaseURL = "http://localhost:8080/api/v1/client/nodes"

// 备用节点地址（当 API 拉取失败时使用）
const fallbackNodeAddr = "uaptest.org:52222"

// node 节点结构体（未导出，仅内部使用）
type node struct {
	Name    string        `json:"name"`
	Address string        `json:"address"`
	Latency time.Duration `json:"-"` // 延迟（不序列化到 JSON）
}

// apiResponse API 响应结构体（未导出，仅内部使用）
type apiResponse struct {
	Code int    `json:"code"`
	Data []node `json:"data"`
	Msg  string `json:"msg,omitempty"`
}

// fetchNodeList 从 API 获取节点列表
func fetchNodeList(token string) []node {
	// 构建请求
	req, err := http.NewRequest("GET", apiBaseURL, nil)
	if err != nil {
		log.Printf("❌ 创建请求失败: %v", err)
		return nil
	}

	// 设置 Authorization Header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// 发送请求
	client := &http.Client{
		Timeout: 10 * time.Second, // 设置超时
	}
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
	var apiResp apiResponse
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

// pingNodes 并发测速所有节点
func pingNodes(nodes []node) []node {
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

// Start 移动端启动方法（智能选路版本）
// token: 鉴权密钥（不再需要 host 参数，会自动从 API 获取节点并选路）
// port: 本地 SOCKS5 监听端口 (e.g., 1080)
// mode: 代理模式 ("smart" 或 "global")
// rules: 路由规则字符串 (换行符分隔，空字符串表示使用默认文件)
func Start(token string, port int, mode string, rules string) error {
	clientLock.Lock()
	defer clientLock.Unlock()

	// 如果已经启动，先停止
	if client != nil {
		client.Stop()
		client = nil
	}

	var serverAddr string

	// 1. 尝试从 API 获取节点列表
	log.Println("🔍 正在从 API 获取节点列表...")
	nodes := fetchNodeList(token)

	if len(nodes) > 0 {
		// 2. 对节点进行测速并排序
		nodes = pingNodes(nodes)

		// 3. 选择延迟最低的节点（排序后的第一个）
		bestNode := nodes[0]
		const maxLatency = time.Duration(1<<63 - 1)
		if bestNode.Latency == maxLatency {
			// 所有节点都超时，使用备用地址
			log.Printf("⚠️  所有节点测速失败，使用备用节点: %s", fallbackNodeAddr)
			serverAddr = fallbackNodeAddr
		} else {
			// 使用最快的节点
			serverAddr = bestNode.Address
			latencyMs := bestNode.Latency.Round(time.Millisecond)
			log.Printf("[SDK] 选中节点: %s (%v)", bestNode.Name, latencyMs)
		}
	} else {
		// 获取失败，使用备用节点
		log.Printf("⚠️  获取节点列表失败，使用备用节点: %s", fallbackNodeAddr)
		serverAddr = fallbackNodeAddr
	}

	// 4. 创建客户端实例
	client = core.NewClient(serverAddr, token, port, mode)

	// 5. 如果提供了规则字符串，写入临时文件
	whitelistFile := "whitelist.txt"
	if rules != "" {
		// 这里可以扩展为写入临时文件，暂时使用默认文件
		// 实际使用时，可以通过 core.Client 的接口扩展来支持直接传入规则
		whitelistFile = "whitelist.txt"
	}

	// 6. 在 goroutine 中启动（非阻塞）
	go func() {
		if err := client.Start(whitelistFile); err != nil {
			log.Printf("❌ SDK 启动失败: %v", err)
		}
	}()

	return nil
}

