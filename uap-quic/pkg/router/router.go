package router

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Router 域名后缀树路由器
type Router struct {
	root *TrieNode
}

// TrieNode 后缀树节点
type TrieNode struct {
	children map[string]*TrieNode // 子节点映射（域名部分 -> 节点）
	isEnd    bool                 // 是否为规则终点
}

// NewRouter 创建新的路由器
func NewRouter() *Router {
	return &Router{
		root: &TrieNode{
			children: make(map[string]*TrieNode),
			isEnd:    false,
		},
	}
}

// AddRule 将域名倒序插入树中
// 例如：google.com -> com -> google (isEnd=true)
func (r *Router) AddRule(domain string) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return
	}

	// 转换为小写并分割域名部分
	parts := splitDomain(domain)
	if len(parts) == 0 {
		return
	}

	// 倒序插入（从 TLD 开始）
	current := r.root
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if part == "" {
			continue
		}

		// 如果子节点不存在，创建新节点
		if current.children[part] == nil {
			current.children[part] = &TrieNode{
				children: make(map[string]*TrieNode),
				isEnd:    false,
			}
		}

		current = current.children[part]
	}

	// 标记为规则终点
	current.isEnd = true
}

// ShouldProxy 将域名倒序在树中查找，如果匹配到节点是 isEnd，则返回 true
// 例如：www.google.com -> 查找 com -> google，如果 google 节点 isEnd=true，返回 true
func (r *Router) ShouldProxy(domain string) bool {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return false
	}

	// 转换为小写并分割域名部分
	parts := splitDomain(domain)
	if len(parts) == 0 {
		return false
	}

	// 倒序查找（从 TLD 开始）
	current := r.root
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if part == "" {
			continue
		}

		// 如果当前节点是规则终点，匹配成功
		if current.isEnd {
			return true
		}

		// 查找子节点
		child := current.children[part]
		if child == nil {
			// 没有匹配的子节点，查找失败
			return false
		}

		current = child
	}

	// 检查最后一个节点是否为规则终点
	return current.isEnd
}

// splitDomain 分割域名为部分
// 例如：www.google.com -> ["www", "google", "com"]
func splitDomain(domain string) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}

	// 移除末尾的点
	domain = strings.TrimSuffix(domain, ".")

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

// LoadRules 从文件加载规则
// 按行读取 whitelist.txt 并插入树中
func (r *Router) LoadRules(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		// 如果文件不存在，不报错（允许可选的白名单文件）
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("打开规则文件失败: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 添加规则
		r.AddRule(line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取规则文件失败: %v", err)
	}

	return nil
}

// GetRuleCount 获取规则数量（用于调试）
func (r *Router) GetRuleCount() int {
	return r.countNodes(r.root)
}

// countNodes 递归计算节点数量
func (r *Router) countNodes(node *TrieNode) int {
	if node == nil {
		return 0
	}

	count := 0
	if node.isEnd {
		count = 1
	}

	for _, child := range node.children {
		count += r.countNodes(child)
	}

	return count
}

