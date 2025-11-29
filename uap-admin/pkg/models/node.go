package models

// Node 节点模型
type Node struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	Name      string `json:"name"`                          // 节点名称 (e.g. "🇺🇸 美国高速-01")
	Address   string `json:"address"`                       // 域名:端口 (e.g. "uaptest.org:52222")
	PublicKey string `gorm:"uniqueIndex" json:"public_key"` // 该节点的 Ed25519 公钥 (用于客户端验签，唯一)
	Region    string `json:"region"`                        // 地区 (US, JP, HK)
	IsVIP     bool   `json:"is_vip"`                        // 是否 VIP 节点
	Status    int    `json:"status"`                        // 1:在线, 0:下线
}

// TableName 指定表名
func (Node) TableName() string {
	return "nodes"
}
