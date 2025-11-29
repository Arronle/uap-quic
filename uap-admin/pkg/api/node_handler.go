package api

import (
	"log"
	"strings"

	"uap-admin/pkg/models"
	"uap-admin/pkg/response"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// NodeRegisterRequest 节点注册请求
type NodeRegisterRequest struct {
	Name      string `json:"name" binding:"required"`
	Address   string `json:"address" binding:"required"`    // e.g. "1.2.3.4:443"
	PublicKey string `json:"public_key" binding:"required"` // 节点的公钥内容
	Region    string `json:"region" binding:"required"`     // e.g. "US"
}

// GetNodeList 获取节点列表（客户端使用）
func GetNodeList(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var nodes []models.Node

		// 查询所有 Status=1 的节点
		if err := db.Where("status = ?", 1).Find(&nodes).Error; err != nil {
			log.Printf("查询节点列表失败: %v", err)
			c.JSON(500, response.Error(500, "查询节点列表失败"))
			return
		}

		// 返回节点列表
		c.JSON(200, response.Success(nodes))
	}
}

// HandleNodeRegister 处理节点注册/更新（管理员接口）
func HandleNodeRegister(db *gorm.DB, adminSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 管理员鉴权：检查 X-Admin-Secret
		secret := c.GetHeader("X-Admin-Secret")
		if strings.TrimSpace(secret) != adminSecret {
			log.Printf("❌ 管理员密钥错误，拒绝节点注册请求")
			c.JSON(403, response.Error(403, "forbidden"))
			return
		}

		// 解析请求体
		var req NodeRegisterRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, response.Error(400, "参数错误"))
			return
		}

		// 使用 PublicKey 作为唯一键进行 upsert
		node := models.Node{
			Name:      req.Name,
			Address:   req.Address,
			PublicKey: req.PublicKey,
			Region:    req.Region,
			Status:    1, // 在线
		}

		if err := db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "public_key"}},
			DoUpdates: clause.AssignmentColumns([]string{"name", "address", "region", "status"}),
		}).Create(&node).Error; err != nil {
			log.Printf("❌ 节点注册失败: %v", err)
			c.JSON(500, response.Error(500, "节点注册失败"))
			return
		}

		log.Printf("✅ 节点注册/更新成功: Name=%s, Address=%s, Region=%s", req.Name, req.Address, req.Region)
		c.JSON(200, response.Success(map[string]string{
			"msg": "Node registered",
		}))
	}
}

// NodeDeleteRequest 节点删除请求
type NodeDeleteRequest struct {
	Address string `json:"address" binding:"required"` // e.g. "1.1.1.1:443"
}

// HandleDeleteNode 处理节点删除（管理员接口）
func HandleDeleteNode(db *gorm.DB, adminSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 管理员鉴权：检查 X-Admin-Secret
		secret := c.GetHeader("X-Admin-Secret")
		if strings.TrimSpace(secret) != adminSecret {
			log.Printf("❌ 管理员密钥错误，拒绝节点删除请求")
			c.JSON(403, response.Error(403, "forbidden"))
			return
		}

		// 解析请求体
		var req NodeDeleteRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, response.Error(400, "参数错误"))
			return
		}

		// 查找并删除节点（通过地址）
		result := db.Where("address = ?", req.Address).Delete(&models.Node{})
		if result.Error != nil {
			log.Printf("❌ 节点删除失败: %v", result.Error)
			c.JSON(500, response.Error(500, "节点删除失败"))
			return
		}

		// 检查是否找到并删除了节点
		if result.RowsAffected == 0 {
			log.Printf("⚠️  未找到地址为 %s 的节点", req.Address)
			c.JSON(404, response.Error(404, "节点不存在"))
			return
		}

		log.Printf("✅ 节点删除成功: Address=%s", req.Address)
		c.JSON(200, response.Success(map[string]string{
			"msg": "Node deleted",
		}))
	}
}

