package main

import (
	"encoding/pem"
	"log"
	"os"

	"uap-admin/pkg/api"
	"uap-admin/pkg/auth"
	"uap-admin/pkg/models"
	"uap-admin/pkg/response"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ADMIN_SECRET 管理员密钥（实际项目中应从环境变量读取）
const ADMIN_SECRET = "uap-admin-secret-8888"

func main() {
	// 调用 auth 包的初始化逻辑（通过导入触发 init 函数）
	_ = auth.GenerateToken // 触发包初始化

	// 初始化数据库
	db, err := gorm.Open(sqlite.Open("uap_admin.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("❌ 数据库连接失败: %v", err)
	}

	// 自动迁移
	if err := db.AutoMigrate(&models.User{}, &models.Node{}); err != nil {
		log.Fatalf("❌ 数据库迁移失败: %v", err)
	}
	log.Println("✅ 数据库初始化完成")

	// 初始化节点数据（如果数据库里没有节点，自动插入一条测试数据）
	initNodeData(db)

	// 初始化 Gin 路由
	r := gin.Default()

	// 健康检查路由
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, response.Success(map[string]string{
			"status": "ok",
		}))
	})

	// API 路由组
	apiV1 := r.Group("/api/v1")
	{
		authGroup := apiV1.Group("/auth")
		{
			// 钱包登录/注册（公开接口，无需 JWT）
			authGroup.POST("/wallet", api.HandleWalletLogin(db))
			// 邮箱验证码发送（公开接口，无需 JWT）
			authGroup.POST("/email/code", api.HandleEmailCode())
			// 邮箱登录/注册（公开接口，无需 JWT）
			authGroup.POST("/email/login", api.HandleEmailLogin(db))
		}

		clientGroup := apiV1.Group("/client")
		{
			// 获取节点列表（需要 JWT 鉴权）
			clientGroup.GET("/nodes", api.AuthMiddleware(), api.GetNodeList(db))
		}
	}

	// 管理员接口：节点注册（简单的管理员密钥鉴权）
	r.POST("/api/v1/admin/node/register", api.HandleNodeRegister(db, ADMIN_SECRET))

	// 打印启动日志
	log.Println("[UAP-Admin] 服务启动成功，密钥对已就绪")

	// 启动服务器
	log.Println("[UAP-Admin] 服务监听在 :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}

// initNodeData 初始化节点数据
func initNodeData(db *gorm.DB) {
	var count int64
	db.Model(&models.Node{}).Count(&count)

	if count == 0 {
		// 读取 public_key.pem 文件内容
		publicKeyPath := "public_key.pem"
		publicKeyData, err := os.ReadFile(publicKeyPath)
		if err != nil {
			log.Fatalf("❌ 读取公钥文件失败: %v (请确保 public_key.pem 文件存在)", err)
		}

		// 解析 PEM 块
		block, _ := pem.Decode(publicKeyData)
		if block == nil {
			log.Fatalf("❌ 解析公钥 PEM 失败")
		}

		// 将 PEM 块编码为字符串（包含完整的 PEM 格式）
		publicKeyPEM := string(pem.EncodeToMemory(block))

		// 创建测试节点
		testNode := models.Node{
			Name:      "🇺🇸 美国核心测试节点",
			Address:   "uaptest.org:52222",
			PublicKey: publicKeyPEM,
			Region:    "US",
			IsVIP:     false,
			Status:    1, // 在线
		}

		if err := db.Create(&testNode).Error; err != nil {
			log.Fatalf("❌ 创建测试节点失败: %v", err)
		}

		log.Printf("✅ 已创建测试节点: %s", testNode.Name)
	} else {
		log.Printf("✅ 节点数据已存在（共 %d 个节点）", count)
	}
}
