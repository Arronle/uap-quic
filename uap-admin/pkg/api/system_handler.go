package api

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

// GetPublicKey 获取系统公钥（公开接口，无需鉴权）
func GetPublicKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 读取 public_key.pem 文件
		publicKeyPath := "public_key.pem"
		publicKeyData, err := os.ReadFile(publicKeyPath)
		if err != nil {
			log.Printf("❌ 读取公钥文件失败: %v", err)
			c.JSON(500, gin.H{
				"code": 500,
				"msg":  "公钥文件读取失败",
			})
			return
		}

		// 以 text/plain 格式返回公钥内容
		c.Data(200, "text/plain; charset=utf-8", publicKeyData)
	}
}

