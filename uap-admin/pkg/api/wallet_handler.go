package api

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"uap-admin/pkg/auth"
	"uap-admin/pkg/models"
	"uap-admin/pkg/response"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// WalletLoginRequest 钱包登录请求
type WalletLoginRequest struct {
	PublicKey string `json:"public_key" binding:"required"` // Hex 编码的公钥
	Signature string `json:"signature" binding:"required"`   // Hex 编码的签名
	Timestamp int64  `json:"timestamp" binding:"required"`    // Unix 时间戳（秒）
}

// WalletLoginResponse 钱包登录响应
type WalletLoginResponse struct {
	Token string `json:"token"` // JWT Token
	UUID  string `json:"uuid"`  // 用户 UUID
}

// HandleWalletLogin 处理钱包登录/注册
func HandleWalletLogin(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req WalletLoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, response.Error(400, fmt.Sprintf("参数错误: %v", err)))
			return
		}

		// 1. 解析公钥（Hex -> Bytes）
		publicKeyBytes, err := hex.DecodeString(req.PublicKey)
		if err != nil {
			c.JSON(400, response.Error(400, "公钥格式错误（必须是 Hex 编码）"))
			return
		}

		// 验证公钥长度（Ed25519 公钥固定 32 字节）
		if len(publicKeyBytes) != ed25519.PublicKeySize {
			c.JSON(400, response.Error(400, fmt.Sprintf("公钥长度错误（期望 %d 字节，实际 %d 字节）", ed25519.PublicKeySize, len(publicKeyBytes))))
			return
		}

		// 2. 防重放攻击：检查时间戳
		now := time.Now().Unix()
		timeDiff := now - req.Timestamp
		if timeDiff < 0 {
			timeDiff = -timeDiff
		}
		if timeDiff > 300 { // 5 分钟 = 300 秒
			c.JSON(401, response.Error(401, fmt.Sprintf("请求已过期（时间差 %d 秒，最大允许 300 秒）", timeDiff)))
			return
		}

		// 3. 验签：验证签名是否合法
		signatureBytes, err := hex.DecodeString(req.Signature)
		if err != nil {
			c.JSON(400, response.Error(400, "签名格式错误（必须是 Hex 编码）"))
			return
		}

		// 构造签名消息：uap-login:timestamp
		message := fmt.Sprintf("uap-login:%d", req.Timestamp)
		messageBytes := []byte(message)

		// 使用 Ed25519 验证签名
		if !ed25519.Verify(publicKeyBytes, messageBytes, signatureBytes) {
			c.JSON(401, response.Error(401, "签名验证失败"))
			return
		}

		// 4. 数据库操作：查找或创建用户
		publicKeyHex := req.PublicKey // 使用 Hex 字符串存储，便于查询
		var user models.User

		err = db.Where("wallet_pub_key = ?", publicKeyHex).First(&user).Error
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				// 用户不存在，自动注册
				newUUID := uuid.New().String()
				user = models.User{
					UUID:          newUUID,
					WalletPubKey:  publicKeyHex,
					WalletPrivKey: "", // 私钥登录时，私钥在用户自己手里，不存储
					Email:         nil, // 钱包登录不设置邮箱（nil 表示 NULL）
					GoogleID:      nil, // 钱包登录不设置 Google ID（nil 表示 NULL）
				}

				if err := db.Create(&user).Error; err != nil {
					log.Printf("❌ 创建用户失败: %v", err)
					c.JSON(500, response.Error(500, "用户注册失败"))
					return
				}

				log.Printf("✅ 新用户注册: UUID=%s, PublicKey=%s", newUUID, publicKeyHex)
			} else {
				log.Printf("❌ 数据库查询错误: %v", err)
				c.JSON(500, response.Error(500, "数据库错误"))
				return
			}
		} else {
			log.Printf("✅ 用户登录: UUID=%s, PublicKey=%s", user.UUID, publicKeyHex)
		}

		// 5. 生成 JWT Token
		token, err := auth.GenerateToken(user.UUID)
		if err != nil {
			log.Printf("❌ JWT 生成失败: %v", err)
			c.JSON(500, response.Error(500, "Token 生成失败"))
			return
		}

		// 6. 返回响应
		c.JSON(200, response.Success(WalletLoginResponse{
			Token: token,
			UUID:  user.UUID,
		}))
	}
}

