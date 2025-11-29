package api

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net/mail"
	"strings"
	"sync"
	"time"

	"uap-admin/pkg/auth"
	"uap-admin/pkg/models"
	"uap-admin/pkg/response"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// EmailCodeRequest 邮箱验证码请求
type EmailCodeRequest struct {
	Email string `json:"email" binding:"required"`
}

// codeCacheItem 验证码缓存项
type codeCacheItem struct {
	Code      string
	ExpiresAt time.Time
}

// emailCodeCache 邮箱验证码缓存（使用 sync.Map 存储）
var emailCodeCache sync.Map

// 定期清理过期验证码的 goroutine
func init() {
	// 初始化随机数种子
	rand.Seed(time.Now().UnixNano())

	go func() {
		ticker := time.NewTicker(1 * time.Minute) // 每分钟清理一次
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			emailCodeCache.Range(func(key, value interface{}) bool {
				item := value.(codeCacheItem)
				if now.After(item.ExpiresAt) {
					emailCodeCache.Delete(key)
				}
				return true
			})
		}
	}()
}

// validateEmail 验证邮箱格式
func validateEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// generateCode 生成6位数随机验证码
func generateCode() string {
	// 生成 100000 到 999999 之间的随机数
	code := rand.Intn(900000) + 100000
	return fmt.Sprintf("%06d", code)
}

// HandleEmailCode 处理邮箱验证码发送请求
func HandleEmailCode() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req EmailCodeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, response.Error(400, fmt.Sprintf("参数错误: %v", err)))
			return
		}

		// 校验邮箱格式
		if !validateEmail(req.Email) {
			c.JSON(400, response.Error(400, "邮箱格式错误"))
			return
		}

		// 生成6位数随机验证码
		code := generateCode()

		// 打印验证码到控制台（临时方案，不真发邮件）
		log.Printf("====== 验证码: %s ======", code)
		log.Printf("邮箱: %s", req.Email)

		// 将验证码存入内存缓存，设置5分钟过期
		item := codeCacheItem{
			Code:      code,
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}
		emailCodeCache.Store(req.Email, item)

		// 返回成功响应
		c.JSON(200, response.Success(map[string]string{
			"msg": "验证码已发送",
		}))
	}
}

// GetEmailCode 获取邮箱对应的验证码（用于后续验证）
func GetEmailCode(email string) (string, bool) {
	value, ok := emailCodeCache.Load(email)
	if !ok {
		return "", false
	}

	item := value.(codeCacheItem)
	
	// 检查是否过期
	if time.Now().After(item.ExpiresAt) {
		emailCodeCache.Delete(email)
		return "", false
	}

	return item.Code, true
}

// EmailLoginRequest 邮箱登录请求
type EmailLoginRequest struct {
	Email string `json:"email" binding:"required"`
	Code  string `json:"code" binding:"required"`
}

// EmailLoginResponse 邮箱登录响应
type EmailLoginResponse struct {
	Token string `json:"token"` // JWT Token
	UUID  string `json:"uuid"`  // 用户 UUID
}

// HandleEmailLogin 处理邮箱登录/注册
func HandleEmailLogin(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req EmailLoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, response.Error(400, fmt.Sprintf("参数错误: %v", err)))
			return
		}

		// 校验邮箱格式
		if !validateEmail(req.Email) {
			c.JSON(400, response.Error(400, "邮箱格式错误"))
			return
		}

		// 校验验证码
		correctCode, ok := GetEmailCode(req.Email)
		if !ok {
			c.JSON(401, response.Error(401, "验证码不存在或已过期"))
			return
		}

		if req.Code != correctCode {
			c.JSON(401, response.Error(401, "验证码错误"))
			return
		}

		// 验证码验证成功后，删除验证码（防止重复使用）
		emailCodeCache.Delete(req.Email)

		// 查询数据库中是否存在该邮箱
		var user models.User
		err := db.Where("email = ?", req.Email).First(&user).Error

		if err != nil {
			if err == gorm.ErrRecordNotFound {
				// 新用户注册：生成密钥对并创建用户
				user, err = createUserWithEmail(db, req.Email)
				if err != nil {
					log.Printf("❌ 创建用户失败: %v", err)
					c.JSON(500, response.Error(500, "用户注册失败"))
					return
				}
				log.Printf("✅ 新用户注册: UUID=%s, Email=%s", user.UUID, req.Email)
			} else {
				log.Printf("❌ 数据库查询错误: %v", err)
				c.JSON(500, response.Error(500, "数据库错误"))
				return
			}
		} else {
			// 老用户登录
			log.Printf("✅ 用户登录: UUID=%s, Email=%s", user.UUID, req.Email)
		}

		// 签发 Token
		token, err := auth.GenerateToken(user.UUID)
		if err != nil {
			log.Printf("❌ JWT 生成失败: %v", err)
			c.JSON(500, response.Error(500, "Token 生成失败"))
			return
		}

		// 返回响应
		c.JSON(200, response.Success(EmailLoginResponse{
			Token: token,
			UUID:  user.UUID,
		}))
	}
}

// createUserWithEmail 创建邮箱用户（处理并发冲突）
func createUserWithEmail(db *gorm.DB, email string) (models.User, error) {
	// 生成 Ed25519 密钥对
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return models.User{}, fmt.Errorf("生成密钥对失败: %w", err)
	}

	// 转换为 Hex 编码
	publicKeyHex := hex.EncodeToString(pub)
	privateKeyHex := hex.EncodeToString(priv)

	// 生成 UUID
	newUUID := uuid.New().String()

	// 创建用户记录
	user := models.User{
		UUID:          newUUID,
		Email:         &email, // 使用指针类型
		WalletPubKey:  publicKeyHex,
		WalletPrivKey: privateKeyHex,
		GoogleID:      nil, // 邮箱注册不设置 Google ID
	}

	// 使用事务处理并发冲突
	var result models.User
	err = db.Transaction(func(tx *gorm.DB) error {
		// 再次检查邮箱是否已存在（防止并发注册）
		var existingUser models.User
		if err := tx.Where("email = ?", email).First(&existingUser).Error; err == nil {
			// 邮箱已存在，返回已存在的用户
			result = existingUser
			return nil
		} else if err != gorm.ErrRecordNotFound {
			// 数据库查询错误
			return err
		}

		// 创建新用户
		if err := tx.Create(&user).Error; err != nil {
			// 如果是因为唯一约束冲突（并发注册），再次查询
			if err == gorm.ErrDuplicatedKey || isUniqueConstraintError(err) {
				// 查询已存在的用户
				if err := tx.Where("email = ?", email).First(&existingUser).Error; err == nil {
					result = existingUser
					return nil
				}
			}
			return err
		}

		result = user
		return nil
	})

	if err != nil {
		return models.User{}, err
	}

	return result, nil
}

// isUniqueConstraintError 检查是否是唯一约束冲突错误
func isUniqueConstraintError(err error) bool {
	// SQLite 的唯一约束错误通常包含 "UNIQUE constraint failed"
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "unique constraint") || strings.Contains(errStr, "duplicate")
}

