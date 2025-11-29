package api

import (
	"fmt"
	"log"
	"strings"

	"uap-admin/pkg/auth"
	"uap-admin/pkg/response"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware JWT 鉴权中间件
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从 Header 获取 Token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Printf("[鉴权] 缺少 Authorization Header")
			c.JSON(401, response.Error(401, "缺少 Authorization Header"))
			c.Abort()
			return
		}

		// 支持 "Bearer <token>" 格式
		tokenString := authHeader
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		}

		// 获取公钥（调用 auth.GetPublicKey()）
		publicKey := auth.GetPublicKey()
		if len(publicKey) == 0 {
			log.Printf("[鉴权] 获取公钥失败：公钥为空")
			c.JSON(500, response.Error(500, "服务器配置错误：公钥未初始化"))
			c.Abort()
			return
		}

		// 验证 Token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// 必须检查签名算法是否匹配 jwt.SigningMethodEdDSA
			// 注意：jwt.SigningMethodEdDSA 是用于 Ed25519 的签名方法
			if token.Method != jwt.SigningMethodEdDSA {
				log.Printf("[鉴权] 签名方法不匹配：期望 %v，实际 %v", jwt.SigningMethodEdDSA.Alg(), token.Method.Alg())
				return nil, fmt.Errorf("unexpected signing method: %v (expected: %v)", token.Method.Alg(), jwt.SigningMethodEdDSA.Alg())
			}

			// 返回 ed25519.PublicKey 类型
			// 严禁返回私钥，也严禁返回 nil
			return publicKey, nil
		})

		// 详细的错误处理
		if err != nil {
			// 打印详细的错误信息用于调试
			log.Printf("[鉴权] Token 验证失败：%v (错误类型: %T)", err, err)
			
			// 根据错误信息判断具体原因
			errMsg := strings.ToLower(err.Error())
			if strings.Contains(errMsg, "expired") || strings.Contains(errMsg, "exp") {
				log.Printf("[鉴权] 具体错误：Token 已过期")
				c.JSON(401, response.Error(401, "Token 已过期"))
			} else if strings.Contains(errMsg, "signature") || strings.Contains(errMsg, "crypto") {
				log.Printf("[鉴权] 具体错误：Token 签名验证失败（可能是公钥不匹配或签名算法错误）")
				c.JSON(401, response.Error(401, "Token 签名验证失败"))
			} else if strings.Contains(errMsg, "malformed") || strings.Contains(errMsg, "invalid") {
				log.Printf("[鉴权] 具体错误：Token 格式错误或无效")
				c.JSON(401, response.Error(401, "Token 格式错误"))
			} else if strings.Contains(errMsg, "signing method") {
				log.Printf("[鉴权] 具体错误：签名方法不匹配")
				c.JSON(401, response.Error(401, "Token 签名方法不匹配"))
			} else {
				log.Printf("[鉴权] 具体错误：未知错误")
				c.JSON(401, response.Error(401, fmt.Sprintf("Token 验证失败: %v", err)))
			}
			c.Abort()
			return
		}

		// 再次检查 token 是否有效
		if !token.Valid {
			log.Printf("[鉴权] Token 无效")
			c.JSON(401, response.Error(401, "Token 无效"))
			c.Abort()
			return
		}

		// 提取用户 UUID
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			log.Printf("[鉴权] 无法解析 Token Claims（类型断言失败）")
			c.JSON(401, response.Error(401, "无法解析 Token Claims"))
			c.Abort()
			return
		}

		userUUID, ok := claims["uuid"].(string)
		if !ok {
			log.Printf("[鉴权] Token 中缺少 uuid 字段（Claims: %+v）", claims)
			c.JSON(401, response.Error(401, "Token 中缺少 uuid 字段"))
			c.Abort()
			return
		}

		// 将用户 UUID 存储到上下文
		c.Set("user_uuid", userUUID)
		log.Printf("[鉴权] 用户 [%s] 验证成功", userUUID)
		c.Next()
	}
}

