package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"uap-admin/pkg/utils"

	"github.com/golang-jwt/jwt/v5"
)

var (
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
)

// init 初始化函数，确保密钥存在并加载私钥
func init() {
	// 确保密钥对存在
	if err := utils.EnsureKeys(); err != nil {
		panic(fmt.Sprintf("初始化密钥失败: %v", err))
	}

	// 加载私钥
	if err := loadPrivateKey(); err != nil {
		panic(fmt.Sprintf("加载私钥失败: %v", err))
	}
}

// loadPrivateKey 加载私钥文件
func loadPrivateKey() error {
	privateKeyPath := "private_key.pem"
	privData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("读取私钥文件失败: %w", err)
	}

	block, _ := pem.Decode(privData)
	if block == nil {
		return fmt.Errorf("解析私钥 PEM 失败")
	}

	// 使用 x509.ParsePKCS8PrivateKey 解析私钥
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("解析私钥失败: %w", err)
	}

	// 转换为 ed25519.PrivateKey
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return fmt.Errorf("私钥类型错误，期望 ed25519.PrivateKey")
	}

	privateKey = priv
	publicKey = priv.Public().(ed25519.PublicKey)
	return nil
}

// GetPublicKey 获取公钥用于 JWT 验证（别名函数）
func GetPublicKey() ed25519.PublicKey {
	return publicKey
}

// GetPublicKeyForVerification 获取公钥用于 JWT 验证
func GetPublicKeyForVerification() ed25519.PublicKey {
	return publicKey
}

// GenerateToken 生成 JWT Token
func GenerateToken(uuid string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"uuid": uuid,
		"iat":  now.Unix(),
		"exp":  now.Add(time.Hour * 24 * 7).Unix(), // 7 天有效期
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	// 使用 Ed25519 私钥签名
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("签名 Token 失败: %w", err)
	}

	return tokenString, nil
}
