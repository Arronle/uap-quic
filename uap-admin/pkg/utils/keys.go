package utils

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// EnsureKeys 确保 Ed25519 密钥对存在
// 如果不存在，自动生成并保存为 PEM 文件
func EnsureKeys() error {
	privateKeyPath := "private_key.pem"
	publicKeyPath := "public_key.pem"

	// 检查密钥文件是否已存在
	_, privExists := os.Stat(privateKeyPath)
	_, pubExists := os.Stat(publicKeyPath)

	if privExists == nil && pubExists == nil {
		// 密钥文件已存在，无需生成
		fmt.Println("✅ 密钥对文件已存在")
		return nil
	}

	// 生成新的 Ed25519 密钥对
	fmt.Println("🔑 正在生成新的 Ed25519 密钥对...")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("生成密钥对失败: %w", err)
	}

	// 使用 x509.MarshalPKCS8PrivateKey 编码私钥
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("编码私钥失败: %w", err)
	}

	// 保存私钥为 PEM 文件
	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	privFile, err := os.Create(privateKeyPath)
	if err != nil {
		return fmt.Errorf("创建私钥文件失败: %w", err)
	}
	defer privFile.Close()
	if err := pem.Encode(privFile, privBlock); err != nil {
		return fmt.Errorf("写入私钥文件失败: %w", err)
	}
	fmt.Printf("✅ 私钥已保存到: %s\n", privateKeyPath)

	// 使用 x509.MarshalPKIXPublicKey 编码公钥
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("编码公钥失败: %w", err)
	}

	// 保存公钥为 PEM 文件
	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	pubFile, err := os.Create(publicKeyPath)
	if err != nil {
		return fmt.Errorf("创建公钥文件失败: %w", err)
	}
	defer pubFile.Close()
	if err := pem.Encode(pubFile, pubBlock); err != nil {
		return fmt.Errorf("写入公钥文件失败: %w", err)
	}
	fmt.Printf("✅ 公钥已保存到: %s\n", publicKeyPath)

	return nil
}

