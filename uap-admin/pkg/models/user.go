package models

import (
	"time"

	"gorm.io/gorm"
)

// User 用户模型
type User struct {
	ID            uint      `gorm:"primarykey" json:"id"`
	UUID          string    `gorm:"uniqueIndex;not null" json:"uuid"`           // 用户唯一标识
	WalletPubKey  string    `gorm:"uniqueIndex" json:"wallet_pub_key"`          // 钱包公钥（Ed25519，Hex 编码）
	WalletPrivKey string    `gorm:"column:wallet_priv_key" json:"-"`            // 钱包私钥（Ed25519，Hex 编码，托管钱包使用，不返回给客户端）
	Email         *string   `gorm:"uniqueIndex" json:"email"`                   // 邮箱（指针类型，允许 NULL）
	GoogleID      *string   `gorm:"uniqueIndex" json:"google_id"`               // Google OAuth ID（指针类型，允许 NULL）
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName 指定表名
func (User) TableName() string {
	return "users"
}

