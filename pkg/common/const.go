package common

import (
	"time"
)

const ServerIP = "127.0.0.1"

const (
	IPV4 = 0x01
	IPV6 = 0x02
)

const (
	Realm          = "turn.example.com"
	StaticPassword = "123456"
)

const (
	DefaultLifeTime  = 10 * time.Minute
	MaxLimitLifeTime = time.Hour
)

func MagicCookie() []byte {
	return []byte{0x21, 0x12, 0xa4, 0x42}
}

const (
	SuccessCode                  uint16 = 200
	ErrUnauthorizedCode          uint16 = 401 // 未授权
	ErrNonceExpiredCode          uint16 = 438 // Nonce过期
	ErrUnSupportedProtocolCode   uint16 = 442 // 不支持的协议
	ErrInsufficientResourcesCode uint16 = 508 // 资源不足
	ErrInvalidRequest            uint16 = 400 // 无效请求
)
