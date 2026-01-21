package turn

import (
	"crypto/hmac"
	"fmt"
	"sync"
	"time"
	"webRTCInfra/pkg/common"
	"webRTCInfra/pkg/protocol"
)

const (
	NonceTimeout = 5 * time.Second
	NonceLen     = 16
)

const (
	ErrMissingAttributes = "missing required attributes"
	ErrInvalidNonce      = "nonce expired or invalid"
	ErrInvalidIntegrity  = "message integrity verification failed"
)

type Auth struct {
	users  map[string]struct{}
	nonces map[string]time.Time
	mu     sync.Mutex
}

func NewAuth() *Auth {
	return &Auth{
		users:  make(map[string]struct{}),
		nonces: make(map[string]time.Time),
	}
}

func (a *Auth) AddUser(user string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.users[user] = struct{}{}
}

func (a *Auth) RemoveUser(user string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.users, user)
}

func (a *Auth) AddNonce(nonce string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nonces[nonce] = time.Now().Add(NonceTimeout)
	return nonce
}

func (a *Auth) DeleteNonce(nonce string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.nonces, nonce)
}

func (a *Auth) Verify(msg *protocol.Message) (bool, uint16, error) {
	// 提取字段
	byteName, _ := msg.GetAttribute(protocol.AttributeTypeUsername)
	byteNonce, _ := msg.GetAttribute(protocol.AttributeTypeNonce)
	byteRealm, _ := msg.GetAttribute(protocol.AttributeTypeRealm)
	username := string(byteName)
	nonce := string(byteNonce)
	if len(username) == 0 || len(nonce) == 0 || len(byteRealm) == 0 {
		return false, common.ErrUnauthorizedCode, fmt.Errorf("missing required attributes, must contain username、nonce、messageIntegrity")
	}

	// 检查realm与服务器是否一致
	if string(byteRealm) != common.Realm {
		return false, common.ErrUnauthorizedCode, fmt.Errorf("realm is not consistent with the server")
	}

	// 检查 nonce 是否过期
	if !a.validateNonce(nonce) {
		return false, common.ErrNonceExpiredCode, fmt.Errorf("nonce expired or invalid")
	}

	// 构建 Message-Integrity 前的报文 —— 使用原始 attribute 顺序
	rawPacket := a.rawWithoutMessageIntegrity(msg)

	// 验证 MESSAGE-INTEGRITY
	integrity, _ := msg.GetAttribute(protocol.AttributeTypeMessageIntegrity)
	key := common.GenerateAuthKey(username, common.Realm, common.StaticPassword)
	expectedHMAC := common.CalculateMessageIntegrity(key, rawPacket)
	if !hmac.Equal(expectedHMAC, integrity) {
		return false, common.ErrInvalidRequest, fmt.Errorf("message integrity verification failed")
	}

	return true, common.SuccessCode, nil
}

// rawWithoutMessageIntegrity 按原始解析顺序重新编码
func (a *Auth) rawWithoutMessageIntegrity(msg *protocol.Message) []byte {
	m := protocol.NewMessage(msg.Type, msg.TransactionID)

	// 按 msg.Attributes 顺序复制
	for _, attr := range msg.Attributes {
		// MESSAGE-INTEGRITY 必须计算在它之前的所有属性上（不包括它本身）
		if attr.Type == protocol.AttributeTypeMessageIntegrity {
			break // MESSAGE-INTEGRITY 后面的不用加入
		}
		m.BuildAttribute(attr.Type, attr.Value)
	}

	return m.Encode()
}

// 验证 Nonce
func (a *Auth) validateNonce(nonce string) bool {
	a.mu.Lock()
	exp, ok := a.nonces[nonce]
	a.mu.Unlock()
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		// 删除过期的 nonce
		a.DeleteNonce(nonce)
		return false
	}
	return true
}
