package turn

import (
	"fmt"
	"testing"
	"time"
	"webRTCInfra/pkg/common"
	"webRTCInfra/pkg/protocol"

	"github.com/go-playground/assert/v2"
)

func TestAuth_Verify(t *testing.T) {
	transactionID := [12]byte{
		0x63, 0x61, 0x66, 0x65, 0x62, 0x61,
		0x62, 0x65, 0x66, 0x61, 0x63, 0x65,
	}
	tests := []struct {
		name        string
		setup       func(*Auth) *protocol.Message
		expectValid bool
		wantErrCode uint16
	}{
		// TODO: Add test cases.
		{
			name: "Valid message",
			setup: func(auth *Auth) *protocol.Message {
				nonce := common.GenerateRandomString(NonceLen)
				auth.AddNonce(nonce)
				username := "testuser"

				// 构建消息
				msg := protocol.NewMessage(protocol.MessageTypeTurnAllocateRequest, transactionID)
				msg.BuildAttribute(protocol.AttributeTypeUsername, []byte(username))
				msg.BuildAttribute(protocol.AttributeTypeNonce, []byte(nonce))
				msg.BuildAttribute(protocol.AttributeTypeRealm, []byte(common.Realm))
				msg.Attributes = []protocol.AttributesInfo{
					{
						Type:  protocol.AttributeTypeUsername,
						Value: []byte(username),
					},
					{
						Type:  protocol.AttributeTypeNonce,
						Value: []byte(nonce),
					},
					{
						Type:  protocol.AttributeTypeRealm,
						Value: []byte(common.Realm),
					},
				}
				rawPacket := auth.rawWithoutMessageIntegrity(msg)

				key := common.GenerateAuthKey(username, common.Realm, common.StaticPassword)
				integrity := common.CalculateMessageIntegrity(key, rawPacket)
				msg.BuildAttribute(protocol.AttributeTypeMessageIntegrity, integrity)
				msg.Attributes = append(msg.Attributes,
					protocol.AttributesInfo{
						Type:  protocol.AttributeTypeMessageIntegrity,
						Value: integrity,
					},
				)
				return msg
			},
			expectValid: true,
			wantErrCode: common.SuccessCode,
		}, {
			name: "Missing parameters",
			setup: func(auth *Auth) *protocol.Message {
				return protocol.NewMessage(protocol.MessageTypeTurnAllocateRequest, transactionID)
			},
			expectValid: false,
			wantErrCode: common.ErrUnauthorizedCode,
		}, {
			name: "Invalid nonce",
			setup: func(auth *Auth) *protocol.Message {
				username := "testuser"
				invalidNonce := "invalid_nonce"

				msg := protocol.NewMessage(protocol.MessageTypeTurnAllocateRequest, transactionID)
				msg.BuildAttribute(protocol.AttributeTypeUsername, []byte(username))
				msg.BuildAttribute(protocol.AttributeTypeNonce, []byte(invalidNonce))
				msg.BuildAttribute(protocol.AttributeTypeRealm, []byte(common.Realm))
				msg.BuildAttribute(protocol.AttributeTypeMessageIntegrity, []byte("fake_integrity"))
				msg.Attributes = []protocol.AttributesInfo{
					{
						Type:  protocol.AttributeTypeUsername,
						Value: []byte(username),
					},
					{
						Type:  protocol.AttributeTypeNonce,
						Value: []byte(invalidNonce),
					},
					{
						Type:  protocol.AttributeTypeRealm,
						Value: []byte(common.Realm),
					},
					{
						Type:  protocol.AttributeTypeMessageIntegrity,
						Value: []byte("fake_integrity"),
					},
				}
				return msg
			},
			expectValid: false,
			wantErrCode: common.ErrNonceExpiredCode,
		}, {
			name: "Expired nonce",
			setup: func(auth *Auth) *protocol.Message {
				// 添加一个过期的nonce
				expiredNonce := "expired_nonce"
				auth.mu.Lock()
				auth.nonces[expiredNonce] = time.Now().Add(-10 * time.Second) // 已过期
				auth.mu.Unlock()

				username := "testuser"
				msg := protocol.NewMessage(protocol.MessageTypeTurnAllocateRequest, transactionID)
				msg.BuildAttribute(protocol.AttributeTypeUsername, []byte(username))
				msg.BuildAttribute(protocol.AttributeTypeNonce, []byte(expiredNonce))
				msg.BuildAttribute(protocol.AttributeTypeRealm, []byte(common.Realm))
				msg.BuildAttribute(protocol.AttributeTypeMessageIntegrity, []byte("fake_integrity"))
				msg.Attributes = []protocol.AttributesInfo{
					{
						Type:  protocol.AttributeTypeUsername,
						Value: []byte(username),
					},
					{
						Type:  protocol.AttributeTypeNonce,
						Value: []byte(expiredNonce),
					},
					{
						Type:  protocol.AttributeTypeRealm,
						Value: []byte(common.Realm),
					},
					{
						Type:  protocol.AttributeTypeMessageIntegrity,
						Value: []byte("fake_integrity"),
					},
				}
				return msg
			},
			expectValid: false,
			wantErrCode: common.ErrNonceExpiredCode,
		}, {
			name: "Invalid realm",
			setup: func(auth *Auth) *protocol.Message {
				username := "testuser"
				nonce := common.GenerateRandomString(NonceLen)
				auth.AddNonce(nonce)
				invalidRealm := "invalid.realm"

				msg := protocol.NewMessage(protocol.MessageTypeTurnAllocateRequest, transactionID)
				msg.BuildAttribute(protocol.AttributeTypeUsername, []byte(username))
				msg.BuildAttribute(protocol.AttributeTypeNonce, []byte(nonce))
				msg.BuildAttribute(protocol.AttributeTypeRealm, []byte(invalidRealm))
				msg.BuildAttribute(protocol.AttributeTypeMessageIntegrity, []byte("fake_integrity"))
				msg.Attributes = []protocol.AttributesInfo{
					{
						Type:  protocol.AttributeTypeUsername,
						Value: []byte(username),
					},
					{
						Type:  protocol.AttributeTypeNonce,
						Value: []byte(nonce),
					},
					{
						Type:  protocol.AttributeTypeRealm,
						Value: []byte(invalidRealm),
					},
					{
						Type:  protocol.AttributeTypeMessageIntegrity,
						Value: []byte("fake_integrity"),
					},
				}
				return msg
			},
			expectValid: false,
			wantErrCode: common.ErrUnauthorizedCode,
		}, {
			name: "Invalid integrity",
			setup: func(auth *Auth) *protocol.Message {
				nonce := common.GenerateRandomString(NonceLen)
				auth.AddNonce(nonce)
				username := "testuser"

				// 构建消息但使用错误的完整性值
				msg := protocol.NewMessage(protocol.MessageTypeTurnAllocateRequest, transactionID)
				msg.BuildAttribute(protocol.AttributeTypeUsername, []byte(username))
				msg.BuildAttribute(protocol.AttributeTypeNonce, []byte(nonce))
				msg.BuildAttribute(protocol.AttributeTypeRealm, []byte(common.Realm))
				msg.BuildAttribute(protocol.AttributeTypeMessageIntegrity, []byte("invalid_integrity_value"))
				msg.Attributes = []protocol.AttributesInfo{
					{
						Type:  protocol.AttributeTypeUsername,
						Value: []byte(username),
					},
					{
						Type:  protocol.AttributeTypeNonce,
						Value: []byte(nonce),
					},
					{
						Type:  protocol.AttributeTypeRealm,
						Value: []byte(common.Realm),
					},
					{
						Type:  protocol.AttributeTypeMessageIntegrity,
						Value: []byte("invalid_integrity_value"),
					},
				}
				return msg
			},
			expectValid: false,
			wantErrCode: common.ErrInvalidRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewAuth()
			auth.AddUser("testuser")

			msg := tt.setup(auth)
			valid, code, err := auth.Verify(msg)
			if valid != tt.expectValid {
				t.Errorf("Expected valid=%v, got %v", tt.expectValid, valid)
			}

			if err != nil {
				fmt.Printf("Error: %v", err)
			}

			assert.Equal(t, tt.wantErrCode, code)
		})
	}
}
