package protocol

import (
	"encoding/binary"
	"testing"
	"webRTCInfra/pkg/common"

	"github.com/stretchr/testify/assert"
)

func TestMessage_Encode(t *testing.T) {
	magicCookie := common.MagicCookie()
	testTransactionID := [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	testUsername := "test_user"
	expectedAuthKey := common.GenerateAuthKey(testUsername, common.Realm, common.StaticPassword)

	// 定义测试用例结构体（表驱动核心）
	type encodeTestCase struct {
		name     string   // 测试用例名称
		inputMsg *Message // 输入的 Message 实例
		expected []byte   // 期望的编码结果
	}

	tests := []encodeTestCase{
		// TODO: Add test cases.
		{
			name: "无MI属性_仅基础属性",
			inputMsg: &Message{
				Type:          0x0001, // 假设是绑定请求类型
				TransactionID: testTransactionID,
				Attributes: []AttributesInfo{
					{Type: AttributeTypeUsername, Value: []byte(testUsername)},
					{Type: AttributeTypeRealm, Value: []byte(common.Realm)},
				},
			},
			// 期望结果：头部 + 所有属性（无MI）
			expected: func() []byte {
				header := make([]byte, 20)
				binary.BigEndian.PutUint16(header[:2], 0x0001)
				binary.BigEndian.PutUint16(header[2:4], 0) // 先占位，后续更新属性长度
				copy(header[4:8], magicCookie)
				copy(header[8:20], testTransactionID[:])

				// 编码所有属性（Username + Realm）
				attrsBytes := make([]byte, 0)
				for _, attr := range []AttributesInfo{
					{Type: AttributeTypeUsername, Value: []byte(testUsername)},
					{Type: AttributeTypeRealm, Value: []byte(common.Realm)},
				} {
					fullAttr, _ := (&Message{}).convertAttributeToByte(attr)
					attrsBytes = append(attrsBytes, fullAttr...)
				}

				// 更新头部的属性长度字段
				binary.BigEndian.PutUint16(header[2:4], uint16(len(attrsBytes)))

				return append(header, attrsBytes...)
			}(),
		},
		{
			name: "含MI属性_需计算消息完整性",
			inputMsg: &Message{
				Type:          0x0002, // 假设是绑定响应类型
				TransactionID: testTransactionID,
				Attributes: []AttributesInfo{
					{Type: AttributeTypeUsername, Value: []byte(testUsername)},
					{Type: AttributeTypeRealm, Value: []byte(common.Realm)},
					{Type: AttributeTypeMessageIntegrity, Value: nil}, // MI占位
				},
			},

			// 期望结果：头部 + 前置属性 + MI属性 + 后置属性（此处无后置属性）
			expected: func() []byte {
				// 1. 构造头部（属性长度先占位）
				header := make([]byte, 20)
				binary.BigEndian.PutUint16(header[:2], 0x0002)
				binary.BigEndian.PutUint16(header[2:4], 0)
				copy(header[4:8], magicCookie)
				copy(header[8:20], testTransactionID[:])

				// 2. 编码前置属性（Username + Realm，MI是后置属性）
				preAttrs := []AttributesInfo{
					{Type: AttributeTypeUsername, Value: []byte(testUsername)},
					{Type: AttributeTypeRealm, Value: []byte(common.Realm)},
				}
				preAttrsBytes := make([]byte, 0)
				for _, attr := range preAttrs {
					fullAttr, _ := (&Message{}).convertAttributeToByte(attr)
					preAttrsBytes = append(preAttrsBytes, fullAttr...)
				}

				// 3. 更新头部属性长度（仅前置属性长度）
				binary.BigEndian.PutUint16(header[2:4], uint16(len(preAttrsBytes)))

				// 4. 计算MI值
				withoutMIPacket := append(header[:], preAttrsBytes...)
				expectedMI := common.CalculateMessageIntegrity(expectedAuthKey, withoutMIPacket)

				// 5. 编码MI属性
				miAttr, _ := (&Message{}).convertAttributeToByte(AttributesInfo{
					Type:  AttributeTypeMessageIntegrity,
					Value: expectedMI,
				})

				// 6. 拼接最终报文
				return append(append(header, preAttrsBytes...), miAttr...)
			}(),
		},
		{
			name: "含MI+后置属性_完整场景",
			inputMsg: &Message{
				Type:          0x0003,
				TransactionID: testTransactionID,
				Attributes: []AttributesInfo{
					{Type: AttributeTypeUsername, Value: []byte(testUsername)}, // 前置
					{Type: AttributeTypeMessageIntegrity, Value: nil},          // MI
					{Type: AttributeTypeNonce, Value: []byte("random_nonce")},  // 后置
				},
			},
			expected: func() []byte {
				header := make([]byte, 20)
				binary.BigEndian.PutUint16(header[:2], 0x0003)
				binary.BigEndian.PutUint16(header[2:4], 0)
				copy(header[4:8], magicCookie)
				copy(header[8:20], testTransactionID[:])

				// 前置属性（Username）
				preAttr := AttributesInfo{Type: AttributeTypeUsername, Value: []byte(testUsername)}
				preAttrBytes, _ := (&Message{}).convertAttributeToByte(preAttr)

				// 更新头部属性长度
				binary.BigEndian.PutUint16(header[2:4], uint16(len(preAttrBytes)))

				// 计算MI
				withoutMIPacket := append(header[:], preAttrBytes...)
				expectedMI := common.CalculateMessageIntegrity(expectedAuthKey, withoutMIPacket)
				miAttrBytes, _ := (&Message{}).convertAttributeToByte(AttributesInfo{
					Type:  AttributeTypeMessageIntegrity,
					Value: expectedMI,
				})

				// 后置属性（Nonce）
				postAttr := AttributesInfo{Type: AttributeTypeNonce, Value: []byte("random_nonce")}
				postAttrBytes, _ := (&Message{}).convertAttributeToByte(postAttr)

				// 拼接：头部+前置+MI+后置
				return append(append(append(header, preAttrBytes...), miAttrBytes...), postAttrBytes...)
			}(),
		},
		{
			name: "无任何属性_空属性报文",
			inputMsg: &Message{
				Type:          0x0004,
				TransactionID: testTransactionID,
				Attributes:    []AttributesInfo{}, // 无属性（包括无MI）
			},
			expected: func() []byte {
				header := make([]byte, 20)
				binary.BigEndian.PutUint16(header[:2], 0x0004)
				binary.BigEndian.PutUint16(header[2:4], 0) // 属性长度为0
				copy(header[4:8], magicCookie)
				copy(header[8:20], testTransactionID[:])
				return header
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 执行编码
			actual := tt.inputMsg.Encode()

			// 断言结果（使用 testify/assert 简化断言）
			assert.Equal(t, tt.expected, actual, "编码结果不匹配")
		})
	}
}
