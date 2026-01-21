package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"webRTCInfra/pkg/common"

	"github.com/stretchr/testify/assert"
)

var testRealm = "test.example.com"
var testPassword = "test_password"
var staticNonce = "fixed_nonce_123456"

// buildHeader 构造 20 字节头部，返回 Hex 字符串
// 参数：msgType（消息类型）、msgLen（头部 MsgLen）、tid（事务ID）
func buildHeader(msgType uint16, msgLen uint16, tid [12]byte) []byte {
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], msgType) // 消息类型
	binary.BigEndian.PutUint16(header[2:4], msgLen)  // MsgLen
	copy(header[4:8], common.MagicCookie())          // Cookie
	copy(header[8:20], tid[:])                       // 事务ID
	return header
}

func CalcPadding(attrValueLen int) int {
	return (4 - (attrValueLen % 4)) % 4
}
func buildAttribute(_type uint16, value []byte) []byte {
	actuallyValueLen := len(value)
	padding := CalcPadding(actuallyValueLen)
	attr := make([]byte, 4+actuallyValueLen+padding)
	binary.BigEndian.PutUint16(attr[0:2], _type)
	binary.BigEndian.PutUint16(attr[2:4], uint16(actuallyValueLen))
	copy(attr[4:], value)
	for i := 0; i < padding; i++ {
		// 填充属性
		attr[4+actuallyValueLen+i] = 0
	}
	return attr
}

func buildAllPocket(msg *Message) []byte {
	preMI, MI, postMI := msg.splitAttributes()

	// 构建MI前的属性包
	preMIByte := make([]byte, 0)
	for _, attr := range preMI {
		b := buildAttribute(attr.Type, attr.Value)
		preMIByte = append(preMIByte, b...)
	}

	msg.Len = uint16(len(preMIByte))
	headByte := buildHeader(msg.Type, msg.Len, msg.TransactionID)
	userName, _ := msg.GetAttribute(AttributeTypeUsername)

	// 构建MI属性包
	preMIPocket := append(headByte, preMIByte...)
	key := common.GenerateAuthKey(string(userName), testRealm, testPassword)
	MIValue := common.CalculateMessageIntegrity(key, preMIPocket)
	packet := preMIPocket
	if len(MI) > 0 {
		MI[0] = AttributesInfo{
			Type:  AttributeTypeMessageIntegrity,
			Value: MIValue,
		}
		// 将MI回填至原始数据中
		msg.BuildAttribute(MI[0].Type, MI[0].Value)

		MIByte := buildAttribute(MI[0].Type, MI[0].Value)
		packet = append(packet, MIByte...)
	}

	postMIByte := make([]byte, 0)
	for _, attr := range postMI {
		b := buildAttribute(attr.Type, attr.Value)
		postMIByte = append(postMIByte, b...)
	}
	packet = append(packet, postMIByte...)
	return packet
}

func TestDecode(t *testing.T) {
	transactionID := [12]byte{
		0x63, 0x61, 0x66, 0x65, 0x62, 0x61,
		0x62, 0x65, 0x66, 0x61, 0x63, 0x65,
	}

	testErrorMagicCookie := []byte{0x11, 0x22, 0x33, 0x44}

	preMIAttr := []AttributesInfo{
		{
			Type:  AttributeTypeUsername,
			Value: []byte("test_name"),
		},
		{
			Type:  AttributeTypeRealm,
			Value: []byte(testRealm),
		},
		{
			Type:  AttributeTypeNonce,
			Value: []byte(staticNonce),
		},
	}
	MIAttr := []AttributesInfo{
		{
			Type:  AttributeTypeMessageIntegrity,
			Value: []byte{},
		},
	}
	postMIAttr := []AttributesInfo{
		{
			Type:  0x0022,
			Value: []byte("Go-TURN/1.0"),
		},
	}
	// 构建TURN-带MI属性（Allocate请求）
	containMIMsg := &Message{
		Type:          MessageTypeTurnAllocateRequest,
		Len:           0,
		TransactionID: transactionID,
		Attributes:    make([]AttributesInfo, 0),
	}
	containMIMsg.Attributes = append(preMIAttr, MIAttr...)
	containMIMsg.Attributes = append(containMIMsg.Attributes, postMIAttr...)

	noMIMsg := &Message{
		Type:          MessageTypeTurnAllocateRequest,
		Len:           0,
		TransactionID: transactionID,
		Attributes:    preMIAttr,
	}

	tests := []struct {
		name           string
		args           func() []byte
		expectedMsg    *Message
		wantErr        bool
		expectedErrMsg string // 期望的错误信息（精确匹配）
		check          func(t *testing.T, msg, expectedMsg *Message)
	}{
		// TODO: Add test cases.
		{
			name:        "正常TURN-带MI属性（Allocate请求）",
			expectedMsg: containMIMsg,
			args: func() []byte {
				return buildAllPocket(containMIMsg)
			},
			check: func(t *testing.T, msg, expectedMsg *Message) {
				// 校验解析出来的type
				if msg.Type != expectedMsg.Type {
					t.Errorf("expected type %x, got %x", expectedMsg.Type, msg.Type)
				}
				// 校验解析出来的transactionID
				if !bytes.Equal(msg.TransactionID[:], expectedMsg.TransactionID[:]) {
					t.Errorf("expected transactionID %x, got %x", transactionID, msg.TransactionID)
				}

				// 3. 校验属性（顺序+Type+Value）
				assert.Equal(t, len(expectedMsg.Attributes), len(msg.Attributes), "属性数量不匹配")

				// 轮询解码出来的属性是否正确,以及顺序是否正确
				for i, attr := range msg.Attributes {
					assert.Equal(t, expectedMsg.Attributes[i].Type, attr.Type, "第%d个属性Type不匹配", i)
					assert.Equal(t, expectedMsg.Attributes[i].Value, msg.Attributes[i].Value, "第%d个属性Value不匹配", i)
				}
			},
			wantErr: false,
		},
		{
			name:        "正常TURN-不带MI属性",
			expectedMsg: noMIMsg,
			args: func() []byte {
				return buildAllPocket(noMIMsg)
			},
			check: func(t *testing.T, msg, expectedMsg *Message) {
				// 校验解析出来的type
				if msg.Type != expectedMsg.Type {
					t.Errorf("expected type %x, got %x", expectedMsg.Type, msg.Type)
				}
				// 校验解析出来的transactionID
				if !bytes.Equal(msg.TransactionID[:], expectedMsg.TransactionID[:]) {
					t.Errorf("expected transactionID %x, got %x", transactionID, msg.TransactionID)
				}

				// 3. 校验属性（顺序+Type+Value）
				assert.Equal(t, len(expectedMsg.Attributes), len(msg.Attributes), "属性数量不匹配")

				// 轮询解码出来的属性是否正确,以及顺序是否正确
				for i, attr := range msg.Attributes {
					assert.Equal(t, expectedMsg.Attributes[i].Type, attr.Type, "第%d个属性Type不匹配", i)
					assert.Equal(t, expectedMsg.Attributes[i].Value, msg.Attributes[i].Value, "第%d个属性Value不匹配", i)
				}
			},
			wantErr: false,
		},
		{
			name:        "异常-报文长度不超过20",
			expectedMsg: nil,
			args: func() []byte {
				return []byte("too_short_packet")
			},
			check:          nil,
			wantErr:        true,
			expectedErrMsg: "packet too short (length: 16), the length cannot be less than 20",
		},
		{
			name:        "异常-MagicCookie不匹配",
			expectedMsg: nil,
			args: func() []byte {
				packet := buildAllPocket(containMIMsg)
				// 修改MagicCookie
				copy(packet[4:8], []byte{0x11, 0x22, 0x33, 0x44})
				return packet
			},
			check:          nil,
			wantErr:        true,
			expectedErrMsg: fmt.Sprintf("magic cookie mismatch, expected: 0x%08X, got: 0x%08X", common.MagicCookie(), testErrorMagicCookie),
		},
		{
			name:        "异常-属性头部不完整（不足4字节）",
			expectedMsg: nil,
			args: func() []byte {
				// 构建合法头部（20字节），但属性部分仅2字节（不足属性头部4字节）
				header := make([]byte, 20)
				binary.BigEndian.PutUint16(header[:2], MessageTypeTurnAllocateRequest)
				binary.BigEndian.PutUint16(header[2:4], 0x0002) // 欺骗性设置属性长度=2
				copy(header[4:8], common.MagicCookie())
				copy(header[8:20], transactionID[:])
				return append(header, []byte{0x00, 0x06}...) // 属性部分仅2字节（仅Type，无Length）
			},
			check:          nil,
			wantErr:        true,
			expectedErrMsg: "attribute too short",
		},
		{
			name:        "异常-属性长度值不匹配",
			expectedMsg: nil,
			args: func() []byte {
				header := make([]byte, 20)
				binary.BigEndian.PutUint16(header[:2], MessageTypeTurnAllocateRequest)
				binary.BigEndian.PutUint16(header[2:4], 0x0008)
				copy(header[4:8], common.MagicCookie())
				copy(header[8:20], transactionID[:])

				attrByte := make([]byte, 8)
				value := []byte("test")
				binary.BigEndian.PutUint16(attrByte[:2], AttributeTypeUsername)
				binary.BigEndian.PutUint16(attrByte[2:4], uint16(5)) // 期望属性长度为5字节，实际属性值长度只有4
				copy(attrByte[4:8], value[:])
				return append(header, attrByte...)
			},
			check:          nil,
			wantErr:        true,
			expectedErrMsg: "attribute length mismatch",
		},
		{
			name:        "异常-报文长度校验失败（MI前属性长度）",
			expectedMsg: nil,
			args: func() []byte {
				header := make([]byte, 20)
				binary.BigEndian.PutUint16(header[:2], MessageTypeTurnAllocateRequest)
				binary.BigEndian.PutUint16(header[2:4], 0x0009) // 属性长度设置为9字节，实际属性长度为8字节
				copy(header[4:8], common.MagicCookie())
				copy(header[8:20], transactionID[:])

				attrByte := make([]byte, 8)
				value := []byte("test")
				binary.BigEndian.PutUint16(attrByte[:2], AttributeTypeUsername)
				binary.BigEndian.PutUint16(attrByte[2:4], uint16(len(value)))
				copy(attrByte[4:8], value[:])
				return append(header, attrByte...)
			},
			check:          nil,
			wantErr:        true,
			expectedErrMsg: "packet length mismatch, expected: 8, got: 9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode(tt.args())
			if tt.wantErr {
				assert.EqualError(t, err, tt.expectedErrMsg, "错误信息不匹配")
				assert.Nil(t, got, "解析结果不为nil")
			} else {
				assert.NoError(t, err, "不期望返回错误，但返回了：%v", err)
				// 正常场景下Message不能为nil
				assert.NotNil(t, got, "正常场景应返回非nil Message")
				// 执行额外的业务校验
				if tt.check != nil {
					tt.check(t, got, tt.expectedMsg)
				}
			}
		})
	}
}
