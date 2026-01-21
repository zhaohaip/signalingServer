package protocol

import (
	"encoding/binary"
	"webRTCInfra/pkg/common"
)

// 消息类型
const (
	MessageTypeStunBindingRequest  uint16 = 0x0001 // stun 请求
	MessageTypeStunBindingResponse uint16 = 0x0101 // stun 响应

	MessageTypeTurnAllocateRequest         uint16 = 0x0003 // turn 请求
	MessageTypeTurnAllocateSuccessResponse uint16 = 0x0103 // turn 成功响应
	MessageTypeTurnAllocateErrorResponse   uint16 = 0x0303 // turn 错误响应
)

// 属性类型
const (
	AttributeTypeXORMappedAddress   = 0x0020
	AttributeTypeErrorCode          = 0x0009
	AttributeTypeUsername           = 0x0006
	AttributeTypeRealm              = 0x0014
	AttributeTypeNonce              = 0x0015
	AttributeTypeMessageIntegrity   = 0x0007
	AttributeTypeLifetime           = 0x000D
	AttributeTypeXORRelayedAddress  = 0x0016
	AttributeTypeRequestedTransport = 0x0019
)

type AttributesInfo struct {
	Type  uint16
	Value []byte
}

type Message struct {
	Type          uint16
	Len           uint16
	TransactionID [12]byte
	Attributes    []AttributesInfo // 核心属性（MI之前的属性）
}

func NewMessage(type_ uint16, transactionID [12]byte) *Message {
	return &Message{
		Type:          type_,
		TransactionID: transactionID,
		Attributes:    make([]AttributesInfo, 0),
	}
}

func (m *Message) GetAttribute(type_ uint16) ([]byte, bool) {
	for _, attr := range m.Attributes {
		if attr.Type == type_ {
			return attr.Value, true
		}
	}

	return nil, false
}

func (m *Message) BuildAttribute(type_ uint16, value []byte) {
	isExist := false
	for i, attr := range m.Attributes {
		if attr.Type == type_ {
			m.Attributes[i].Value = value
			isExist = true
		}
	}

	if !isExist {
		m.Attributes = append(m.Attributes, AttributesInfo{
			Type:  type_,
			Value: value,
		})
	}

}

func (m *Message) SetErrorCodeAttribute(code uint16, reason string) {
	class := code / 100
	number := code % 100

	value := []byte{0x00, 0x00, byte(class), byte(number)}
	value = append(value, []byte(reason)...)
	m.BuildAttribute(AttributeTypeErrorCode, value)
}

func (m *Message) splitAttributes() (preMI, MI, postMI []AttributesInfo) {
	miFound := false
	for _, attr := range m.Attributes {
		if attr.Type == AttributeTypeMessageIntegrity {
			miFound = true
			MI = append(MI, attr)
		} else {
			if miFound {
				postMI = append(postMI, attr)
			} else {
				preMI = append(preMI, attr)
			}
		}
	}
	return preMI, MI, postMI
}

func (m *Message) convertAttributeToByte(attr AttributesInfo) ([]byte, int) {
	valueLen := len(attr.Value)
	padding := common.CalcPadding(valueLen)
	// 属性总长度：属性头部长度 + 属性值长度  + 属性填充
	totalAttrLen := 4 + valueLen + padding
	fullAddr := make([]byte, totalAttrLen)

	// 写入属性类型
	binary.BigEndian.PutUint16(fullAddr[:2], attr.Type)
	// 写入属性值长度
	binary.BigEndian.PutUint16(fullAddr[2:4], uint16(valueLen))
	// 写入属性原始值
	copy(fullAddr[4:4+valueLen], attr.Value)
	for i := 0; i < padding; i++ {
		// 填充属性
		fullAddr[4+valueLen+i] = 0
	}
	return fullAddr, totalAttrLen
}

func (m *Message) Encode() []byte {
	// 获取属性，并进行拆分
	preMI, MI, postMI := m.splitAttributes()

	// 构造报文头部
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[:2], m.Type)
	binary.BigEndian.PutUint16(header[2:4], 0) // 先进行占位
	copy(header[4:8], common.MagicCookie())
	copy(header[8:20], m.TransactionID[:])

	// 构造MI之前的属性
	preAttrByte := make([]byte, 0)
	for _, attr := range preMI {
		fullAttr, _ := m.convertAttributeToByte(attr)
		preAttrByte = append(preAttrByte, fullAttr...)
	}

	// 写入属性长度
	binary.BigEndian.PutUint16(header[2:4], uint16(len(preAttrByte)))
	// 拼接头部+MI前属性（用于计算MI）
	withoutMIPacket := append(header[:], preAttrByte...)

	// 构造MESSAGE-INTEGRITY
	miAttrByte := make([]byte, 0)
	if len(MI) > 0 {
		// 计算MI
		userName, _ := m.GetAttribute(AttributeTypeUsername)
		key := common.GenerateAuthKey(string(userName), common.Realm, common.StaticPassword)

		// 若未设置值，则进行计算
		MIValue := MI[0].Value
		if len(MIValue) == 0 {
			MIValue = common.CalculateMessageIntegrity(key, withoutMIPacket)
		}

		// 写入MI属性,更新至message中
		m.BuildAttribute(AttributeTypeMessageIntegrity, MIValue)

		MI[0] = AttributesInfo{
			Type:  AttributeTypeMessageIntegrity,
			Value: MIValue,
		}
		miAttrByte, _ = m.convertAttributeToByte(MI[0])
	}

	// 构造MI之后的属性
	postAttrByte := make([]byte, 0)
	for _, attr := range postMI {
		fullAttr, _ := m.convertAttributeToByte(attr)
		postAttrByte = append(postAttrByte, fullAttr...)
	}

	// 拼接报文
	packet := append(withoutMIPacket, miAttrByte...)
	packet = append(packet, postAttrByte...)

	return packet
}
