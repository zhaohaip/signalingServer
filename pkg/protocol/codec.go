package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"webRTCInfra/pkg/common"
)

// 验证报文长度
func verifyPocketLength(msg *Message) error {
	// 报文长度只计算MI之前的属性
	preMI, _, _ := msg.splitAttributes()
	proMILen := 0
	for _, attr := range preMI {
		valueLen := len(attr.Value)
		padding := common.CalcPadding(valueLen)
		// 属性总长度：属性头部长度 + 属性值长度  + 属性填充
		totalAttrLen := 4 + valueLen + padding
		proMILen += totalAttrLen
	}

	if uint16(proMILen) != msg.Len {
		return fmt.Errorf("packet length mismatch, expected: %d, got: %d", proMILen, msg.Len)
	}

	return nil
}

func Decode(date []byte) (*Message, error) {
	// 基础校验：头部报文至少需要20字节
	if len(date) < 20 {
		return nil, fmt.Errorf("packet too short (length: %d), the length cannot be less than 20", len(date))
	}

	// 解析头部报文
	msgType := binary.BigEndian.Uint16(date[0:2])
	msgLen := binary.BigEndian.Uint16(date[2:4])
	cookie := date[4:8]
	// 获取事务ID，通过拷贝的方式，避免修改原始数据
	var transactionID [12]byte
	copy(transactionID[:], date[8:20])

	// 校验magicCookie
	if !bytes.Equal(cookie, common.MagicCookie()) {
		return nil, fmt.Errorf("magic cookie mismatch, expected: 0x%08X, got: 0x%08X", common.MagicCookie(), cookie)
	}

	msg := NewMessage(msgType, transactionID)
	msg.Len = msgLen

	attributeDate := date[20:]

	offset := 0
	// 属性值可能存在一个或多个
	for offset < len(attributeDate) {
		if offset+4 > len(attributeDate) {
			return nil, fmt.Errorf("attribute too short")
		}

		attrType := binary.BigEndian.Uint16(attributeDate[offset : offset+2])
		attrLen := binary.BigEndian.Uint16(attributeDate[offset+2 : offset+4])
		attrHeadLen := 4

		if offset+attrHeadLen+int(attrLen) > len(attributeDate) {
			return nil, fmt.Errorf("attribute length mismatch")
		}

		var value = make([]byte, attrLen)
		copy(value, attributeDate[offset+attrHeadLen:offset+attrHeadLen+int(attrLen)])
		msg.Attributes = append(msg.Attributes, AttributesInfo{
			Type:  attrType,
			Value: value,
		})

		// 属性总长度按4个字节对其
		attrTotalLen := attrHeadLen + int(attrLen)
		if pad := int(attrTotalLen) % 4; pad != 0 {
			attrTotalLen += 4 - pad
		}
		offset += attrTotalLen // 偏移量加上属性总长度
	}

	// 验证报文长度
	if err := verifyPocketLength(msg); err != nil {
		return nil, err
	}
	return msg, nil
}
