package utils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"webRTCInfra/pkg/common"
)

func AnalyseXORAddress(xor []byte, transactionID [12]byte) (ip [4]byte, port uint16, err error) {
	if len(xor) < 7 {
		return ip, 0, errors.New("invalid XOR-MAPPED-ADDRESS length")
	}

	// 跳过前两个字节(0x00和family)
	family := xor[1]
	portBytes := xor[2:4]
	ipBytes := xor[4:]

	key := make([]byte, 16)
	copy(key[:4], common.MagicCookie())
	copy(key[4:16], transactionID[:])

	// 解码端口
	magic := binary.BigEndian.Uint16(key[:2])
	port = binary.BigEndian.Uint16(portBytes) ^ magic

	// 解码IP地址
	xorIP := make([]byte, len(ipBytes))
	for i := 0; i < len(ipBytes); i++ {
		xorIP[i] = ipBytes[i] ^ key[i]
	}

	if family == common.IPV4 && len(xorIP) == 4 {
		copy(ip[:], xorIP)
	} else if family == common.IPV6 && len(xorIP) == 16 {
		copy(ip[:], xorIP[:4])
	} else {
		return ip, 0, fmt.Errorf("invalid IP address family or length")
	}

	return ip, port, nil
}
