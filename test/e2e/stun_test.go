package e2e

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"testing"
	"time"
	"webRTCInfra/pkg/common"
	"webRTCInfra/pkg/protocol"
)

// 设置Transaction ID (12字节随机数)
var transactionID = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}
var magicCookie = []byte{0x21, 0x12, 0xa4, 0x42}

// createSTUNBindingRequest 创建一个基本的STUN绑定请求
func createSTUNBindingRequest() []byte {
	// STUN消息头部 (20字节)
	// 0                   1                   2                   3
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |0 0|     STUN Message Type     |         Message Length        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                         Magic Cookie                          |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                                                               |
	// |                     Transaction ID (96 bits)                  |
	// |                                                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	request := make([]byte, 20)

	// 设置消息类型为Binding Request (0x0001)
	request[0] = 0x00
	request[1] = 0x01

	// 消息长度设置为0 (没有属性)
	request[2] = 0x00
	request[3] = 0x00

	// 设置Magic Cookie (0x2112A442)
	request[4] = 0x21
	request[5] = 0x12
	request[6] = 0xA4
	request[7] = 0x42

	copy(request[8:20], transactionID)

	return request
}

// isValidSTUNResponse 验证STUN响应的基本格式
func isValidSTUNResponse(conn net.Conn, response []byte, t *testing.T) bool {
	if len(response) < 20 {
		return false
	}

	// 检查是否是Binding Response (0x0101)
	if response[0] != 0x01 || response[1] != 0x01 {
		return false
	}

	// 检查Magic Cookie
	if response[4] != 0x21 || response[5] != 0x12 || response[6] != 0xA4 || response[7] != 0x42 {
		return false
	}

	// 解析响应
	resp, err := protocol.Decode(response)
	if err != nil {
		t.Fatalf("Failed to parse STUN response: %v", err)
		return false
	}

	// 验证响应类型
	if resp.Type != protocol.MessageTypeStunBindingResponse {
		t.Errorf("Expected response type %x, got %x", protocol.MessageTypeStunBindingResponse, resp.Type)
		return false
	}

	log.Printf("Received STUN response: %+v", resp)

	// 解析XOR映射地址（预期是客户端的本地地址，因为在本地测试）
	xorValue, ok := resp.GetAttribute(protocol.AttributeTypeXORMappedAddress)
	if !ok {
		t.Fatalf("XOR-MAPPED-ADDRESS attribute not found")
	}
	ip, port, err := GetXORMappedAddress(xorValue)
	if err != nil {
		t.Fatalf("Failed to get XOR-MAPPED-ADDRESS: %v", err)
	}

	// 客户端本地地址（测试环境中，服务器看到的客户端地址就是客户端的本地地址）
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	localIP := localAddr.IP.To4()
	if localIP == nil {
		t.Fatal("Client is using unsupported IPv6")
	}

	// 验证IP是否匹配
	var expectedIP [4]byte
	copy(expectedIP[:], localIP)
	if ip != expectedIP {
		t.Errorf("Expected XOR IP %v, got %v", expectedIP, ip)
	}

	// 验证端口是否匹配
	if port != uint16(localAddr.Port) {
		t.Errorf("Expected XOR port %d, got %d", localAddr.Port, port)
	}

	t.Log("STUN end-to-end test passed")

	return true
}

// 属性类型常量
const (
	AttributeTypeXORMappedAddress = 0x0020
)

// 解析XOR映射地址属性
func GetXORMappedAddress(xor []byte) (ip [4]byte, port uint16, err error) {
	if len(xor) < 7 {
		return ip, 0, errors.New("invalid XOR-MAPPED-ADDRESS length")
	}

	// 跳过前两个字节(0x00和family)
	family := xor[1]
	portBytes := xor[2:4]
	ipBytes := xor[4:]

	// 解码端口
	magic := binary.BigEndian.Uint16(magicCookie[:2])
	port = binary.BigEndian.Uint16(portBytes) ^ magic

	// 解码IP地址
	xorIP := make([]byte, len(ipBytes))
	for i := 0; i < len(ipBytes); i++ {
		xorIP[i] = ipBytes[i] ^ magicCookie[i%4]
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

func TestSTUNServerE2E(t *testing.T) {
	// 创建客户端UDP连接
	conn, err := net.Dial("udp", ":3478")
	if err != nil {
		t.Fatalf("Client failed to connect: %v", err)
	}
	defer conn.Close()

	t.Run("测试STUN服务端对端功能：客户端发送Binding请求，验证服务器返回正确的公网地址", func(t *testing.T) {

		// 创建STUN绑定请求
		stunRequest := createSTUNBindingRequest()

		// 发送STUN请求
		_, err = conn.Write(stunRequest)
		if err != nil {
			t.Fatalf("Failed to send STUN request: %v", err)
		}

		// 设置读取超时
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		// 读取STUN响应
		response := make([]byte, 1024)
		n, err := conn.Read(response)
		if err != nil {
			t.Fatalf("Failed to read STUN response: %v", err)
		}

		// 验证STUN响应
		if !isValidSTUNResponse(conn, response[:n], t) {
			t.Error("Invalid STUN response received")
		}
	})

	t.Run("测试服务器对无效STUN数据包的处理（应忽略或不崩溃）", func(t *testing.T) {
		// 发送无效数据包（非STUN格式）
		invalidData := []byte("this is not a stun_turn packet")
		_, err = conn.Write(invalidData)
		if err != nil {
			t.Fatalf("Client failed to send invalid data: %v", err)
		}

		// 设置读取超时
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		response := make([]byte, 1024)
		_, err = conn.Read(response)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				t.Log("Invalid packet test passed: server correctly ignored invalid packet")
			} else {
				t.Fatalf("Unexpected error when reading response: %v", err)
			}
		} else {
			t.Error("Server responded to invalid packet, should have ignored it")
		}

		t.Log("Invalid packet test passed")
	})

}
