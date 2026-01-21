package common

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestXORAddress(t *testing.T) {
	// 预定义测试数据
	testTIDv4 := [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}
	testTIDv6 := [12]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B}

	type args struct {
		ip            net.IP   // 输入IP
		port          int      // 输入端口
		transactionID [12]byte // 输入事务ID

	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		expectedErr error
		expected    []byte // 期望的返回值
	}{
		// TODO: Add test cases.
		{
			name: "IPv4-常规端口和IP",
			args: args{
				ip:            net.ParseIP("192.168.1.100"), // 0xC0 0xA8 0x01 0x64
				port:          3478,                         // 0x0D 0x96
				transactionID: testTIDv4,
			},
			expected: func() []byte {
				// 1. 计算密钥（magic cookie + transactionID）
				key := make([]byte, 16)
				copy(key[:4], MagicCookie())
				copy(key[4:], testTIDv4[:])

				// 2. 计算端口XOR：0x0D96 ^ key前2字节(0x2112) = 0x2112 ^ 0x0D96 = 0x2C84
				keyPort := binary.BigEndian.Uint16(key[:2]) // 0x2112
				xorPort := make([]byte, 2)
				binary.BigEndian.PutUint16(xorPort, uint16(3478)^keyPort) // 0x2C84

				// 3. 计算IP XOR：每个字节与key对应位置XOR
				ipBytes := net.ParseIP("192.168.1.100").To4() // 0xC0 0xA8 0x01 0x64
				xorIP := make([]byte, 4)
				for i := range ipBytes {
					xorIP[i] = ipBytes[i] ^ key[i]
				}
				// 0xC0^0x21=0xE1, 0xA8^0x12=0xBA, 0x01^0xA4=0xA5, 0x64^0x42=0x26

				// 4. 组装结果：保留(0x00) + 地址族(0x01) + 端口 + IP
				return []byte{
					0x00, 0x01, // 保留 + IPv4
					xorPort[0], xorPort[1], // 0x2C 0x84
					xorIP[0], xorIP[1], xorIP[2], xorIP[3], // XOR后的IP
				}
			}(),
			wantErr: false,
		},
		{
			name: "IPv6-常规端口和IP",
			args: args{
				ip:            net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
				port:          5432, // 0x15 0x30
				transactionID: testTIDv6,
			},
			expected: func() []byte {
				// 1. 计算密钥
				key := make([]byte, 16)
				copy(key[:4], MagicCookie())
				copy(key[4:], testTIDv6[:])

				// 2. 端口XOR：0x1530 ^ 0x2112 = 0x3422
				keyPort := binary.BigEndian.Uint16(key[:2])
				xorPort := make([]byte, 2)
				binary.BigEndian.PutUint16(xorPort, uint16(5432)^keyPort)

				// 3. IPv6 XOR（前16字节与key对应位置XOR）
				ipBytes := net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334").To16()
				xorIP := make([]byte, 16)
				for i := range ipBytes {
					xorIP[i] = ipBytes[i] ^ key[i]
				}

				// 4. 组装结果：保留 + IPv6(0x02) + 端口 + IP
				result := []byte{0x00, 0x02}
				result = append(result, xorPort...)
				result = append(result, xorIP...)
				return result
			}(),
		},
		{
			name: "IPv4-端口为0（边界值）",
			args: args{
				ip:            net.ParseIP("0.0.0.0"),
				port:          0,
				transactionID: testTIDv4,
			},

			expected: func() []byte {
				key := make([]byte, 16)
				copy(key[:4], MagicCookie())
				copy(key[4:], testTIDv4[:])

				// 端口0 XOR key前2字节 = 0x2112
				xorPort := make([]byte, 2)
				binary.BigEndian.PutUint16(xorPort, 0^binary.BigEndian.Uint16(key[:2]))

				// IP 0.0.0.0 XOR key前4字节 = key前4字节
				xorIP := make([]byte, 4)
				for i := 0; i < 4; i++ {
					xorIP[i] = 0 ^ key[i]
				}

				return []byte{0x00, 0x01, xorPort[0], xorPort[1], xorIP[0], xorIP[1], xorIP[2], xorIP[3]}
			}(),
		},
		{
			name: "IPv4-端口65535（最大值）",
			args: args{
				ip:            net.ParseIP("255.255.255.255"),
				port:          65535, // 0xFFFF
				transactionID: testTIDv4,
			},

			expected: func() []byte {
				key := make([]byte, 16)
				copy(key[:4], MagicCookie())
				copy(key[4:], testTIDv4[:])

				// 端口0xFFFF ^ 0x2112 = 0xDEED
				xorPort := make([]byte, 2)
				binary.BigEndian.PutUint16(xorPort, 0xFFFF^binary.BigEndian.Uint16(key[:2]))

				// IP 255.255.255.255 XOR key前4字节 = ~key前4字节（按位取反）
				xorIP := make([]byte, 4)
				for i := 0; i < 4; i++ {
					xorIP[i] = 0xFF ^ key[i]
				}

				return []byte{0x00, 0x01, xorPort[0], xorPort[1], xorIP[0], xorIP[1], xorIP[2], xorIP[3]}
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 执行XORAddress
			actual, err := XORAddress(tt.args.ip, tt.args.port, tt.args.transactionID)
			if (err != nil) != tt.wantErr {
				assert.EqualError(t, err, tt.expectedErr.Error(), "测试用例[%s]错误不匹配", tt.name)
			}
			// 断言结果（精确匹配）
			assert.Equal(t, tt.expected, actual, "测试用例[%s]结果不匹配", tt.name)
		})
	}
}
