package common

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
)

const (
	LowerLetters = "abcdefghijklmnopqrstuvwxyz"
	UpperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Letters      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func random(s string, length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = s[rand.Int63()%int64(len(s))]
	}
	return string(b)
}

// GenerateRandomString 生成随机字符串
func GenerateRandomString(strLen int) string {
	return random(Letters, strLen)
}

func GenerateAuthKey(username, realm, password string) string {
	raw := []byte(fmt.Sprintf("%s:%s:%s", username, realm, password))
	h := md5.New()
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

// CalculateMessageIntegrity 计算 MESSAGE-INTEGRITY（HMAC-SHA1）
// 注意：计算对象是“头部+所有属性（不含 MESSAGE-INTEGRITY 自身）”
func CalculateMessageIntegrity(key string, pocket []byte) []byte {
	// 计算 HMAC-SHA1
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write(pocket)
	return mac.Sum(nil)
}

func getIPFamily(ip net.IP) (int, net.IP, error) {
	// 标准库 To4() 已处理所有场景：
	// - 纯IPv4地址（len=4）：返回自身
	// - IPv6格式的IPv4映射地址：返回提取的4字节IPv4
	// - 普通IPv6地址：返回nil
	if ipv4 := ip.To4(); ipv4 != nil {
		return IPV4, ipv4, nil
	}

	// 校验是否为合法IPv6地址
	if ipv6 := ip.To16(); ipv6 != nil && len(ipv6) == net.IPv6len {
		return IPV6, ipv6, nil
	}

	// 长度非法（既不是4也不是16）
	return 0, nil, errors.New("invalid IP address length")
}

func XORAddress(ip net.IP, port int, transactionID [12]byte) ([]byte, error) {
	// 准备完整密钥（magic cookie + 事物ID 一共16个字节）
	key := make([]byte, 16)
	copy(key[:4], MagicCookie())    // 前四个字节为magic cookie
	copy(key[4:], transactionID[:]) // 后十二个字节为事物ID

	// 端口 XOR 运算
	xorPort := make([]byte, 2)
	keyPort := binary.BigEndian.Uint16(key[:2]) // magic cookie 前两个字节
	binary.BigEndian.PutUint16(xorPort, uint16(port)^keyPort)

	// IP XOR 运算
	family, ipByte, err := getIPFamily(ip)
	if err != nil {
		return nil, err
	}
	xorIP := make([]byte, len(ipByte))
	for i := range ipByte {
		xorIP[i] = ipByte[i] ^ key[i]
	}

	// 组装数据，属性格式：保留 0x00 + 地址族（0x01=IPv4, 0x02=IPv6） + 端口 + IP
	value := []byte{0x00, byte(family)}
	value = append(value, xorPort...)
	value = append(value, xorIP...)
	return value, nil
}

func ConvertRelayAddressToByte(relayAddr *net.UDPAddr) []byte {
	ip := net.ParseIP(relayAddr.IP.String())
	var ipBytes [4]byte
	copy(ipBytes[:], ip.To4())

	// 格式：1字节地址族（0x01=IPv4） + 2字节端口 + 4字节IP
	data := make([]byte, 7)
	data[0] = IPV4
	binary.BigEndian.PutUint16(data[1:3], uint16(relayAddr.Port))
	copy(data[3:7], ipBytes[:])

	return data
}

func CalcPadding(attrValueLen int) int {
	return (4 - (attrValueLen % 4)) % 4
}
