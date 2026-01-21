package e2e

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"testing"
	"time"
	"webRTCInfra/pkg/common"
	"webRTCInfra/pkg/network/udp"
	"webRTCInfra/pkg/protocol"
	stunturn "webRTCInfra/pkg/service/stun_turn"
	"webRTCInfra/pkg/service/stun_turn/turn"
	e2eclient "webRTCInfra/test/e2e/client"
	"webRTCInfra/test/e2e/utils"

	"github.com/stretchr/testify/assert"
)

var publicIP = "192.168.1.1"
var stunAddr = ":3478" // STUN服务地址
func startTurnServer() *stunturn.Service {
	udpServer := udp.NewService(stunAddr, nil)
	stunService := stunturn.NewService(udpServer, publicIP)
	stunService.Start()
	return stunService
}

func analyseErrorCode(msg *protocol.Message) (uint16, string, bool) {
	errInfo, ok := msg.GetAttribute(protocol.AttributeTypeErrorCode)
	if !ok {
		return 0, "", false
	}

	_ = errInfo[:4]

	errCodeByte := errInfo[2:4]
	errCode := uint16(errCodeByte[0])*100 + uint16(errCodeByte[1])
	fmt.Printf("ErrorCode: %d, ErrorMsg: %s\n", errCode, string(errInfo[4:]))

	return errCode, string(errInfo[4:]), true
}

func VerifyLiftTime(t *testing.T, respMsg *protocol.Message, expectedLifeTime time.Duration) {
	lifeTimeByte, ok := respMsg.GetAttribute(protocol.AttributeTypeLifetime)
	assert.Truef(t, ok, "no lifetime attribute")
	lifeTime := binary.BigEndian.Uint32(lifeTimeByte)
	assert.Equal(t, uint32(expectedLifeTime.Seconds()), lifeTime)
}

func getTurnServerNonce(t *testing.T, client *e2eclient.Client, turnTransactionID [12]byte, userName string) ([]byte, []byte) {
	msg := protocol.NewMessage(protocol.MessageTypeTurnAllocateRequest, turnTransactionID)
	msg.BuildAttribute(protocol.AttributeTypeUsername, []byte(userName))
	packet := msg.Encode()
	client.SendMsg(packet)

	respMsg, err := handlerPacket(client)
	assert.Nil(t, err)

	// 验证响应
	// 头部信息校验
	assert.Equal(t, turnTransactionID, respMsg.TransactionID)
	assert.Equal(t, protocol.MessageTypeTurnAllocateErrorResponse, respMsg.Type)

	// 错误码校验,应为认证失败，401错误码
	errCode, _, ok := analyseErrorCode(respMsg)
	assert.True(t, ok)
	assert.Equal(t, common.ErrUnauthorizedCode, errCode)

	// 判断服务端是否返回nonce和realm
	nonce, ok := respMsg.GetAttribute(protocol.AttributeTypeNonce)
	assert.True(t, ok)
	realm, ok := respMsg.GetAttribute(protocol.AttributeTypeRealm)
	assert.True(t, ok)
	return nonce, realm
}

func buildAuthRequestMsg(userName string, nonce, realm, msgIntegrity []byte, turnTransactionID [12]byte) *protocol.Message {
	msg := protocol.NewMessage(protocol.MessageTypeTurnAllocateRequest, turnTransactionID)
	msg.BuildAttribute(protocol.AttributeTypeUsername, []byte(userName))
	msg.BuildAttribute(protocol.AttributeTypeNonce, nonce)
	msg.BuildAttribute(protocol.AttributeTypeRealm, realm)
	tsp := make([]byte, 4)
	tsp[0] = protocol.UDP
	msg.BuildAttribute(protocol.AttributeTypeRequestedTransport, tsp)
	msg.BuildAttribute(protocol.AttributeTypeMessageIntegrity, msgIntegrity)
	return msg
}

func handlerPacket(c *e2eclient.Client) (*protocol.Message, error) {
	ticker := time.NewTicker(time.Second * 10)

	for {
		select {
		case data := <-c.ReceiveData():
			ticker.Reset(time.Second * 10)

			respMsg, err := protocol.Decode(data)
			if err != nil {
				log.Printf("decode error: %v", err)
				return nil, err
			}
			// log.Printf("Response: %+v", respMsg)
			return respMsg, nil
		case <-ticker.C:
			return nil, fmt.Errorf("receive timeout")
		}
	}

}

func testTurnRequestRelayAddress(t *testing.T, client *e2eclient.Client) {
	userName := "turn-test"
	var turnTransactionID = [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	nonce, realm := getTurnServerNonce(t, client, turnTransactionID, userName)

	// 拿着服务端返回的凭证，再次认证
	msg := buildAuthRequestMsg(userName, nonce, realm, []byte{}, turnTransactionID)
	p := msg.Encode()
	client.SendMsg(p)

	respMsg, err := handlerPacket(client)
	assert.Nil(t, err)

	// 错误码校验,应为认证成功，未返回错误码
	_, _, ok := analyseErrorCode(respMsg)
	assert.False(t, ok)
	// 解析中继地址
	relayAddressByte, ok := respMsg.GetAttribute(protocol.AttributeTypeXORRelayedAddress)
	assert.Truef(t, ok, "未返回中继地址")
	relayAddr, port, err := utils.AnalyseXORAddress(relayAddressByte, turnTransactionID)
	gotIP := net.IP(relayAddr[:]).String()
	assert.Equal(t, publicIP, gotIP)
	fmt.Printf("relay address: %s, port: %d\n", gotIP, port)

	// 校验 lifeTime
	VerifyLiftTime(t, respMsg, common.DefaultLifeTime)
}

func testNonceTimeout(t *testing.T, client *e2eclient.Client) {
	userName := "nonce-timeout"
	var turnTransactionID = [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	nonce, realm := getTurnServerNonce(t, client, turnTransactionID, userName)

	time.Sleep(turn.NonceTimeout)
	// 拿着服务端返回的凭证，再次认证
	msg := buildAuthRequestMsg(userName, nonce, realm, []byte{}, turnTransactionID)
	p := msg.Encode()
	client.SendMsg(p)

	respMsg, err := handlerPacket(client)
	assert.Nil(t, err)
	// 头部信息校验
	assert.Equal(t, turnTransactionID, respMsg.TransactionID)
	assert.Equal(t, protocol.MessageTypeTurnAllocateErrorResponse, respMsg.Type)

	// 错误码校验,应为认证失败，438错误码
	errCode, _, ok := analyseErrorCode(respMsg)
	assert.True(t, ok)
	assert.Equal(t, common.ErrNonceExpiredCode, errCode)
}

func testInvalidRealm(t *testing.T, client *e2eclient.Client) {
	userName := "test-realm"
	realm := []byte("invalid realm")
	var turnTransactionID = [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	nonce, _ := getTurnServerNonce(t, client, turnTransactionID, userName)

	// 拿着服务端返回的凭证，再次认证
	msg := buildAuthRequestMsg(userName, nonce, realm, []byte{}, turnTransactionID)
	p := msg.Encode()
	client.SendMsg(p)

	respMsg, err := handlerPacket(client)
	assert.Nil(t, err)
	// 头部信息校验
	assert.Equal(t, turnTransactionID, respMsg.TransactionID)
	assert.Equal(t, protocol.MessageTypeTurnAllocateErrorResponse, respMsg.Type)

	// 错误码校验,应为认证失败，401错误码
	errCode, _, ok := analyseErrorCode(respMsg)
	assert.True(t, ok)
	assert.Equal(t, common.ErrUnauthorizedCode, errCode)
}

func testInvalidMessageIntegrity(t *testing.T, client *e2eclient.Client) {
	userName := "test-message-integrity"
	var turnTransactionID = [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	nonce, realm := getTurnServerNonce(t, client, turnTransactionID, userName)

	// 拿着服务端返回的凭证，再次认证
	msg := buildAuthRequestMsg(userName, nonce, realm, []byte("invalid message integrity"), turnTransactionID)
	p := msg.Encode()
	client.SendMsg(p)

	respMsg, err := handlerPacket(client)
	assert.Nil(t, err)
	// 头部信息校验
	assert.Equal(t, turnTransactionID, respMsg.TransactionID)
	assert.Equal(t, protocol.MessageTypeTurnAllocateErrorResponse, respMsg.Type)

	// 错误码校验,应为认证失败，400错误码
	errCode, _, ok := analyseErrorCode(respMsg)
	assert.True(t, ok)
	assert.Equal(t, common.ErrInvalidRequest, errCode)
}

func testLackRequestTransport(t *testing.T, client *e2eclient.Client) {
	userName := "lack-request-transport"
	var turnTransactionID = [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	nonce, realm := getTurnServerNonce(t, client, turnTransactionID, userName)
	msg := protocol.NewMessage(protocol.MessageTypeTurnAllocateRequest, turnTransactionID)
	msg.BuildAttribute(protocol.AttributeTypeUsername, []byte(userName))
	msg.BuildAttribute(protocol.AttributeTypeNonce, nonce)
	msg.BuildAttribute(protocol.AttributeTypeRealm, realm)
	msg.BuildAttribute(protocol.AttributeTypeMessageIntegrity, []byte{})

	p := msg.Encode()
	client.SendMsg(p)

	respMsg, err := handlerPacket(client)
	assert.Nil(t, err)
	// 头部信息校验
	assert.Equal(t, turnTransactionID, respMsg.TransactionID)
	assert.Equal(t, protocol.MessageTypeTurnAllocateErrorResponse, respMsg.Type)

	// 错误码校验,应为认证失败，400错误码
	errCode, _, ok := analyseErrorCode(respMsg)
	assert.True(t, ok)
	assert.Equal(t, common.ErrInvalidRequest, errCode)
}

func testSetLifeTimeGreaterThanMaxLimit(t *testing.T, client *e2eclient.Client) {
	userName := "turn-test"
	var turnTransactionID = [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	nonce, realm := getTurnServerNonce(t, client, turnTransactionID, userName)

	// 拿着服务端返回的凭证，再次认证
	msg := protocol.NewMessage(protocol.MessageTypeTurnAllocateRequest, turnTransactionID)
	msg.BuildAttribute(protocol.AttributeTypeUsername, []byte(userName))
	msg.BuildAttribute(protocol.AttributeTypeNonce, nonce)
	msg.BuildAttribute(protocol.AttributeTypeRealm, realm)
	lt := make([]byte, 4)
	binary.BigEndian.PutUint32(lt, uint32(common.MaxLimitLifeTime.Seconds()+1000))
	msg.BuildAttribute(protocol.AttributeTypeLifetime, lt)
	tsp := make([]byte, 4)
	tsp[0] = protocol.UDP
	msg.BuildAttribute(protocol.AttributeTypeRequestedTransport, tsp)
	msg.BuildAttribute(protocol.AttributeTypeMessageIntegrity, []byte{})

	p := msg.Encode()
	client.SendMsg(p)

	respMsg, err := handlerPacket(client)
	assert.Nil(t, err)

	// 错误码校验,应为认证成功，未返回错误码
	_, _, ok := analyseErrorCode(respMsg)
	assert.False(t, ok)

	// 校验 lifeTime
	VerifyLiftTime(t, respMsg, common.DefaultLifeTime)
}

func testSetLifeTime(t *testing.T, client *e2eclient.Client) {
	userName := "turn-test"
	var turnTransactionID = [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	nonce, realm := getTurnServerNonce(t, client, turnTransactionID, userName)

	// 拿着服务端返回的凭证，再次认证
	msg := protocol.NewMessage(protocol.MessageTypeTurnAllocateRequest, turnTransactionID)
	msg.BuildAttribute(protocol.AttributeTypeUsername, []byte(userName))
	msg.BuildAttribute(protocol.AttributeTypeNonce, nonce)
	msg.BuildAttribute(protocol.AttributeTypeRealm, realm)
	lt := make([]byte, 4)
	timeValue := 5 * time.Minute
	binary.BigEndian.PutUint32(lt, uint32(timeValue.Seconds()))
	msg.BuildAttribute(protocol.AttributeTypeLifetime, lt)
	tsp := make([]byte, 4)
	tsp[0] = protocol.UDP
	msg.BuildAttribute(protocol.AttributeTypeRequestedTransport, tsp)
	msg.BuildAttribute(protocol.AttributeTypeMessageIntegrity, []byte{})

	p := msg.Encode()
	client.SendMsg(p)

	respMsg, err := handlerPacket(client)
	assert.Nil(t, err)

	// 错误码校验,应为认证成功，未返回错误码
	_, _, ok := analyseErrorCode(respMsg)
	assert.False(t, ok)

	// 校验 lifeTime
	VerifyLiftTime(t, respMsg, timeValue)
}

func TestTurnServerE2EAllocate(t *testing.T) {
	// 启动TURN服务
	// server := startTurnServer()

	client := e2eclient.NewClient(stunAddr)
	go client.ReadLoop()
	go client.WriteLoop()

	t.Run("TURN服务端E2E测试:分配请求认证通过，并分配中继地址", func(t *testing.T) {
		testTurnRequestRelayAddress(t, client)
	})
	t.Run("TURN服务端E2E测试:分配请求认证 Nonce 超时，并返回错误码438", func(t *testing.T) {
		testNonceTimeout(t, client)
	})
	t.Run("TURN服务端E2E测试:分配请求认证失败 Realm 与服务器不符，并返回错误码401", func(t *testing.T) {
		testInvalidRealm(t, client)
	})
	t.Run("TURN服务端E2E测试:分配请求认证失败 MESSAGE-INTEGRITY 非法，并返回错误码400", func(t *testing.T) {
		testInvalidMessageIntegrity(t, client)
	})
	t.Run("TURN服务端E2E测试: 缺少 request-transport 属性，并返回错误码400", func(t *testing.T) {
		testLackRequestTransport(t, client)
	})
	t.Run("TURN服务端E2E测试: 分配请求认证通过，设置大于 lifeTime 最大值，设置未成功，返回服务器默认 lifetime 值", func(t *testing.T) {
		testSetLifeTimeGreaterThanMaxLimit(t, client)
	})
	t.Run("TURN服务端E2E测试: 分配请求认证通过，设置 lifeTime 成功，返回服务器已设置的 lifetime 值", func(t *testing.T) {
		testSetLifeTime(t, client)
	})

	// server.Close()
	client.Close()

}
