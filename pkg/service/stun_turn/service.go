package stun_turn

import (
	"log"
	"net"
	"webRTCInfra/pkg/common"
	"webRTCInfra/pkg/network/udp"
	"webRTCInfra/pkg/protocol"
	"webRTCInfra/pkg/service/stun_turn/turn"
)

type Service struct {
	udpSvc *udp.Server
	auth   *turn.Auth
	relay  *turn.Relay
}

func NewService(udpSvc *udp.Server, publicIP string) *Service {
	service := &Service{
		udpSvc: udpSvc,
		auth:   turn.NewAuth(),
		relay:  turn.NewRelay(publicIP),
	}
	udpSvc.SetOnPacket(service.handlePacket)
	return service
}

func (s *Service) Start() error {
	return s.udpSvc.Start()
}

func (s *Service) Close() {
	s.udpSvc.Close()
}

func (s *Service) handlePacket(conn *udp.Connection, data []byte) {
	msg, err := protocol.Decode(data)
	if err != nil {
		log.Printf("failed to decode STUN message: %v", err)
		return
	}

	clientAddr := conn.GetRemoteAddr()
	switch msg.Type {
	case protocol.MessageTypeStunBindingRequest: // stun 请求
		s.handleStunBindingRequest(clientAddr, msg)
	case protocol.MessageTypeTurnAllocateRequest: // turn 请求
		s.handleTurnAllocateRequest(clientAddr, msg)
	default:
		log.Printf("unknown STUN message type: 0x%x", msg.Type)
		return
	}
}

func (s *Service) handleStunBindingRequest(clientAddr *net.UDPAddr, msg *protocol.Message) {
	// 创建响应消息
	resp := protocol.NewMessage(protocol.MessageTypeStunBindingResponse, msg.TransactionID)

	// 设置XOR-MAPPED-ADDRESS
	xor, _ := common.XORAddress(clientAddr.IP, clientAddr.Port, msg.TransactionID)
	resp.BuildAttribute(protocol.AttributeTypeXORMappedAddress, xor)

	// 编码响应消息
	data := resp.Encode()

	// 发送响应
	s.udpSvc.Send(clientAddr, data)
}

func (s *Service) verify(clientAddr *net.UDPAddr, msg *protocol.Message) bool {
	// 1. 验证客户认证信息
	if ok, errCode, err := s.auth.Verify(msg); !ok {
		switch errCode {
		case common.ErrNonceExpiredCode, common.ErrUnauthorizedCode: // 认证失败，服务端返回错误，并携带错误码、nonce和realm
			// 创建响应消息
			resp := protocol.NewMessage(protocol.MessageTypeTurnAllocateErrorResponse, msg.TransactionID)

			// 设置错误码
			resp.SetErrorCodeAttribute(errCode, err.Error())

			// 生成nonce
			nonce := common.GenerateRandomString(turn.NonceLen)
			s.auth.AddNonce(nonce)
			resp.BuildAttribute(protocol.AttributeTypeNonce, []byte(nonce))

			resp.BuildAttribute(protocol.AttributeTypeRealm, []byte(common.Realm))
			data := resp.Encode()
			s.udpSvc.Send(clientAddr, data)
		default:
			s.buildAndSendError(clientAddr, msg.TransactionID, errCode, err.Error())
		}

		log.Printf("failed to verify client authentication: %v", err)
		return false
	}
	return true
}

func (s *Service) handleTurnAllocateRequest(clientAddr *net.UDPAddr, msg *protocol.Message) {
	//  验证客户认证信息
	if !s.verify(clientAddr, msg) {
		return
	}

	// 校验属性中是否包含 REQUESTED-TRANSPORT 属性
	requestedTransport := protocol.RequestedTransport{}
	if err := requestedTransport.Get(msg); err != nil {
		log.Printf("failed to get REQUESTED-TRANSPORT attribute: %v", err)
		s.buildAndSendError(clientAddr, msg.TransactionID, common.ErrInvalidRequest, "REQUESTED-TRANSPORT attribute is missing")
		return
	}
	if requestedTransport.Transport != protocol.UDP {
		log.Printf("unsupported transport protocol: %v", requestedTransport.Transport)
		s.buildAndSendError(clientAddr, msg.TransactionID, common.ErrUnSupportedProtocolCode, "unsupported transport protocol")
		return
	}

	// 获取TURN地址有效期
	protoLifeTime := protocol.LifeTime{}
	lifeTimeDuration := protoLifeTime.GetLifeTime(msg)

	//  转发客户端中继地址
	allocateAddr, err := s.relay.Allocate(lifeTimeDuration)
	if err != nil {
		log.Printf("failed to allocate relay address: %v", err)
		s.buildAndSendError(clientAddr, msg.TransactionID, common.ErrInsufficientResourcesCode, "no available relay addresses")
		return
	}

	// 创建中继地址响应消息
	resp := protocol.NewMessage(protocol.MessageTypeTurnAllocateSuccessResponse, msg.TransactionID)

	// 添加XOR-RELAYED-ADDRESS
	xor, _ := common.XORAddress(allocateAddr.IP, allocateAddr.Port, msg.TransactionID)
	resp.BuildAttribute(protocol.AttributeTypeXORRelayedAddress, xor)

	// 添加有效期
	protoLifeTime.AddTo(resp)

	// 添加XOR-MAPPED-ADDRESS
	xor, _ = common.XORAddress(clientAddr.IP, clientAddr.Port, msg.TransactionID)
	resp.BuildAttribute(protocol.AttributeTypeXORMappedAddress, xor)

	resp.BuildAttribute(protocol.AttributeTypeMessageIntegrity, []byte{}) // MI占位，编码时会对MI进行计算
	data := resp.Encode()
	s.udpSvc.Send(clientAddr, data)
}

func (s *Service) buildAndSendError(clientAddr *net.UDPAddr, transactionID [12]byte, errCode uint16, reason string) {
	resp := protocol.NewMessage(protocol.MessageTypeTurnAllocateErrorResponse, transactionID)
	resp.SetErrorCodeAttribute(errCode, reason)
	data := resp.Encode()
	s.udpSvc.Send(clientAddr, data)
}
