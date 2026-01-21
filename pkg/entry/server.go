package entry

import (
	"log"
	"sync"
	"webRTCInfra/pkg/api/http"
	"webRTCInfra/pkg/network/udp"
	"webRTCInfra/pkg/network/websocket"
	"webRTCInfra/pkg/service/sdp"
	stuntrun "webRTCInfra/pkg/service/stun_turn"
)

type Server struct {
	wsManager   *websocket.Manager
	apiHandler  *http.Handler
	udpServer   *udp.Server
	sdpService  *sdp.Service
	stunService *stuntrun.Service
	stunAddr    string
	httpAddr    string

	wg sync.WaitGroup
}

func NewServer(httpAddr, stunAddr, publicIP string) *Server {
	// 1. 初始化WebSocket连接管理器（SDP服务用）
	wsManager := websocket.NewManager()

	// 2. 初始化SDP业务服务和API处理器
	sdpService := sdp.NewService(wsManager)
	apiHandler := http.NewHandler(sdpService)

	// 3. 初始化UDP服务器和STUN服务
	udpServer := udp.NewService(stunAddr, nil)
	stunService := stuntrun.NewService(udpServer, publicIP)
	return &Server{
		wsManager:   wsManager,
		apiHandler:  apiHandler,
		udpServer:   udpServer,
		sdpService:  sdpService,
		stunService: stunService,
		stunAddr:    stunAddr,
		httpAddr:    httpAddr,
	}
}

func (s *Server) Start() error {
	if err := s.stunService.Start(); err != nil {
		return err
	}
	log.Println("stun_turn service started at", s.stunAddr)

	s.wg.Add(1)
	go s.startHttpServer()
	return nil
}

func (s *Server) startHttpServer() {
	defer s.wg.Done()
	r := http.NewRouter(s.apiHandler)
	if err := r.Run(s.httpAddr); err != nil {
		log.Printf("http server start error: %v", err)
	}
	log.Printf("server started at %s", s.httpAddr)

}

func (s *Server) Close() {
	s.stunService.Close()
	s.wg.Wait()
	log.Println("server closed")
}
