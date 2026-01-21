package udp

import (
	"log"
	"net"
	"sync"
	"time"
)

var UDPTimeOut = time.Minute * 5

// Server UDP服务器，负责监听端口并分发数据包
type Server struct {
	addr     string
	conn     *net.UDPConn
	clients  map[string]*Connection // 客户端链接映射
	mu       sync.RWMutex
	onPacket func(*Connection, []byte)
	close    bool
	sendChan chan struct {
		target *net.UDPAddr
		data   []byte
	}
}

func NewService(addr string, onPacket func(*Connection, []byte)) *Server {
	return &Server{
		addr:     addr,
		clients:  make(map[string]*Connection),
		onPacket: onPacket,
		sendChan: make(chan struct {
			target *net.UDPAddr
			data   []byte
		}, 1024),
	}
}

func (s *Server) SetOnPacket(fn func(*Connection, []byte)) {
	s.onPacket = fn
}

func (s *Server) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	s.conn = conn
	s.close = false

	go s.ListenLoop()
	go s.WriteLoop()

	return nil
}

func (s *Server) Send(target *net.UDPAddr, data []byte) {
	if s.close {
		return
	}

	select {
	case s.sendChan <- struct {
		target *net.UDPAddr
		data   []byte
	}{target: target, data: data}:
	default:
		log.Println("udp send queue full")
	}
}

func (s *Server) WriteLoop() {
	for {
		for packet := range s.sendChan {
			if packet.target != nil {
				_, err := s.conn.WriteToUDP(packet.data, packet.target)
				if err != nil {
					log.Printf("write to udp error: %v", err)
				}
			}
		}
	}
}

// 定义数据包缓存池
var packetPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1024)
	},
}

func (s *Server) ListenLoop() {
	buf := make([]byte, 1024)
	for !s.close {
		n, clientAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if !s.close {
				log.Printf("read from udp error: %v", err)
			}
			return
		}

		// 从缓存池中获取内存
		packet := packetPool.Get().([]byte)[:n]
		copy(packet, buf[:n])

		conn := s.getOrCreateClient(clientAddr)
		conn.SavePacket(packet) // 将数据分发至通道
	}
}

func (s *Server) getOrCreateClient(clientAddr *net.UDPAddr) *Connection {
	clientKey := clientAddr.String()

	s.mu.RLock()
	conn, ok := s.clients[clientKey]
	s.mu.RUnlock()
	if !ok {
		conn = NewUDPConnection(s.conn, clientAddr)
		s.mu.Lock()
		s.clients[clientKey] = conn
		s.mu.Unlock()

		go s.handlePackets(conn)
	}
	log.Printf("client %s connected", clientAddr.String())

	return conn
}

func (s *Server) handlePackets(conn *Connection) {
	ticker := time.NewTicker(UDPTimeOut)
	clientAddr := conn.GetRemoteAddr().String()
	defer func() {
		s.mu.Lock()
		delete(s.clients, clientAddr)
		s.mu.Unlock()
		conn.Close()
	}()

	// 从通道中读取分发的数据包，调用业务层回调处理
	for {
		select {
		case pocket, ok := <-conn.Receive():
			if s.onPacket != nil && ok {
				s.onPacket(conn, pocket) // 处理数据包
				ticker.Reset(UDPTimeOut) // 重置超时计时器
			}
			packetPool.Put(pocket) // 处理完成后将内存放回缓存池

		case <-ticker.C:
			log.Printf("client %s timeout, close connection", clientAddr)
			return
		}
	}
}

func (s *Server) Close() {
	s.close = true
	close(s.sendChan)
	if s.conn != nil {
		s.conn.Close()
	}
	log.Println("udp service closed")
}
