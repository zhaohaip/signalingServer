package udp

import (
	"log"
	"net"
)

// Connection 封装UDP客户端连接（仅负责接收分发的数据包和发送响应）
type Connection struct {
	Conn     *net.UDPConn
	addr     *net.UDPAddr
	recvChan chan []byte
	SendChan chan struct {
		target *net.UDPAddr
		data   []byte
	}
	close bool
}

func NewUDPConnection(conn *net.UDPConn, addr *net.UDPAddr) *Connection {
	return &Connection{
		Conn:     conn,
		addr:     addr,
		recvChan: make(chan []byte, 100),
		SendChan: make(chan struct {
			target *net.UDPAddr
			data   []byte
		}, 1024),
	}
}

func (c *Connection) Write(data []byte) error {
	_, err := c.Conn.WriteToUDP(data, c.addr)
	return err
}

func (c *Connection) SavePacket(packet []byte) {
	if c.close {
		return
	}

	select {
	case c.recvChan <- packet:
	default:
		packetPool.Put(packet) // 释放内存
		log.Println("udp recv queue full")
	}
}

func (c *Connection) Receive() <-chan []byte {
	return c.recvChan
}

func (c *Connection) GetRemoteAddr() *net.UDPAddr {
	return c.addr
}

func (c *Connection) Close() {
	if !c.close {
		c.close = true
		close(c.recvChan)
	}
}
