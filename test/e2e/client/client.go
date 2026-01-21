package client

import (
	"log"
	"net"
	"sync"
)

type Client struct {
	conn     net.Conn
	close    bool
	onPacket func(data []byte)
	SendChan chan []byte
	recvChan chan []byte
}

func NewClient(addr string) *Client {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		panic(err)
	}

	return &Client{
		conn:     conn,
		SendChan: make(chan []byte, 100),
		recvChan: make(chan []byte, 100),
	}
}

func (c *Client) SetHandlerPacket(fn func(data []byte)) {
	c.onPacket = fn
}

var packetPool = sync.Pool{
	New: func() any {
		return make([]byte, 1024)
	},
}

func (c *Client) ReadLoop() {
	buf := make([]byte, 1024)
	for !c.close {
		n, err := c.conn.Read(buf)
		if err != nil {
			if !c.close {
				log.Printf("read from tcp error: %v", err)
			}
			return
		}

		c.recvChan <- buf[:n]
	}
}

func (c *Client) WriteLoop() {
	for !c.close {
		select {
		case data := <-c.SendChan:
			_, err := c.conn.Write(data)
			if err != nil {
				log.Printf("write to tcp error: %v", err)
				return
			}
		}
	}
}

func (c *Client) SendMsg(data []byte) {
	c.SendChan <- data
}

func (c *Client) ReceiveData() <-chan []byte {
	return c.recvChan
}

func (c *Client) Close() {
	c.close = true
	close(c.SendChan)
	close(c.recvChan)
	c.conn.Close()
}
