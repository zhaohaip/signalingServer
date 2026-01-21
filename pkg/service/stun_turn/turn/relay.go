package turn

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	StartPort = 50000
	EndPort   = 51000
)

type RelaySession struct {
	Addr      *net.UDPAddr
	ExpiresAt time.Time
}

type Relay struct {
	clientMu      sync.Mutex
	clientMap     map[string]*RelaySession
	RelayAddress  net.IP
	portMu        sync.Mutex
	availablePort map[int]struct{}
}

func NewRelay(publicIP string) *Relay {
	availablePort := map[int]struct{}{}
	for port := StartPort; port <= EndPort; port++ {
		// addr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(common.ServerIP, strconv.Itoa(port)))
		availablePort[port] = struct{}{}
	}
	relay := &Relay{
		clientMap:     make(map[string]*RelaySession),
		availablePort: availablePort,
		RelayAddress:  net.ParseIP(publicIP),
	}

	relay.StartClean()
	return relay
}

func (r *Relay) StartClean() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				for _, session := range r.clientMap {
					if time.Now().After(session.ExpiresAt) {
						r.Release(session.Addr)
					}
				}
			}
		}
	}()
}

func (r *Relay) generateRelayAddress() (*net.UDPAddr, error) {
	r.portMu.Lock()
	defer r.portMu.Unlock()

	if len(r.availablePort) == 0 {
		return nil, fmt.Errorf("no available port")
	}

	var port int
	for p, _ := range r.availablePort {
		port = p
		break
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(r.RelayAddress.String(), strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	delete(r.availablePort, port)
	return addr, nil
}

// Allocate 分配一个可用的中继地址
func (r *Relay) Allocate(lifeTime time.Duration) (*net.UDPAddr, error) {
	r.clientMu.Lock()
	defer r.clientMu.Unlock()

	addr, err := r.generateRelayAddress()
	if err != nil {
		return nil, err
	}

	session := &RelaySession{
		Addr:      addr,
		ExpiresAt: time.Now().Add(lifeTime),
	}

	r.clientMap[addr.String()] = session
	return addr, nil
}

// GetRelayAddr 获取中继地址
func (r *Relay) GetRelayAddr(clientAddr string) (*net.UDPAddr, bool) {
	r.clientMu.Lock()
	defer r.clientMu.Unlock()

	clientMsg, ok := r.clientMap[clientAddr]
	return clientMsg.Addr, ok
}

// Refresh 刷新中继地址的过期时间
func (r *Relay) Refresh(clientAddr string, lifeTime uint32) error {
	r.clientMu.Lock()
	defer r.clientMu.Unlock()

	client, ok := r.clientMap[clientAddr]
	if !ok {
		return fmt.Errorf("client %s not found", clientAddr)
	}
	client.ExpiresAt = time.Now().Add(time.Duration(lifeTime))
	return nil
}

// Release 释放中继地址
func (r *Relay) Release(addr *net.UDPAddr) {
	r.clientMu.Lock()
	delete(r.clientMap, addr.String())
	r.clientMu.Unlock()

	port := addr.Port

	r.portMu.Lock()
	r.availablePort[port] = struct{}{}
	r.portMu.Unlock()
}
