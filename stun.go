package main

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	stunMagicCookie    = 0x2112A442
	stunMethodBinding  = 0x0001
	stunClassRequest   = 0x0000
	stunClassSuccess   = 0x0100
	stunAttrMappedAddr = 0x0001
	stunAttrXORMapped  = 0x0020
)

// STUNResult holds the result of a STUN binding request.
type STUNResult struct {
	MappedIP   net.IP
	MappedPort int
	Server     string
	RTT        time.Duration
	NATType    NATType
}

// NATType describes the NAT classification.
type NATType int

const (
	NATNone NATType = iota
	NATFullCone
	NATRestrictedCone
	NATPortRestricted
	NATSymmetric
	NATUnknown
)

func (n NATType) String() string {
	switch n {
	case NATNone:
		return "No NAT (public IP)"
	case NATFullCone:
		return "Full Cone NAT"
	case NATRestrictedCone:
		return "Restricted Cone NAT"
	case NATPortRestricted:
		return "Port Restricted Cone NAT"
	case NATSymmetric:
		return "Symmetric NAT"
	default:
		return "Unknown"
	}
}

// STUNClient discovers the public IP/port of this node via STUN servers.
type STUNClient struct {
	cfg     *Config
	mu      sync.RWMutex
	results map[string]*STUNResult
	natType NATType
	publicIP net.IP
	publicPort int
}

// NewSTUNClient creates a new STUN client.
func NewSTUNClient(cfg *Config) *STUNClient {
	return &STUNClient{
		cfg:     cfg,
		results: make(map[string]*STUNResult),
	}
}

// Discover sends STUN binding requests to all configured servers and returns
// the public endpoint discovered from the first responding server.
func (s *STUNClient) Discover() (*STUNResult, error) {
	var lastErr error

	for _, server := range s.cfg.STUN.Servers {
		result, err := s.bindingRequest(server)
		if err != nil {
			slog.Debug("STUN request failed", "server", server, "error", err)
			lastErr = err
			continue
		}

		s.mu.Lock()
		s.results[server] = result
		s.publicIP = result.MappedIP
		s.publicPort = result.MappedPort
		s.mu.Unlock()

		slog.Info("STUN discovery success",
			"server", server,
			"public_ip", result.MappedIP,
			"public_port", result.MappedPort,
			"rtt", result.RTT,
		)

		// Detect NAT type using secondary server if available
		if len(s.cfg.STUN.Servers) > 1 && server == s.cfg.STUN.Servers[0] {
			s.detectNATType(result)
		}

		return result, nil
	}

	return nil, fmt.Errorf("all STUN servers failed, last error: %w", lastErr)
}

func (s *STUNClient) bindingRequest(server string) (*STUNResult, error) {
	start := time.Now()

	conn, err := net.DialTimeout("udp4", server, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dialing %s: %w", server, err)
	}
	defer conn.Close()

	// Build STUN Binding Request (RFC 8489)
	msg := s.buildBindingRequest()
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("sending to %s: %w", server, err)
	}

	// Read response with timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("reading from %s: %w", server, err)
	}

	rtt := time.Since(start)

	result, err := s.parseBindingResponse(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("parsing response from %s: %w", server, err)
	}

	result.Server = server
	result.RTT = rtt
	return result, nil
}

func (s *STUNClient) buildBindingRequest() []byte {
	msg := make([]byte, 20)

	// Message Type: Binding Request (0x0001)
	binary.BigEndian.PutUint16(msg[0:2], stunMethodBinding)
	// Message Length: 0 (no attributes)
	binary.BigEndian.PutUint16(msg[2:4], 0)
	// Magic Cookie
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)
	// Transaction ID (96 bits)
	for i := 8; i < 20; i++ {
		msg[i] = byte(i) // deterministic but unique
	}

	return msg
}

func (s *STUNClient) parseBindingResponse(data []byte) (*STUNResult, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("response too short: %d bytes", len(data))
	}

	// Verify magic cookie
	cookie := binary.BigEndian.Uint32(data[4:8])
	if cookie != stunMagicCookie {
		return nil, fmt.Errorf("invalid magic cookie: 0x%08x", cookie)
	}

	// Check message type (should be Binding Success Response 0x0101)
	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != stunClassSuccess+stunMethodBinding {
		return nil, fmt.Errorf("unexpected message type: 0x%04x", msgType)
	}

	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < 20+msgLen {
		return nil, fmt.Errorf("message truncated")
	}

	// Parse attributes
	offset := 20
	for offset < 20+msgLen {
		if offset+4 > len(data) {
			break
		}
		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+attrLen > len(data) {
			break
		}

		switch attrType {
		case stunAttrXORMapped:
			ip, port := parseXORMappedAddr(data[offset:offset+attrLen], data[4:20])
			return &STUNResult{MappedIP: ip, MappedPort: port}, nil
		case stunAttrMappedAddr:
			ip, port := parseMappedAddr(data[offset : offset+attrLen])
			return &STUNResult{MappedIP: ip, MappedPort: port}, nil
		}

		offset += attrLen
		// Pad to 4-byte boundary
		if attrLen%4 != 0 {
			offset += 4 - (attrLen % 4)
		}
	}

	return nil, fmt.Errorf("no MAPPED-ADDRESS or XOR-MAPPED-ADDRESS in response")
}

func parseXORMappedAddr(data []byte, transactionID []byte) (net.IP, int) {
	if len(data) < 8 {
		return nil, 0
	}
	// family := data[1]
	port := int(binary.BigEndian.Uint16(data[2:4])) ^ (stunMagicCookie >> 16)
	ip := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		ip[i] = data[4+i] ^ byte(stunMagicCookie>>(24-uint(i)*8))
	}
	return ip, port
}

func parseMappedAddr(data []byte) (net.IP, int) {
	if len(data) < 8 {
		return nil, 0
	}
	port := int(binary.BigEndian.Uint16(data[2:4]))
	ip := net.IPv4(data[4], data[5], data[6], data[7])
	return ip, port
}

// detectNATType performs NAT classification by comparing results from
// different STUN servers (simplified version of RFC 3489 Section 5).
func (s *STUNClient) detectNATType(firstResult *STUNResult) {
	if len(s.cfg.STUN.Servers) < 2 {
		s.natType = NATUnknown
		return
	}

	// Try second server with same local port
	secondResult, err := s.bindingRequest(s.cfg.STUN.Servers[1])
	if err != nil {
		s.natType = NATUnknown
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if firstResult.MappedIP.Equal(secondResult.MappedIP) &&
		firstResult.MappedPort == secondResult.MappedPort {
		// Same mapping from different servers = cone NAT (or no NAT)
		s.natType = NATFullCone
	} else {
		// Different mapping from different servers = symmetric NAT
		s.natType = NATSymmetric
	}

	slog.Info("NAT type detected", "type", s.natType.String(),
		"server1", fmt.Sprintf("%s:%d", firstResult.MappedIP, firstResult.MappedPort),
		"server2", fmt.Sprintf("%s:%d", secondResult.MappedIP, secondResult.MappedPort),
	)
}

// GetPublicEndpoint returns the last discovered public IP and port.
func (s *STUNClient) GetPublicEndpoint() (net.IP, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.publicIP, s.publicPort
}

// GetNATType returns the detected NAT type.
func (s *STUNClient) GetNATType() NATType {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.natType
}

// RunPeriodicDiscovery runs STUN discovery at the configured interval.
func (s *STUNClient) RunPeriodicDiscovery(ctx interface{ Done() <-chan struct{} }) {
	ticker := time.NewTicker(s.cfg.STUN.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.Discover(); err != nil {
				slog.Warn("periodic STUN discovery failed", "error", err)
			}
		}
	}
}
