package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSServer provides MagicDNS-like resolution for .nexus.local hostnames.
type DNSServer struct {
	cfg       *Config
	conn      *net.UDPConn
	wg        sync.WaitGroup
	peers     map[string]net.IP // hostname -> IP mapping
	mu        sync.RWMutex
	cache     map[string]*dnsCacheEntry
	cacheMu   sync.RWMutex
	upstream  *net.Resolver
}

type dnsCacheEntry struct {
	ip        net.IP
	expiresAt time.Time
}

// NewDNSServer creates a new DNS server for .nexus.local resolution.
func NewDNSServer(cfg *Config) *DNSServer {
	return &DNServer{
		cfg:   cfg,
		peers: make(map[string]net.IP),
		cache: make(map[string]*dnsCacheEntry),
		upstream: &net.Resolver{
			PreferGo: true,
		},
	}
}

// AddPeer registers a hostname-to-IP mapping.
func (d *DNServer) AddPeer(hostname string, ip net.IP) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.peers[hostname] = ip
	slog.Info("DNS: added peer record", "hostname", hostname, "ip", ip)
}

// RemovePeer removes a hostname mapping.
func (d *DNServer) RemovePeer(hostname string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.peers, hostname)
}

// Start begins the DNS server on the configured address.
func (d *DNServer) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", d.cfg.DNS.ListenAddr)
	if err != nil {
		return fmt.Errorf("resolving DNS addr: %w", err)
	}

	d.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listening DNS: %w", err)
	}

	// Pre-populate DNS records from peer config
	for name, peer := range d.cfg.Peers {
		if len(peer.AllowedIPs) > 0 {
			_, ipNet, err := net.ParseCIDR(peer.AllowedIPs[0])
			if err == nil {
				hostname := fmt.Sprintf("%s.%s", name, d.cfg.DNS.Domain)
				d.AddPeer(hostname, ipNet.IP)
			}
		}
	}

	slog.Info("DNS server started", "addr", d.cfg.DNS.ListenAddr, "domain", d.cfg.DNS.Domain)

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.serveLoop(ctx)
	}()

	return nil
}

func (d *DNServer) serveLoop(ctx context.Context) {
	buf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		d.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				slog.Error("DNS read error", "error", err)
				continue
			}
		}

		go d.handleQuery(buf[:n], remoteAddr)
	}
}

func (d *DNServer) handleQuery(data []byte, remoteAddr *net.UDPAddr) {
	if len(data) < 12 {
		return
	}

	// Parse DNS header
	queryID := binary.BigEndian.Uint16(data[0:2])
	qdCount := binary.BigEndian.Uint16(data[4:6])

	if qdCount == 0 {
		return
	}

	// Parse question section
	offset := 12
	questions := make([]dnsQuestion, 0, qdCount)
	for i := 0; i < int(qdCount) && offset < len(data); i++ {
		name, newOffset, err := parseDNSName(data, offset)
		if err != nil || newOffset+4 > len(data) {
			return
		}
		qtype := binary.BigEndian.Uint16(data[newOffset : newOffset+2])
		qclass := binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4])
		questions = append(questions, dnsQuestion{
			name:  name,
			qtype: qtype,
			qclass: qclass,
		})
		offset = newOffset + 4
	}

	if len(questions) == 0 {
		return
	}

	q := questions[0]
	slog.Debug("DNS query", "name", q.name, "type", dnsTypeName(q.qtype), "from", remoteAddr)

	// Check if it's a .nexus.local query
	if strings.HasSuffix(q.name, "."+d.cfg.DNS.Domain) && q.qtype == 1 {
		d.handleNexusQuery(queryID, q, remoteAddr)
		return
	}

	// Forward to upstream
	d.forwardToUpstream(data, remoteAddr)
}

func (d *DNServer) handleNexusQuery(queryID uint16, q dnsQuestion, remoteAddr *net.UDPAddr) {
	d.mu.RLock()
	ip, ok := d.peers[q.name]
	d.mu.RUnlock()

	var response []byte

	if ok {
		response = d.buildResponse(queryID, q, ip, uint32(d.cfg.DNS.CacheTTL))
		slog.Info("DNS: resolved", "name", q.name, "ip", ip, "to", remoteAddr)
	} else {
		// Check if it's a wildcard *.nexus.local
		if q.name == d.cfg.DNS.Domain || q.name == "*."+d.cfg.DNS.Domain {
			// Return all peers
			d.mu.RLock()
			ips := make([]net.IP, 0, len(d.peers))
			for _, v := range d.peers {
				ips = append(ips, v)
			}
			d.mu.RUnlock()
			if len(ips) > 0 {
				response = d.buildMultiResponse(queryID, q, ips, uint32(d.cfg.DNS.CacheTTL))
			}
		}
		if response == nil {
			response = d.buildNXDOMAIN(queryID, q)
			slog.Debug("DNS: NXDOMAIN", "name", q.name)
		}
	}

	d.conn.WriteToUDP(response, remoteAddr)
}

func (d *DNServer) buildResponse(queryID uint16, q dnsQuestion, ip net.IP, ttl uint32) []byte {
	// DNS response packet
	var buf []byte

	// Header
	buf = append(buf, byte(queryID>>8), byte(queryID))   // ID
	buf = append(buf, 0x81, 0x80)                          // Flags: response, recursion available
	buf = append(buf, 0x00, 0x01)                          // QDCOUNT: 1
	buf = append(buf, 0x00, 0x01)                          // ANCOUNT: 1
	buf = append(buf, 0x00, 0x00)                          // NSCOUNT: 0
	buf = append(buf, 0x00, 0x00)                          // ARCOUNT: 0

	// Question
	buf = append(buf, encodeDNSName(q.name)...)
	buf = append(buf, byte(q.qtype>>8), byte(q.qtype))    // QTYPE
	buf = append(buf, byte(q.qclass>>8), byte(q.qclass))  // QCLASS

	// Answer: pointer to question name (0xC00C)
	buf = append(buf, 0xC0, 0x0C)
	buf = append(buf, 0x00, 0x01)                          // TYPE: A
	buf = append(buf, 0x00, 0x01)                          // CLASS: IN
	buf = append(buf, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl)) // TTL
	buf = append(buf, 0x00, 0x04)                          // RDLENGTH: 4
	buf = append(buf, ip.To4()...)                         // RDATA

	return buf
}

func (d *DNServer) buildMultiResponse(queryID uint16, q dnsQuestion, ips []net.IP, ttl uint32) []byte {
	var buf []byte
	ansCount := len(ips)

	buf = append(buf, byte(queryID>>8), byte(queryID))
	buf = append(buf, 0x81, 0x80)
	buf = append(buf, 0x00, 0x01)
	buf = append(buf, byte(ansCount>>8), byte(ansCount))
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00)

	buf = append(buf, encodeDNSName(q.name)...)
	buf = append(buf, byte(q.qtype>>8), byte(q.qtype))
	buf = append(buf, byte(q.qclass>>8), byte(q.qclass))

	for _, ip := range ips {
		buf = append(buf, 0xC0, 0x0C)
		buf = append(buf, 0x00, 0x01)
		buf = append(buf, 0x00, 0x01)
		buf = append(buf, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
		buf = append(buf, 0x00, 0x04)
		buf = append(buf, ip.To4()...)
	}

	return buf
}

func (d *DNServer) buildNXDOMAIN(queryID uint16, q dnsQuestion) []byte {
	var buf []byte
	buf = append(buf, byte(queryID>>8), byte(queryID))
	buf = append(buf, 0x81, 0x83) // NXDOMAIN
	buf = append(buf, 0x00, 0x01)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, encodeDNSName(q.name)...)
	buf = append(buf, byte(q.qtype>>8), byte(q.qtype))
	buf = append(buf, byte(q.qclass>>8), byte(q.qclass))
	return buf
}

func (d *DNServer) forwardToUpstream(data []byte, remoteAddr *net.UDPAddr) {
	for _, upstream := range d.cfg.DNS.Upstream {
		conn, err := net.DialTimeout("udp", upstream, 3*time.Second)
		if err != nil {
			continue
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		conn.Write(data)
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			continue
		}
		d.conn.WriteToUDP(buf[:n], remoteAddr)
		return
	}
	slog.Error("all upstream DNS servers failed")
}

// Stop shuts down the DNS server.
func (d *DNServer) Stop() {
	if d.conn != nil {
		d.conn.Close()
	}
	d.wg.Wait()
	slog.Info("DNS server stopped")
}

// DNS helper types and functions

type dnsQuestion struct {
	name   string
	qtype  uint16
	qclass uint16
}

func parseDNSName(data []byte, offset int) (string, int, error) {
	var parts []string
	for {
		if offset >= len(data) {
			return "", 0, fmt.Errorf("name offset out of bounds")
		}
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		// Handle compression pointers
		if length >= 0xC0 {
			if offset+1 >= len(data) {
				return "", 0, fmt.Errorf("compression pointer out of bounds")
			}
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			name, _, err := parseDNSName(data, pointer)
			if err != nil {
				return "", 0, err
			}
			return strings.Join(append(parts, strings.Split(name, ".")...), "."), offset + 2, nil
		}
		offset++
		if offset+length > len(data) {
			return "", 0, fmt.Errorf("name label out of bounds")
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(parts, "."), offset, nil
}

func encodeDNSName(name string) []byte {
	var buf []byte
	for _, part := range strings.Split(name, ".") {
		buf = append(buf, byte(len(part)))
		buf = append(buf, part...)
	}
	buf = append(buf, 0)
	return buf
}

func dnsTypeName(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", qtype)
	}
}

// Fix the typo in the struct name
type DNServer = DNSServer
