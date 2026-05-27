// nexus-stun: A minimal RFC 8489 STUN server for the NEXUSAI SWARM mesh VPN.
//
// Usage:
//
//	nexus-stun [flags]
//
// Flags:
//
//	--port int      UDP listen port (default 3478)
//	--bind string   Bind address (default "0.0.0.0")
//	--verbose       Enable per-request logging
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	// DefaultPort is the IANA-assigned STUN port.
	DefaultPort = 3478

	// DefaultBind is the default listen address.
	DefaultBind = "0.0.0.0"

	// ReadBufferSize is the UDP read buffer size.
	ReadBufferSize = 1500

	// RateLimitRequests is the max STUN requests per source per window.
	RateLimitRequests = 50

	// RateLimitWindow is the rate limit sliding window duration.
	RateLimitWindow = 10 * time.Second
)

func main() {
	port := flag.Int("port", DefaultPort, "UDP listen port (RFC 8489 default: 3478)")
	bind := flag.String("bind", DefaultBind, "Bind address")
	verbose := flag.Bool("verbose", false, "Log every request")
	flag.Parse()

	addr := net.UDPAddr{
		Port: *port,
		IP:   net.ParseIP(*bind),
	}

	conn, err := listenUDP(&addr)
	if err != nil {
		log.Fatalf("nexus-stun: bind failed: %v", err)
	}
	defer conn.Close()

	limiter := NewRateLimiter(RateLimitRequests, RateLimitWindow)
	defer limiter.Stop()

	handler := NewHandler(limiter, *verbose)

	log.Printf("nexus-stun: listening on %s:%d (RFC 8489, XOR-MAPPED-ADDRESS)", *bind, *port)

	// Graceful shutdown on SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("nexus-stun: received %v, shutting down", sig)
		conn.Close()
	}()

	buf := make([]byte, ReadBufferSize)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Check if we're shutting down.
			if isClosedError(err) {
				log.Println("nexus-stun: stopped")
				return
			}
			log.Printf("nexus-stun: read error: %v", err)
			continue
		}

		// Copy the data so the buffer can be reused immediately.
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		handler.HandlePacket(conn, pkt, src)
	}
}

// listenUDP opens a UDP socket with a generous read buffer for burst traffic.
func listenUDP(addr *net.UDPAddr) (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, err
	}
	// Set a 256KB read buffer for burst handling.
	if err := conn.SetReadBuffer(256 * 1024); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set read buffer: %w", err)
	}
	return conn, nil
}

// isClosedError checks if an error is due to a closed connection.
func isClosedError(err error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		return opErr.Err.Error() == "use of closed network connection"
	}
	return false
}
