package main

import (
	"log"
	"net"
	"sync"
	"time"
)

// RateLimiter tracks per-source-IP request rates using a simple
// sliding-window counter. This prevents abuse without heavy allocations.
type RateLimiter struct {
	mu       sync.Mutex
	clients  map[string]*clientState
	maxRate  int           // max requests per window
	window   time.Duration // window duration
	stopOnce sync.Once
	stopCh   chan struct{}
}

type clientState struct {
	count    int
	windowStart time.Time
}

// NewRateLimiter creates a rate limiter that allows maxRate requests
// per window duration per source IP.
func NewRateLimiter(maxRate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		clients: make(map[string]*clientState),
		maxRate: maxRate,
		window:  window,
		stopCh:  make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Allow returns true if the source IP is within its rate limit.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cs, exists := rl.clients[ip]
	if !exists {
		rl.clients[ip] = &clientState{count: 1, windowStart: now}
		return true
	}

	if now.Sub(cs.windowStart) > rl.window {
		cs.count = 1
		cs.windowStart = now
		return true
	}

	if cs.count >= rl.maxRate {
		return false
	}

	cs.count++
	return true
}

// cleanup periodically removes stale entries to bound memory.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.window * 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, cs := range rl.clients {
				if now.Sub(cs.windowStart) > rl.window*2 {
					delete(rl.clients, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

// Stop halts the background cleanup goroutine.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() { close(rl.stopCh) })
}

// Stats returns current tracking state for monitoring.
func (rl *RateLimiter) Stats() (trackedIPs int) {
	rl.mu.Lock()
	trackedIPs = len(rl.clients)
	rl.mu.Unlock()
	return
}

// Handler processes incoming STUN packets.
type Handler struct {
	limiter *RateLimiter
	verbose bool
}

// NewHandler creates a handler with the given rate limiter.
func NewHandler(limiter *RateLimiter, verbose bool) *Handler {
	return &Handler{limiter: limiter, verbose: verbose}
}

// HandlePacket processes a single UDP datagram and writes the response
// back to the source via the provided connection.
func (h *Handler) HandlePacket(conn *net.UDPConn, data []byte, src *net.UDPAddr) {
	if len(data) == 0 {
		return
	}

	// Extract source IP for rate limiting.
	ip := src.IP.String()
	if !h.limiter.Allow(ip) {
		if h.verbose {
			log.Printf("[rate-limited] %s", ip)
		}
		return
	}

	// Parse the STUN message.
	msg, err := Parse(data)
	if err != nil {
		if h.verbose {
			log.Printf("[parse-error] %s: %v", ip, err)
		}
		return
	}

	// Only handle Binding Requests.
	if msg.Type != msgTypeBindingRequest {
		if h.verbose {
			log.Printf("[ignored] %s: type=0x%04x", ip, msg.Type)
		}
		return
	}

	// Build and send the Binding Success Response.
	resp, err := BuildBindingResponse(msg, src)
	if err != nil {
		log.Printf("[build-error] %s: %v", ip, err)
		return
	}

	_, err = conn.WriteToUDP(resp, src)
	if err != nil {
		if h.verbose {
			log.Printf("[send-error] %s: %v", ip, err)
		}
		return
	}

	if h.verbose {
		log.Printf("[binding] %s:%d -> XOR-MAPPED-ADDRESS", ip, src.Port)
	}
}
