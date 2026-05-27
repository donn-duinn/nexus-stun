package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// RelayServer is a DERP-like TCP relay that forwards WireGuard packets
// between peers that cannot establish direct UDP connections.
type RelayServer struct {
	cfg       *Config
	listener  net.Listener
	clients   map[string]*RelayClient
	mu        sync.RWMutex
	wg        sync.WaitGroup
}

// RelayClient is a connected relay client (one per peer).
type RelayClient struct {
	Name      string
	PublicKey string
	Conn      net.Conn
	LastSeen  time.Time
	mu        sync.Mutex
}

// RelayMessage is the wire format for relay frames.
type RelayMessage struct {
	Type    uint8
	SrcNode string
	DstNode string
	Payload []byte
}

const (
	RelayMsgData      uint8 = 0x01
	RelayMsgRegister  uint8 = 0x02
	RelayMsgPing      uint8 = 0x03
	RelayMsgPong      uint8 = 0x04
	RelayMsgDisconnect uint8 = 0x05
)

// NewRelayServer creates a new relay server.
func NewRelayServer(cfg *Config) *RelayServer {
	return &RelayServer{
		cfg:     cfg,
		clients: make(map[string]*RelayClient),
	}
}

// Start begins listening for relay connections.
func (r *RelayServer) Start(ctx context.Context) error {
	tlsConfig, err := r.buildTLSConfig()
	if err != nil {
		// Fall back to plain TCP if TLS certs not available
		slog.Warn("TLS not available for relay, using plain TCP", "error", err)
		r.listener, err = net.Listen("tcp", r.cfg.Relay.ListenAddr)
	} else {
		r.listener, err = tls.Listen("tcp", r.cfg.Relay.ListenAddr, tlsConfig)
	}
	if err != nil {
		return fmt.Errorf("relay listen: %w", err)
	}

	slog.Info("relay server started", "addr", r.cfg.Relay.ListenAddr, "tls", r.cfg.Relay.TLS.CertFile != "")

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.acceptLoop(ctx)
	}()

	return nil
}

func (r *RelayServer) acceptLoop(ctx context.Context) {
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				slog.Error("relay accept error", "error", err)
				continue
			}
		}

		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.handleClient(ctx, conn)
		}()
	}
}

func (r *RelayServer) handleClient(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// First message must be a REGISTER
	msg, err := r.readMessage(conn)
	if err != nil {
		slog.Debug("relay: failed to read registration", "error", err)
		return
	}
	if msg.Type != RelayMsgRegister {
		slog.Debug("relay: expected register, got", "type", msg.Type)
		return
	}

	client := &RelayClient{
		Name:     msg.SrcNode,
		Conn:     conn,
		LastSeen: time.Now(),
	}

	r.mu.Lock()
	r.clients[client.Name] = client
	r.mu.Unlock()

	slog.Info("relay client registered", "node", client.Name, "addr", conn.RemoteAddr())

	defer func() {
		r.mu.Lock()
		delete(r.clients, client.Name)
		r.mu.Unlock()
		slog.Info("relay client disconnected", "node", client.Name)
	}()

	// Handle incoming messages
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		msg, err := r.readMessage(conn)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		client.LastSeen = time.Now()

		switch msg.Type {
		case RelayMsgData:
			r.forwardToPeer(msg)
		case RelayMsgPing:
			r.sendMessage(conn, RelayMsgPong, "", msg.SrcNode, nil)
		}
	}
}

func (r *RelayServer) forwardToPeer(msg *RelayMessage) {
	r.mu.RLock()
	dst, ok := r.clients[msg.DstNode]
	r.mu.RUnlock()

	if !ok {
		slog.Debug("relay: destination not connected", "dst", msg.DstNode)
		return
	}

	if err := r.sendMessage(dst.Conn, RelayMsgData, msg.SrcNode, msg.DstNode, msg.Payload); err != nil {
		slog.Error("relay: failed to forward", "dst", msg.DstNode, "error", err)
	}
}

func (r *RelayServer) readMessage(conn net.Conn) (*RelayMessage, error) {
	// Wire format: [type:1][srcLen:1][src][dstLen:1][dst][payloadLen:4][payload]
	header := make([]byte, 1)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	msgType := header[0]

	// For PING/PONG, no further data
	if msgType == RelayMsgPing || msgType == RelayMsgPong {
		return &RelayMessage{Type: msgType}, nil
	}

	src, err := readString(conn)
	if err != nil {
		return nil, err
	}
	dst, err := readString(conn)
	if err != nil {
		return nil, err
	}

	var payload []byte
	if msgType == RelayMsgData {
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		payloadLen := binary.BigEndian.Uint32(lenBuf)
		if payloadLen > 65535 {
			return nil, fmt.Errorf("payload too large: %d", payloadLen)
		}
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, err
		}
	}

	return &RelayMessage{
		Type:    msgType,
		SrcNode: src,
		DstNode: dst,
		Payload: payload,
	}, nil
}

func (r *RelayServer) sendMessage(conn net.Conn, msgType uint8, src, dst string, payload []byte) error {
	// Build message
	buf := make([]byte, 1)
	buf[0] = msgType

	if msgType == RelayMsgPing || msgType == RelayMsgPong {
		_, err := conn.Write(buf)
		return err
	}

	buf = append(buf, writeString(src)...)
	buf = append(buf, writeString(dst)...)

	if msgType == RelayMsgData {
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
		buf = append(buf, lenBuf...)
		buf = append(buf, payload...)
	}

	_, err := conn.Write(buf)
	return err
}

func readString(r io.Reader) (string, error) {
	lenBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return "", err
	}
	data := make([]byte, lenBuf[0])
	if _, err := io.ReadFull(r, data); err != nil {
		return "", err
	}
	return string(data), nil
}

func writeString(s string) []byte {
	buf := make([]byte, 1+len(s))
	buf[0] = byte(len(s))
	copy(buf[1:], s)
	return buf
}

func (r *RelayServer) buildTLSConfig() (*tls.Config, error) {
	certFile := r.cfg.Relay.TLS.CertFile
	keyFile := r.cfg.Relay.TLS.KeyFile
	caFile := r.cfg.Relay.TLS.CAFile

	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("TLS cert/key not configured")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS cert: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caCert)
		config.ClientCAs = pool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return config, nil
}

// Stop shuts down the relay server.
func (r *RelayServer) Stop() {
	if r.listener != nil {
		r.listener.Close()
	}
	r.wg.Wait()
	slog.Info("relay server stopped")
}

// RelayClientConn connects to a relay server as a client.
type RelayClientConn struct {
	cfg      *Config
	conn     net.Conn
	mu       sync.Mutex
}

// NewRelayClientConn creates a relay client connection.
func NewRelayClientConn(cfg *Config) *RelayClientConn {
	return &RelayClientConn{cfg: cfg}
}

// Connect establishes a connection to the relay server and registers.
func (rc *RelayClientConn) Connect(ctx context.Context, relayAddr string) error {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", relayAddr)
	if err != nil {
		return fmt.Errorf("dialing relay: %w", err)
	}
	rc.conn = conn

	// Register with node name
	msg := &RelayMessage{
		Type:    RelayMsgRegister,
		SrcNode: rc.cfg.NodeName,
	}
	if err := rc.sendMsg(msg); err != nil {
		conn.Close()
		return fmt.Errorf("registering with relay: %w", err)
	}

	slog.Info("connected to relay server", "addr", relayAddr)
	return nil
}

// Send forwards a WireGuard packet through the relay to a destination peer.
func (rc *RelayClientConn) Send(dstNode string, payload []byte) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	return rc.sendMsg(&RelayMessage{
		Type:    RelayMsgData,
		SrcNode: rc.cfg.NodeName,
		DstNode: dstNode,
		Payload: payload,
	})
}

func (rc *RelayClientConn) sendMsg(msg *RelayMessage) error {
	r := &RelayServer{cfg: rc.cfg}
	return r.sendMessage(rc.conn, msg.Type, msg.SrcNode, msg.DstNode, msg.Payload)
}

// Close disconnects from the relay.
func (rc *RelayClientConn) Close() {
	if rc.conn != nil {
		rc.conn.Close()
	}
}
