package main

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// WireGuardManager manages the userspace WireGuard device and its peers.
type WireGuardManager struct {
	cfg      *Config
	device   *device.Device
	tun      *device.Device
	net      *netstack.TUN
	privateKey [32]byte
	publicKey  [32]byte
	mu       sync.RWMutex
	peers    map[string]*PeerState
}

// PeerState tracks the current state of a WireGuard peer.
type PeerState struct {
	Name        string
	PublicKey   [32]byte
	AllowedIPs  []net.IPNet
	Endpoint    string
	Latency     time.Duration
	LastHandshake time.Time
	BytesTx     uint64
	BytesRx     uint64
	Connected   bool
	ViaRelay    bool
}

// NewWireGuardManager creates a new WireGuard manager with generated or loaded keys.
func NewWireGuardManager(cfg *Config) (*WireGuardManager, error) {
	mgr := &WireGuardManager{
		cfg:   cfg,
		peers: make(map[string]*PeerState),
	}

	// Load or generate keys
	if err := mgr.loadOrGenerateKeys(); err != nil {
		return nil, fmt.Errorf("key management: %w", err)
	}

	return mgr, nil
}

func (m *WireGuardManager) loadOrGenerateKeys() error {
	keyDir := m.cfg.WireGuard.KeyDir
	privPath := filepath.Join(keyDir, m.cfg.NodeName+".key")
	pubPath := filepath.Join(keyDir, m.cfg.NodeName+".pub")

	// Try to load existing keys
	if data, err := os.ReadFile(privPath); err == nil {
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil || len(decoded) != 32 {
			return fmt.Errorf("invalid private key in %s", privPath)
		}
		copy(m.privateKey[:], decoded)
		curve25519.ScalarBaseMult(&m.publicKey, &m.privateKey)
		slog.Info("loaded existing keys", "node", m.cfg.NodeName, "pubkey", base64.StdEncoding.EncodeToString(m.publicKey[:]))
		return nil
	}

	// Generate new keys
	slog.Info("generating new WireGuard keys", "node", m.cfg.NodeName)
	if err := GenerateKeys(keyDir); err != nil {
		return fmt.Errorf("generating keys: %w", err)
	}

	// Load the newly generated keys
	data, err := os.ReadFile(privPath)
	if err != nil {
		return fmt.Errorf("reading generated key: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("invalid generated key")
	}
	copy(m.privateKey[:], decoded)
	curve25519.ScalarBaseMult(&m.publicKey, &m.privateKey)

	_ = pubPath // used by GenerateKeys
	return nil
}

// Start brings up the WireGuard interface and adds configured peers.
func (m *WireGuardManager) Start() error {
	slog.Info("starting WireGuard", "interface", m.cfg.WireGuard.Interface, "port", m.cfg.WireGuard.ListenPort)

	// Create TUN device using netstack (userspace)
	tun, tnet, err := netstack.CreateNetTUN(
		[]net.IP{m.getNodeIP()},
		[]string{},
		m.cfg.WireGuard.MTU,
	)
	if err != nil {
		return fmt.Errorf("creating TUN: %w", err)
	}
	m.net = tnet

	// Create WireGuard device
	m.tun = device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))

	// Configure device with private key and listen port
	privKeyStr := base64.StdEncoding.EncodeToString(m.privateKey[:])
	configStr := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", privKeyStr, m.cfg.WireGuard.ListenPort)

	if err := m.tun.IpcSet(configStr); err != nil {
		return fmt.Errorf("configuring WireGuard device: %w", err)
	}

	// Add peers
	for name, peer := range m.cfg.GetOtherPeers() {
		if peer.PublicKey == "" {
			slog.Warn("skipping peer with no public key", "peer", name)
			continue
		}
		if err := m.AddPeer(name, peer.PublicKey, peer.AllowedIPs, peer.Endpoint, peer.TailscaleFallback); err != nil {
			slog.Error("failed to add peer", "peer", name, "error", err)
		}
	}

	if err := m.tun.Up(); err != nil {
		return fmt.Errorf("bringing up WireGuard: %w", err)
	}

	slog.Info("WireGuard started", "publicKey", base64.StdEncoding.EncodeToString(m.publicKey[:]))
	return nil
}

// AddPeer adds or updates a WireGuard peer.
func (m *WireGuardManager) AddPeer(name, pubKeyB64 string, allowedIPs []string, endpoint, fallback string) error {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil || len(pubKeyBytes) != 32 {
		return fmt.Errorf("invalid public key for %s", name)
	}

	var pubKey [32]byte
	copy(pubKey[:], pubKeyBytes)

	// Build WireGuard peer config
	config := fmt.Sprintf("public_key=%s\n", pubKeyB64)
	if endpoint != "" {
		config += fmt.Sprintf("endpoint=%s\n", endpoint)
	} else if fallback != "" {
		config += fmt.Sprintf("endpoint=%s\n", fallback)
	}
	for _, aip := range allowedIPs {
		config += fmt.Sprintf("allowed_ip=%s\n", aip)
	}
	config += "persistent_keepalive_interval=25\n"

	if err := m.tun.IpcSet(config); err != nil {
		return fmt.Errorf("adding peer %s: %w", name, err)
	}

	m.mu.Lock()
	m.peers[name] = &PeerState{
		Name:       name,
		PublicKey:  pubKey,
		Endpoint:   endpoint,
		Connected:  false,
		ViaRelay:   false,
	}
	m.mu.Unlock()

	slog.Info("added peer", "peer", name, "endpoint", endpoint, "fallback", fallback)
	return nil
}

// UpdatePeerEndpoint updates a peer's endpoint (from STUN discovery or relay).
func (m *WireGuardManager) UpdatePeerEndpoint(name, endpoint string, viaRelay bool) error {
	m.mu.RLock()
	peer, ok := m.peers[name]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("unknown peer: %s", name)
	}

	pubKeyB64 := base64.StdEncoding.EncodeToString(peer.PublicKey[:])
	config := fmt.Sprintf("public_key=%s\nendpoint=%s\nreplace_endpoints=true\n", pubKeyB64, endpoint)

	if err := m.tun.IpcSet(config); err != nil {
		return fmt.Errorf("updating endpoint for %s: %w", name, err)
	}

	m.mu.Lock()
	peer.Endpoint = endpoint
	peer.ViaRelay = viaRelay
	m.mu.Unlock()

	slog.Info("updated peer endpoint", "peer", name, "endpoint", endpoint, "relay", viaRelay)
	return nil
}

// getNodeIP returns the IP address for the current node.
func (m *WireGuardManager) getNodeIP() net.IP {
	if peer, ok := m.cfg.Peers[m.cfg.NodeName]; ok {
		if len(peer.AllowedIPs) > 0 {
			_, ipNet, err := net.ParseCIDR(peer.AllowedIPs[0])
			if err == nil {
				return ipNet.IP
			}
		}
	}
	// Default mapping
	switch m.cfg.NodeName {
	case "dagda":
		return net.ParseIP("100.64.0.1")
	case "brigid":
		return net.ParseIP("100.64.0.2")
	case "cernunnos":
		return net.ParseIP("100.64.0.3")
	case "aengus":
		return net.ParseIP("100.64.0.4")
	default:
		return net.ParseIP("100.64.0.1")
	}
}

// GetNet returns the netstack network for dialing through the tunnel.
func (m *WireGuardManager) GetNet() *netstack.TUN {
	return m.net
}

// GetPublicKey returns this node's public key.
func (m *WireGuardManager) GetPublicKey() [32]byte {
	return m.publicKey
}

// GetPeerStates returns a snapshot of all peer states.
func (m *WireGuardManager) GetPeerStates() map[string]*PeerState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	states := make(map[string]*PeerState, len(m.peers))
	for k, v := range m.peers {
		cp := *v
		states[k] = &cp
	}
	return states
}

// Stop shuts down the WireGuard device.
func (m *WireGuardManager) Stop() {
	if m.tun != nil {
		m.tun.Close()
		slog.Info("WireGuard stopped")
	}
}

// GenerateKeys generates a WireGuard keypair and writes to the given directory.
func GenerateKeys(outDir string) error {
	var privateKey [32]byte
	if _, err := os.Read("/dev/urandom", privateKey[:]); err != nil {
		return fmt.Errorf("reading random: %w", err)
	}
	// Clamp private key per WireGuard/Curve25519 spec
	privateKey[0] &= 248
	privateKey[31] = (privateKey[31] & 127) | 64

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	privB64 := base64.StdEncoding.EncodeToString(privateKey[:])
	pubB64 := base64.StdEncoding.EncodeToString(publicKey[:])

	if err := os.MkdirAll(outDir, 0700); err != nil {
		return fmt.Errorf("creating key dir: %w", err)
	}

	privPath := filepath.Join(outDir, "private.key")
	pubPath := filepath.Join(outDir, "public.key")

	if err := os.WriteFile(privPath, []byte(privB64), 0600); err != nil {
		return fmt.Errorf("writing private key: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(pubB64), 0644); err != nil {
		return fmt.Errorf("writing public key: %w", err)
	}

	fmt.Printf("Private key: %s\n", privB64)
	fmt.Printf("Public key:  %s\n", pubB64)
	return nil
}
