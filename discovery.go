package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// DiscoveryMessage is the MQTT payload for peer discovery and heartbeats.
type DiscoveryMessage struct {
	NodeName   string    `json:"node_name"`
	PublicKey  string    `json:"public_key"`
	PublicIP   string    `json:"public_ip"`
	PublicPort int       `json:"public_port"`
	WGPort     int       `json:"wg_port"`
	NATType    string    `json:"nat_type"`
	Timestamp  time.Time `json:"timestamp"`
	ViaRelay   bool      `json:"via_relay,omitempty"`
	RelayAddr  string    `json:"relay_addr,omitempty"`
}

// PeerInfo holds discovered information about a peer.
type PeerInfo struct {
	DiscoveryMessage
	LastSeen       time.Time
	MissedHeartbeats int
}

// Discovery handles MQTT-based peer discovery and heartbeats.
type Discovery struct {
	cfg       *Config
	client    mqtt.Client
	peers     map[string]*PeerInfo
	mu        sync.RWMutex
	wg        sync.WaitGroup
	onPeerUpdate func(name string, info *PeerInfo) // callback when peer info updates
}

// NewDiscovery creates a new MQTT-based discovery service.
func NewDiscovery(cfg *Config) *Discovery {
	return &Discovery{
		cfg:   cfg,
		peers: make(map[string]*PeerInfo),
	}
}

// SetPeerUpdateCallback sets the function called when a peer's info is updated.
func (d *Discovery) SetPeerUpdateCallback(fn func(name string, info *PeerInfo)) {
	d.onPeerUpdate = fn
}

// Start connects to MQTT and begins discovery/heartbeat.
func (d *Discovery) Start(ctx context.Context) error {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(d.cfg.MQTT.Broker)
	opts.SetClientID(d.cfg.MQTT.ClientID)
	opts.SetAutoReconnect(true)
	opts.SetMaxReconnectInterval(30 * time.Second)
	opts.SetCleanSession(true)

	if d.cfg.MQTT.Username != "" {
		opts.SetUsername(d.cfg.MQTT.Username)
	}
	if d.cfg.MQTT.Password != "" {
		opts.SetPassword(d.cfg.MQTT.Password)
	}

	opts.SetConnectionLostHandler(func(client mqtt.Client, err error) {
		slog.Warn("MQTT connection lost", "error", err)
	})

	opts.SetOnConnectHandler(func(client mqtt.Client) {
		slog.Info("MQTT connected", "broker", d.cfg.MQTT.Broker)
		d.subscribe()
	})

	d.client = mqtt.NewClient(opts)
	token := d.client.Connect()
	token.Wait()
	if token.Error() != nil {
		return fmt.Errorf("MQTT connect: %w", token.Error())
	}

	// Start heartbeat publisher
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.heartbeatLoop(ctx)
	}()

	// Start peer health checker
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.healthCheckLoop(ctx)
	}()

	return nil
}

func (d *Discovery) subscribe() {
	topic := fmt.Sprintf("%s/+/heartbeat", d.cfg.MQTT.TopicPrefix)
	d.client.Subscribe(topic, 1, func(client mqtt.Client, msg mqtt.Message) {
		d.handleHeartbeat(msg)
	})

	// Also subscribe to presence (online/offline)
	presenceTopic := fmt.Sprintf("%s/+/presence", d.cfg.MQTT.TopicPrefix)
	d.client.Subscribe(presenceTopic, 1, func(client mqtt.Client, msg mqtt.Message) {
		d.handlePresence(msg)
	})

	slog.Info("subscribed to MQTT topics", "topic", topic)
}

func (d *Discovery) handleHeartbeat(msg mqtt.Message) {
	var hb DiscoveryMessage
	if err := json.Unmarshal(msg.Payload(), &hb); err != nil {
		slog.Debug("invalid heartbeat payload", "error", err)
		return
	}

	if hb.NodeName == d.cfg.NodeName {
		return // ignore own heartbeats
	}

	d.mu.Lock()
	peer, exists := d.peers[hb.NodeName]
	if !exists {
		peer = &PeerInfo{}
		d.peers[hb.NodeName] = peer
	}
	peer.DiscoveryMessage = hb
	peer.LastSeen = time.Now()
	peer.MissedHeartbeats = 0
	d.mu.Unlock()

	if d.onPeerUpdate != nil {
		d.onPeerUpdate(hb.NodeName, peer)
	}

	slog.Debug("heartbeat received", "node", hb.NodeName, "ip", hb.PublicIP, "port", hb.PublicPort)
}

func (d *Discovery) handlePresence(msg mqtt.Message) {
	var presence struct {
		NodeName string `json:"node_name"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal(msg.Payload(), &presence); err != nil {
		return
	}

	if presence.NodeName == d.cfg.NodeName {
		return
	}

	if presence.Status == "offline" {
		d.mu.Lock()
		if peer, ok := d.peers[presence.NodeName]; ok {
			peer.MissedHeartbeats = 999 // mark as offline
		}
		d.mu.Unlock()
		slog.Info("peer went offline", "node", presence.NodeName)
	}
}

func (d *Discovery) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(d.cfg.MQTT.HeartbeatInterval)
	defer ticker.Stop()

	// Send initial heartbeat immediately
	d.publishHeartbeat()

	for {
		select {
		case <-ctx.Done():
			d.publishPresence("offline")
			return
		case <-ticker.C:
			d.publishHeartbeat()
		}
	}
}

func (d *Discovery) publishHeartbeat() {
	hb := DiscoveryMessage{
		NodeName:  d.cfg.NodeName,
		Timestamp: time.Now(),
		WGPort:    d.cfg.WireGuard.ListenPort,
	}

	// Include STUN-discovered public endpoint if available
	// (populated externally by the orchestrator)
	data, err := json.Marshal(hb)
	if err != nil {
		slog.Error("marshaling heartbeat", "error", err)
		return
	}

	topic := fmt.Sprintf("%s/%s/heartbeat", d.cfg.MQTT.TopicPrefix, d.cfg.NodeName)
	token := d.client.Publish(topic, 1, false, data)
	token.Wait()
}

func (d *Discovery) publishPresence(status string) {
	data, _ := json.Marshal(map[string]string{
		"node_name": d.cfg.NodeName,
		"status":    status,
	})
	topic := fmt.Sprintf("%s/%s/presence", d.cfg.MQTT.TopicPrefix, d.cfg.NodeName)
	d.client.Publish(topic, 1, true, data) // retained message
}

func (d *Discovery) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(d.cfg.MQTT.HeartbeatInterval * 3)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.checkPeerHealth()
		}
	}
}

func (d *Discovery) checkPeerHealth() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for name, peer := range d.peers {
		if time.Since(peer.LastSeen) > d.cfg.MQTT.HeartbeatInterval*3 {
			peer.MissedHeartbeats++
			if peer.MissedHeartbeats >= 3 {
				slog.Warn("peer appears down", "node", name,
					"last_seen", peer.LastSeen,
					"missed", peer.MissedHeartbeats)
			}
		}
	}
}

// GetPeer returns info about a discovered peer.
func (d *Discovery) GetPeer(name string) *PeerInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if p, ok := d.peers[name]; ok {
		cp := *p
		return &cp
	}
	return nil
}

// GetPeers returns all discovered peers.
func (d *Discovery) GetPeers() map[string]*PeerInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()
	peers := make(map[string]*PeerInfo, len(d.peers))
	for k, v := range d.peers {
		cp := *v
		peers[k] = &cp
	}
	return peers
}

// UpdateLocalEndpoint publishes updated STUN-discovered endpoint info.
func (d *Discovery) UpdateLocalEndpoint(ip string, port int, natType string) {
	d.mu.Lock()
	// This will be picked up by the next heartbeat
	d.mu.Unlock()
	// Immediate announcement
	hb := DiscoveryMessage{
		NodeName:   d.cfg.NodeName,
		PublicIP:   ip,
		PublicPort: port,
		NATType:    natType,
		Timestamp:  time.Now(),
		WGPort:     d.cfg.WireGuard.ListenPort,
	}
	data, _ := json.Marshal(hb)
	topic := fmt.Sprintf("%s/%s/heartbeat", d.cfg.MQTT.TopicPrefix, d.cfg.NodeName)
	d.client.Publish(topic, 1, false, data)
}

// Stop gracefully disconnects from MQTT.
func (d *Discovery) Stop() {
	if d.client != nil && d.client.IsConnected() {
		d.publishPresence("offline")
		d.client.Disconnect(1000)
	}
	d.wg.Wait()
	slog.Info("MQTT discovery stopped")
}
