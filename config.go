package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the full nexus-vpn configuration.
type Config struct {
	NodeName  string         `yaml:"node_name"`
	WireGuard WireGuardConf  `yaml:"wireguard"`
	STUN      STUNConf       `yaml:"stun"`
	Relay     RelayConf      `yaml:"relay"`
	MQTT      MQTTConf       `yaml:"mqtt"`
	DNS       DNSConf        `yaml:"dns"`
	Dashboard DashboardConf  `yaml:"dashboard"`
	Crypto    CryptoConf     `yaml:"crypto"`
	Peers     map[string]PeerConf `yaml:"peers"`
}

type WireGuardConf struct {
	Interface  string `yaml:"interface"`
	ListenPort int    `yaml:"listen_port"`
	MTU        int    `yaml:"mtu"`
	KeyDir     string `yaml:"key_dir"`
}

type STUNConf struct {
	Servers         []string      `yaml:"servers"`
	ListenAddr      string        `yaml:"listen_addr,omitempty"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
}

type RelayConf struct {
	ListenAddr     string        `yaml:"listen_addr"`
	TLS            TLSConf       `yaml:"tls"`
	FallbackTimeout time.Duration `yaml:"fallback_timeout"`
}

type TLSConf struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
}

type MQTTConf struct {
	Broker           string        `yaml:"broker"`
	TopicPrefix      string        `yaml:"topic_prefix"`
	ClientID         string        `yaml:"client_id"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	Username         string        `yaml:"username"`
	Password         string        `yaml:"password"`
}

type DNSConf struct {
	ListenAddr string   `yaml:"listen_addr"`
	Domain     string   `yaml:"domain"`
	Upstream   []string `yaml:"upstream"`
	CacheTTL   int      `yaml:"cache_ttl"`
}

type DashboardConf struct {
	ListenAddr string  `yaml:"listen_addr"`
	TLS        TLSConf `yaml:"tls"`
	Password   string  `yaml:"password"`
}

type CryptoConf struct {
	Protocol string `yaml:"protocol"`
	PSK      string `yaml:"psk"`
}

type PeerConf struct {
	Name              string        `yaml:"name"`
	PublicKey         string        `yaml:"public_key"`
	AllowedIPs        []string      `yaml:"allowed_ips"`
	Endpoint          string        `yaml:"endpoint"`
	TailscaleFallback string        `yaml:"tailscale_fallback"`
	Keepalive         time.Duration `yaml:"keepalive"`
	Role              string        `yaml:"role"`
	Hardware          HardwareConf  `yaml:"hardware"`
	Optional          bool          `yaml:"optional,omitempty"`
}

type HardwareConf struct {
	GPU    bool   `yaml:"gpu"`
	RAMGB  int    `yaml:"ram_gb"`
	CPU    string `yaml:"cpu"`
}

// LoadConfig reads and parses the YAML config, applying overrides.
func LoadConfig(path, nodeName string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	// Expand environment variables in config
	expanded := os.ExpandEnv(string(data))

	cfg := &Config{}
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Apply defaults
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}

	// Override node name from flag, then env
	if nodeName != "" {
		cfg.NodeName = nodeName
	} else if envNode := os.Getenv("NEXUS_NODE"); envNode != "" {
		cfg.NodeName = envNode
	}

	if cfg.NodeName == "" {
		return nil, fmt.Errorf("node_name must be set in config, --node flag, or NEXUS_NODE env")
	}

	// Apply environment overrides for secrets
	if psk := os.Getenv("NEXUS_PSK"); psk != "" {
		cfg.Crypto.PSK = psk
	}
	if user := os.Getenv("NEXUS_MQTT_USER"); user != "" {
		cfg.MQTT.Username = user
	}
	if pass := os.Getenv("NEXUS_MQTT_PASS"); pass != "" {
		cfg.MQTT.Password = pass
	}
	if pass := os.Getenv("NEXUS_DASHBOARD_PASS"); pass != "" {
		cfg.Dashboard.Password = pass
	}

	// Set MQTT client ID from node name if not overridden
	if cfg.MQTT.ClientID == "" || cfg.MQTT.ClientID == "nexus-vpn-dagda" {
		cfg.MQTT.ClientID = "nexus-vpn-" + cfg.NodeName
	}

	return cfg, nil
}

func (c *Config) applyDefaults() error {
	if c.WireGuard.Interface == "" {
		c.WireGuard.Interface = "nexus0"
	}
	if c.WireGuard.ListenPort == 0 {
		c.WireGuard.ListenPort = 51820
	}
	if c.WireGuard.MTU == 0 {
		c.WireGuard.MTU = 1420
	}
	if c.WireGuard.KeyDir == "" {
		c.WireGuard.KeyDir = "/etc/nexus-vpn/keys"
	}
	if c.STUN.RefreshInterval == 0 {
		c.STUN.RefreshInterval = 30 * time.Second
	}
	if c.Relay.FallbackTimeout == 0 {
		c.Relay.FallbackTimeout = 10 * time.Second
	}
	if c.MQTT.Broker == "" {
		c.MQTT.Broker = "tcp://dagda:1883"
	}
	if c.MQTT.TopicPrefix == "" {
		c.MQTT.TopicPrefix = "nexus-vpn"
	}
	if c.MQTT.HeartbeatInterval == 0 {
		c.MQTT.HeartbeatInterval = 15 * time.Second
	}
	if c.DNS.Domain == "" {
		c.DNS.Domain = "nexus.local"
	}
	if c.DNS.CacheTTL == 0 {
		c.DNS.CacheTTL = 300
	}
	if c.Crypto.Protocol == "" {
		c.Crypto.Protocol = "Noise_XX_25519_ChaChaPoly_SHA256"
	}
	if len(c.STUN.Servers) == 0 {
		c.STUN.Servers = []string{"stun.l.google.com:19302", "stun1.l.google.com:19302"}
	}

	return nil
}

// GetPeer returns the config for a named peer, or nil if not found.
func (c *Config) GetPeer(name string) *PeerConf {
	if p, ok := c.Peers[name]; ok {
		return &p
	}
	return nil
}

// GetOtherPeers returns all peers except the current node.
func (c *Config) GetOtherPeers() map[string]PeerConf {
	others := make(map[string]PeerConf)
	for name, peer := range c.Peers {
		if name != c.NodeName {
			others[name] = peer
		}
	}
	return others
}
