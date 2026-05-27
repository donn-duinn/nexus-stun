package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Dashboard provides a web UI for the mesh VPN.
type Dashboard struct {
	cfg       *Config
	server    *http.Server
	peers     map[string]*PeerInfo
	mesh      *MeshState
	mu        sync.RWMutex
	clients   map[*websocket.Conn]bool
	clientsMu sync.Mutex
	upgrader  websocket.Upgrader
}

// MeshState holds the current state of the entire mesh for the dashboard.
type MeshState struct {
	LocalNode  *NodeState            `json:"local_node"`
	Peers      map[string]*NodeState `json:"peers"`
	Tunnels    []*TunnelState        `json:"tunnels"`
	LastUpdate time.Time             `json:"last_update"`
}

// NodeState represents a single node's status.
type NodeState struct {
	Name         string        `json:"name"`
	IP           string        `json:"ip"`
	PublicIP     string        `json:"public_ip"`
	NATType      string        `json:"nat_type"`
	Connected    bool          `json:"connected"`
	ViaRelay     bool          `json:"via_relay"`
	Latency      time.Duration `json:"latency"`
	BytesTx      uint64        `json:"bytes_tx"`
	BytesRx      uint64        `json:"bytes_rx"`
	LastSeen     time.Time     `json:"last_seen"`
	Role         string        `json:"role"`
	Hardware     HardwareConf  `json:"hardware"`
	Online       bool          `json:"online"`
}

// TunnelState represents a WireGuard tunnel between two nodes.
type TunnelState struct {
	Source      string        `json:"source"`
	Destination string        `json:"destination"`
	Active      bool          `json:"active"`
	Latency     time.Duration `json:"latency"`
	ViaRelay    bool          `json:"via_relay"`
	BytesTx     uint64        `json:"bytes_tx"`
	BytesRx     uint64        `json:"bytes_rx"`
}

// NewDashboard creates a new web dashboard.
func NewDashboard(cfg *Config) *Dashboard {
	return &Dashboard{
		cfg:     cfg,
		peers:   make(map[string]*PeerInfo),
		clients: make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// UpdateMeshState updates the dashboard with current mesh state.
func (d *Dashboard) UpdateMeshState(state *MeshState) {
	d.mu.Lock()
	d.mesh = state
	d.mu.Unlock()

	// Broadcast to WebSocket clients
	d.broadcast(state)
}

// Start starts the HTTP server for the dashboard.
func (d *Dashboard) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleIndex)
	mux.HandleFunc("/api/status", d.handleAPIStatus)
	mux.HandleFunc("/api/peers", d.handleAPIPeers)
	mux.HandleFunc("/api/topology", d.handleAPITopology)
	mux.HandleFunc("/ws", d.handleWebSocket)

	d.server = &http.Server{
		Addr:    d.cfg.Dashboard.ListenAddr,
		Handler: mux,
	}

	slog.Info("dashboard started", "addr", d.cfg.Dashboard.ListenAddr)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d.server.Shutdown(shutdownCtx)
	}()

	var err error
	if d.cfg.Dashboard.TLS.CertFile != "" && d.cfg.Dashboard.TLS.KeyFile != "" {
		err = d.server.ListenAndServeTLS(d.cfg.Dashboard.TLS.CertFile, d.cfg.Dashboard.TLS.KeyFile)
	} else {
		err = d.server.ListenAndServe()
	}

	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(dashboardHTML))
}

func (d *Dashboard) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	state := d.mesh
	d.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(state)
}

func (d *Dashboard) handleAPIPeers(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	state := d.mesh
	d.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if state != nil {
		json.NewEncoder(w).Encode(state.Peers)
	} else {
		json.NewEncoder(w).Encode(map[string]interface{}{})
	}
}

func (d *Dashboard) handleAPITopology(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	state := d.mesh
	d.mu.RUnlock()

	type topology struct {
		Nodes []topologyNode   `json:"nodes"`
		Links []topologyLink   `json:"links"`
	}

	var top topology
	if state != nil {
		for name, node := range state.Peers {
			top.Nodes = append(top.Nodes, topologyNode{
				ID:     name,
				Label:  name,
				IP:     node.IP,
				Online: node.Online,
				Role:   node.Role,
			})
		}
		if state.LocalNode != nil {
			top.Nodes = append(top.Nodes, topologyNode{
				ID:     state.LocalNode.Name,
				Label:  state.LocalNode.Name + " (self)",
				IP:     state.LocalNode.IP,
				Online: true,
				Role:   state.LocalNode.Role,
			})
		}
		for _, tunnel := range state.Tunnels {
			top.Links = append(top.Links, topologyLink{
				Source:   tunnel.Source,
				Target:   tunnel.Destination,
				Active:   tunnel.Active,
				Latency:  tunnel.Latency.String(),
				ViaRelay: tunnel.ViaRelay,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(top)
}

type topologyNode struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	IP     string `json:"ip"`
	Online bool   `json:"online"`
	Role   string `json:"role"`
}

type topologyLink struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Active   bool   `json:"active"`
	Latency  string `json:"latency"`
	ViaRelay bool   `json:"via_relay"`
}

func (d *Dashboard) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := d.upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("websocket upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	d.clientsMu.Lock()
	d.clients[conn] = true
	d.clientsMu.Unlock()

	defer func() {
		d.clientsMu.Lock()
		delete(d.clients, conn)
		d.clientsMu.Unlock()
	}()

	// Send current state immediately
	d.mu.RLock()
	state := d.mesh
	d.mu.RUnlock()
	if state != nil {
		conn.WriteJSON(state)
	}

	// Keep connection alive
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (d *Dashboard) broadcast(state *MeshState) {
	d.clientsMu.Lock()
	defer d.clientsMu.Unlock()

	for client := range d.clients {
		if err := client.WriteJSON(state); err != nil {
			client.Close()
			delete(d.clients, client)
		}
	}
}

// Stop shuts down the dashboard server.
func (d *Dashboard) Stop() {
	if d.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d.server.Shutdown(ctx)
	}
	slog.Info("dashboard stopped")
}

func RunDashboard(ctx context.Context, cfg *Config) error {
	dash := NewDashboard(cfg)
	return dash.Start(ctx)
}

const dashboardHTML = `<!DOCTYPE html>
<html>
<head>
<title>Nexus VPN - Mesh Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0f; color: #e0e0e0; }
  .header { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 20px; border-bottom: 1px solid #0f3460; }
  .header h1 { font-size: 24px; color: #00d4ff; }
  .header .subtitle { color: #888; font-size: 14px; }
  .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }
  .card { background: #1a1a2e; border: 1px solid #0f3460; border-radius: 12px; padding: 20px; }
  .card h2 { color: #00d4ff; font-size: 18px; margin-bottom: 15px; }
  .node { display: flex; align-items: center; padding: 10px; border-bottom: 1px solid #0f3460; }
  .node:last-child { border-bottom: none; }
  .node-dot { width: 12px; height: 12px; border-radius: 50%; margin-right: 12px; }
  .node-dot.online { background: #00ff88; box-shadow: 0 0 8px #00ff88; }
  .node-dot.offline { background: #ff4444; box-shadow: 0 0 8px #ff4444; }
  .node-dot.relay { background: #ffaa00; box-shadow: 0 0 8px #ffaa00; }
  .node-name { font-weight: 600; font-size: 16px; }
  .node-details { color: #888; font-size: 13px; margin-top: 4px; }
  .status-bar { display: flex; gap: 20px; margin-top: 20px; }
  .stat { background: #1a1a2e; border: 1px solid #0f3460; border-radius: 8px; padding: 15px 20px; flex: 1; text-align: center; }
  .stat-value { font-size: 28px; font-weight: 700; color: #00d4ff; }
  .stat-label { color: #888; font-size: 12px; margin-top: 4px; }
  #topology { width: 100%; height: 400px; background: #0a0a0f; border-radius: 12px; }
  .ws-status { position: fixed; bottom: 20px; right: 20px; padding: 8px 16px; border-radius: 20px; font-size: 12px; }
  .ws-status.connected { background: #00ff8833; color: #00ff88; border: 1px solid #00ff88; }
  .ws-status.disconnected { background: #ff444433; color: #ff4444; border: 1px solid #ff4444; }
</style>
</head>
<body>
<div class="header">
  <h1>Nexus VPN - Mesh Dashboard</h1>
  <div class="subtitle">Tech Duinn Swarm - WireGuard Mesh Topology</div>
</div>
<div class="container">
  <div class="status-bar">
    <div class="stat"><div class="stat-value" id="node-count">-</div><div class="stat-label">Total Nodes</div></div>
    <div class="stat"><div class="stat-value" id="online-count">-</div><div class="stat-label">Online</div></div>
    <div class="stat"><div class="stat-value" id="tunnel-count">-</div><div class="stat-label">Active Tunnels</div></div>
    <div class="stat"><div class="stat-value" id="avg-latency">-</div><div class="stat-label">Avg Latency</div></div>
  </div>
  <div class="grid">
    <div class="card">
      <h2>Nodes</h2>
      <div id="nodes-list">Connecting...</div>
    </div>
    <div class="card">
      <h2>Tunnels</h2>
      <div id="tunnels-list">-</div>
    </div>
    <div class="card">
      <h2>Network Topology</h2>
      <canvas id="topology"></canvas>
    </div>
  </div>
</div>
<div class="ws-status disconnected" id="ws-status">Disconnected</div>
<script>
const ws = new WebSocket('ws://' + location.host + '/ws');
const wsStatus = document.getElementById('ws-status');

ws.onopen = () => { wsStatus.textContent = 'Connected'; wsStatus.className = 'ws-status connected'; };
ws.onclose = () => { wsStatus.textContent = 'Disconnected'; wsStatus.className = 'ws-status disconnected'; };

ws.onmessage = (e) => {
  const state = JSON.parse(e.data);
  updateDashboard(state);
};

function updateDashboard(state) {
  const nodes = state.peers || {};
  const local = state.local_node;
  const tunnels = state.tunnels || [];

  document.getElementById('node-count').textContent = Object.keys(nodes).length + (local ? 1 : 0);
  document.getElementById('online-count').textContent = Object.values(nodes).filter(n => n.online).length + (local ? 1 : 0);
  document.getElementById('tunnel-count').textContent = tunnels.filter(t => t.active).length;

  let totalLatency = 0, latCount = 0;
  tunnels.forEach(t => { if (t.latency > 0) { totalLatency += t.latency; latCount++; } });
  document.getElementById('avg-latency').textContent = latCount > 0 ? Math.round(totalLatency/latCount) + 'ms' : '-';

  let html = '';
  if (local) {
    html += nodeHTML(local, true);
  }
  Object.entries(nodes).forEach(([name, node]) => {
    html += nodeHTML(node, false);
  });
  document.getElementById('nodes-list').innerHTML = html || 'No peers discovered';

  let thtml = '';
  tunnels.forEach(t => {
    const status = t.active ? (t.via_relay ? 'relay' : 'online') : 'offline';
    const statusText = t.via_relay ? 'via relay' : (t.active ? 'direct' : 'down');
    thtml += '<div class="node"><div class="node-dot ' + status + '"></div><div><div class="node-name">' +
      t.source + ' <-> ' + t.destination + '</div><div class="node-details">' +
      statusText + ' | ' + (t.latency ? t.latency + 'ms' : '-') + '</div></div></div>';
  });
  document.getElementById('tunnels-list').innerHTML = thtml || 'No tunnels';

  drawTopology(state);
}

function nodeHTML(node, isLocal) {
  const status = isLocal ? 'online' : (node.online ? (node.via_relay ? 'relay' : 'online') : 'offline');
  const name = isLocal ? node.name + ' (self)' : node.name;
  const details = node.ip + ' | ' + node.role + (node.nat_type ? ' | NAT: ' + node.nat_type : '');
  return '<div class="node"><div class="node-dot ' + status + '"></div><div><div class="node-name">' +
    name + '</div><div class="node-details">' + details + '</div></div></div>';
}

function drawTopology(state) {
  const canvas = document.getElementById('topology');
  const ctx = canvas.getContext('2d');
  canvas.width = canvas.offsetWidth;
  canvas.height = canvas.offsetHeight;

  const nodes = [];
  if (state.local_node) nodes.push({...state.local_node, self: true});
  Object.values(state.peers || {}).forEach(n => nodes.push(n));

  const cx = canvas.width / 2, cy = canvas.height / 2;
  const r = Math.min(cx, cy) * 0.6;

  const positions = {};
  nodes.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / nodes.length - Math.PI / 2;
    positions[n.name] = { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
  });

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  (state.tunnels || []).forEach(t => {
    const s = positions[t.source], d = positions[t.destination];
    if (!s || !d) return;
    ctx.beginPath();
    ctx.moveTo(s.x, s.y);
    ctx.lineTo(d.x, d.y);
    ctx.strokeStyle = t.active ? (t.via_relay ? '#ffaa0066' : '#00ff8866') : '#ff444433';
    ctx.lineWidth = t.active ? 2 : 1;
    ctx.stroke();
  });

  nodes.forEach(n => {
    const p = positions[n.name];
    if (!p) return;
    ctx.beginPath();
    ctx.arc(p.x, p.y, 20, 0, 2 * Math.PI);
    ctx.fillStyle = n.self ? '#00d4ff' : (n.online ? '#00ff88' : '#ff4444');
    ctx.fill();
    ctx.fillStyle = '#000';
    ctx.font = '11px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(n.name, p.x, p.y + 4);
  });
}

setInterval(() => { if (ws.readyState === WebSocket.OPEN) ws.send('ping'); }, 30000);
</script>
</body>
</html>`
