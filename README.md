# nexus-stun

Self-hosted STUN server — RFC 8489 compliant, 19 tests, 3MB binary.

## Overview

A lightweight, pure-Go STUN (Session Traversal Utilities for NAT) server implementing RFC 8489. Designed for the Tech Duinn mesh VPN to enable NAT traversal without external STUN services.

## Features

- **RFC 8489 Compliant** — Full STUN protocol implementation
- **Zero Dependencies** — Pure Go, no cgo
- **Small Binary** — ~3MB compiled
- **19 Test Cases** — Comprehensive test suite
- **Prometheus Metrics** — Request rates, error rates, latency
- **Health Endpoint** — `/health` for Kubernetes probes

## Quick Start

```bash
go build -o nexus-stun .
./nexus-stun --config config.yaml
```

## Configuration

```yaml
server:
  host: "0.0.0.0"
  port: 3478
  tls_port: 5349

logging:
  level: info
```

## Tech Stack

- Go (pure, no cgo)
- RFC 8489 (STUN)
- RFC 8445 (ICE)

## License

MIT
