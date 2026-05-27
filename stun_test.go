package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// --- Message Parsing Tests ---

func TestParseTooShort(t *testing.T) {
	_, err := Parse([]byte{0x00, 0x01})
	if err != ErrTooShort {
		t.Fatalf("expected ErrTooShort, got %v", err)
	}
}

func TestParseBadMagicCookie(t *testing.T) {
	buf := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(buf[0:2], msgTypeBindingRequest)
	binary.BigEndian.PutUint16(buf[2:4], 0)
	binary.BigEndian.PutUint32(buf[4:8], 0xDEADBEEF) // wrong cookie
	_, err := Parse(buf)
	if err != ErrBadMagicCookie {
		t.Fatalf("expected ErrBadMagicCookie, got %v", err)
	}
}

func TestParseNotBindingRequest(t *testing.T) {
	buf := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(buf[0:2], 0x0101) // Binding Response, not Request
	binary.BigEndian.PutUint16(buf[2:4], 0)
	binary.BigEndian.PutUint32(buf[4:8], MagicCookie)
	_, err := Parse(buf)
	if err != ErrNotBinding {
		t.Fatalf("expected ErrNotBinding, got %v", err)
	}
}

func TestParseBindingRequestNoAttrs(t *testing.T) {
	buf := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(buf[0:2], msgTypeBindingRequest)
	binary.BigEndian.PutUint16(buf[2:4], 0) // no attributes
	binary.BigEndian.PutUint32(buf[4:8], MagicCookie)
	// Transaction ID = 12 bytes of 0xAA
	for i := 8; i < 20; i++ {
		buf[i] = 0xAA
	}

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Type != msgTypeBindingRequest {
		t.Errorf("type = 0x%04x, want 0x0001", msg.Type)
	}
	if msg.Length != 0 {
		t.Errorf("length = %d, want 0", msg.Length)
	}
	if len(msg.Attributes) != 0 {
		t.Errorf("attributes = %d, want 0", len(msg.Attributes))
	}
	for i, b := range msg.Transaction {
		if b != 0xAA {
			t.Errorf("transaction[%d] = 0x%02x, want 0xAA", i, b)
		}
	}
}

func TestParseBindingRequestWithAttribute(t *testing.T) {
	// One attribute: SOFTWARE = "test" (4 bytes, padded to 4).
	attrLen := 4
	bodyLen := 4 + attrLen // 2 type + 2 len + 4 value
	buf := make([]byte, HeaderSize+bodyLen)
	binary.BigEndian.PutUint16(buf[0:2], msgTypeBindingRequest)
	binary.BigEndian.PutUint16(buf[2:4], uint16(bodyLen))
	binary.BigEndian.PutUint32(buf[4:8], MagicCookie)
	binary.BigEndian.PutUint16(buf[20:22], attrTypeSoftware)
	binary.BigEndian.PutUint16(buf[22:24], uint16(attrLen))
	copy(buf[24:28], []byte("test"))

	msg, err := Parse(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msg.Attributes) != 1 {
		t.Fatalf("attributes = %d, want 1", len(msg.Attributes))
	}
	if msg.Attributes[0].Type != attrTypeSoftware {
		t.Errorf("attr type = 0x%04x, want 0x8022", msg.Attributes[0].Type)
	}
	if string(msg.Attributes[0].Value) != "test" {
		t.Errorf("attr value = %q, want %q", msg.Attributes[0].Value, "test")
	}
}

func TestParseBadLengthField(t *testing.T) {
	buf := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(buf[0:2], msgTypeBindingRequest)
	binary.BigEndian.PutUint16(buf[2:4], 9999) // way too big
	binary.BigEndian.PutUint32(buf[4:8], MagicCookie)
	_, err := Parse(buf)
	if err != ErrBadLength {
		t.Fatalf("expected ErrBadLength, got %v", err)
	}
}

// --- Response Building Tests ---

func TestBuildBindingResponseIPv4(t *testing.T) {
	req := &Message{
		Type: msgTypeBindingRequest,
	}
	// Set a known transaction ID.
	for i := 0; i < 12; i++ {
		req.Transaction[i] = byte(i)
	}

	srcAddr := &net.UDPAddr{
		IP:   net.ParseIP("192.168.1.100"),
		Port: 12345,
	}

	resp, err := BuildBindingResponse(req, srcAddr)
	if err != nil {
		t.Fatalf("build error: %v", err)
	}

	// Verify header.
	msgType := binary.BigEndian.Uint16(resp[0:2])
	if msgType != msgTypeBindingResponse {
		t.Errorf("type = 0x%04x, want 0x0101", msgType)
	}

	cookie := binary.BigEndian.Uint32(resp[4:8])
	if cookie != MagicCookie {
		t.Errorf("cookie = 0x%08x, want 0x%08x", cookie, MagicCookie)
	}

	// Verify transaction ID matches.
	for i := 0; i < 12; i++ {
		if resp[8+i] != byte(i) {
			t.Errorf("transaction[%d] = 0x%02x, want 0x%02x", i, resp[8+i], i)
		}
	}

	// Find XOR-MAPPED-ADDRESS attribute.
	found := false
	offset := HeaderSize
	msgLen := int(binary.BigEndian.Uint16(resp[2:4]))
	end := HeaderSize + msgLen
	for offset+4 <= end {
		attrType := binary.BigEndian.Uint16(resp[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(resp[offset+2 : offset+4]))
		if attrType == attrTypeXORMappedAddress {
			found = true
			// Verify XOR decoding.
			xorPort := binary.BigEndian.Uint16(resp[offset+6 : offset+8])
			decodedPort := xorPort ^ uint16(MagicCookie>>16)
			if decodedPort != 12345 {
				t.Errorf("decoded port = %d, want 12345", decodedPort)
			}

			family := resp[offset+5]
			if family != addrFamilyIPv4 {
				t.Errorf("family = %d, want 1 (IPv4)", family)
			}

			// Decode XOR'd IP.
			xorIP := resp[offset+8 : offset+12]
			decodedIP := make(net.IP, 4)
			for i := 0; i < 4; i++ {
				decodedIP[i] = xorIP[i] ^ byte(MagicCookie>>(24-uint(i)*8))
			}
			if !decodedIP.Equal(net.ParseIP("192.168.1.100").To4()) {
				t.Errorf("decoded IP = %v, want 192.168.1.100", decodedIP)
			}
			break
		}
		offset += 4 + attrLen + (4-attrLen%4)%4
	}
	if !found {
		t.Error("XOR-MAPPED-ADDRESS attribute not found in response")
	}
}

func TestBuildBindingResponseIPv6(t *testing.T) {
	req := &Message{Type: msgTypeBindingRequest}
	for i := 0; i < 12; i++ {
		req.Transaction[i] = byte(i + 10)
	}

	srcAddr := &net.UDPAddr{
		IP:   net.ParseIP("2001:db8::1"),
		Port: 5000,
	}

	resp, err := BuildBindingResponse(req, srcAddr)
	if err != nil {
		t.Fatalf("build error: %v", err)
	}

	// Find XOR-MAPPED-ADDRESS and verify IPv6 decoding.
	offset := HeaderSize
	msgLen := int(binary.BigEndian.Uint16(resp[2:4]))
	end := HeaderSize + msgLen
	found := false
	for offset+4 <= end {
		attrType := binary.BigEndian.Uint16(resp[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(resp[offset+2 : offset+4]))
		if attrType == attrTypeXORMappedAddress {
			found = true
			family := resp[offset+5]
			if family != addrFamilyIPv6 {
				t.Errorf("family = %d, want 2 (IPv6)", family)
			}
			xorPort := binary.BigEndian.Uint16(resp[offset+6 : offset+8])
			decodedPort := xorPort ^ uint16(MagicCookie>>16)
			if decodedPort != 5000 {
				t.Errorf("decoded port = %d, want 5000", decodedPort)
			}
			break
		}
		offset += 4 + attrLen + (4-attrLen%4)%4
	}
	if !found {
		t.Error("XOR-MAPPED-ADDRESS attribute not found in IPv6 response")
	}
}

func TestBuildResponseIncludesSoftware(t *testing.T) {
	req := &Message{Type: msgTypeBindingRequest}
	srcAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8000}

	resp, err := BuildBindingResponse(req, srcAddr)
	if err != nil {
		t.Fatalf("build error: %v", err)
	}

	// Scan for SOFTWARE attribute.
	offset := HeaderSize
	msgLen := int(binary.BigEndian.Uint16(resp[2:4]))
	end := HeaderSize + msgLen
	found := false
	for offset+4 <= end {
		attrType := binary.BigEndian.Uint16(resp[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(resp[offset+2 : offset+4]))
		if attrType == attrTypeSoftware {
			found = true
			// Attribute length is padded to 4 bytes; only compare actual payload.
			rawVal := resp[offset+4 : offset+4+attrLen]
			// Strip trailing null padding.
			actualLen := attrLen
			for actualLen > 0 && rawVal[actualLen-1] == 0 {
				actualLen--
			}
			val := string(rawVal[:actualLen])
			if val != ServerName {
				t.Errorf("SOFTWARE = %q, want %q", val, ServerName)
			}
			break
		}
		offset += 4 + attrLen + (4-attrLen%4)%4
	}
	if !found {
		t.Error("SOFTWARE attribute not found")
	}
}

// --- CRC32 Tests ---

func TestCRC32Checksum(t *testing.T) {
	// Known CRC32 of empty input.
	crc := crc32Checksum(nil)
	if crc != 0x00000000 {
		t.Errorf("CRC32(nil) = 0x%08x, want 0x00000000", crc)
	}

	// CRC32 of "123456789" is 0xCBF43926 (ISO 3309).
	crc = crc32Checksum([]byte("123456789"))
	if crc != 0xCBF43926 {
		t.Errorf("CRC32(123456789) = 0x%08x, want 0xCBF43926", crc)
	}
}

// --- Rate Limiter Tests ---

func TestRateLimiterAllowsNormalTraffic(t *testing.T) {
	rl := NewRateLimiter(5, 1*time.Second)
	defer rl.Stop()

	for i := 0; i < 5; i++ {
		if !rl.Allow("10.0.0.1") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
}

func TestRateLimiterBlocksExcess(t *testing.T) {
	rl := NewRateLimiter(3, 1*time.Second)
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		rl.Allow("10.0.0.2")
	}
	if rl.Allow("10.0.0.2") {
		t.Error("4th request should be blocked")
	}
	// Different IP should still be allowed.
	if !rl.Allow("10.0.0.3") {
		t.Error("different IP should be allowed")
	}
}

func TestRateLimiterWindowReset(t *testing.T) {
	rl := NewRateLimiter(2, 50*time.Millisecond)
	defer rl.Stop()

	rl.Allow("10.0.0.4")
	rl.Allow("10.0.0.4")
	if rl.Allow("10.0.0.4") {
		t.Error("should be blocked within window")
	}

	// Wait for window to expire.
	time.Sleep(60 * time.Millisecond)
	if !rl.Allow("10.0.0.4") {
		t.Error("should be allowed after window reset")
	}
}

func TestRateLimiterStats(t *testing.T) {
	rl := NewRateLimiter(10, 1*time.Second)
	defer rl.Stop()

	rl.Allow("1.1.1.1")
	rl.Allow("2.2.2.2")
	rl.Allow("3.3.3.3")

	if n := rl.Stats(); n != 3 {
		t.Errorf("Stats() = %d, want 3", n)
	}
}

// --- Handler Integration Tests ---

func TestHandlerProcessesValidRequest(t *testing.T) {
	// Build a minimal valid STUN Binding Request.
	buf := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(buf[0:2], msgTypeBindingRequest)
	binary.BigEndian.PutUint16(buf[2:4], 0)
	binary.BigEndian.PutUint32(buf[4:8], MagicCookie)
	for i := 8; i < 20; i++ {
		buf[i] = byte(i)
	}

	rl := NewRateLimiter(100, 1*time.Second)
	defer rl.Stop()
	handler := NewHandler(rl, false)

	// Use a real UDP pair for testing.
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer serverConn.Close()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer clientConn.Close()

	// Send from client to server.
	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)
	_, err = clientConn.WriteToUDP(buf, serverAddr)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read on server side and handle.
	readBuf := make([]byte, 1500)
	serverConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, clientSrc, err := serverConn.ReadFromUDP(readBuf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	pkt := make([]byte, n)
	copy(pkt, readBuf[:n])
	handler.HandlePacket(serverConn, pkt, clientSrc)

	// Read the response on the client side.
	clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 1500)
	n, _, err = clientConn.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	// Verify response is a Binding Success Response.
	msgType := binary.BigEndian.Uint16(respBuf[0:2])
	if msgType != msgTypeBindingResponse {
		t.Errorf("response type = 0x%04x, want 0x0101", msgType)
	}

	cookie := binary.BigEndian.Uint32(respBuf[4:8])
	if cookie != MagicCookie {
		t.Errorf("response cookie = 0x%08x, want 0x%08x", cookie, MagicCookie)
	}

	// Verify transaction ID echoed back.
	// The request set buf[8+i] = byte(8+i), so expect those same values.
	for i := 0; i < 12; i++ {
		expected := byte(8 + i)
		if respBuf[8+i] != expected {
			t.Errorf("response transaction[%d] = 0x%02x, want 0x%02x", i, respBuf[8+i], expected)
		}
	}
}

func TestHandlerIgnoresMalformedPacket(t *testing.T) {
	rl := NewRateLimiter(100, 1*time.Second)
	defer rl.Stop()
	handler := NewHandler(rl, false)

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer serverConn.Close()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer clientConn.Close()

	// Send garbage.
	garbage := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)
	_, err = clientConn.WriteToUDP(garbage, serverAddr)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	readBuf := make([]byte, 1500)
	serverConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, src, err := serverConn.ReadFromUDP(readBuf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	pkt := make([]byte, n)
	copy(pkt, readBuf[:n])

	// Should not panic or send a response.
	handler.HandlePacket(serverConn, pkt, src)

	// Verify nothing was sent back.
	clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, _, err = clientConn.ReadFromUDP(make([]byte, 1500))
	if err == nil {
		t.Error("expected timeout (no response), but got data")
	}
}

func TestHandlerRateLimitsFlood(t *testing.T) {
	rl := NewRateLimiter(2, 1*time.Second)
	defer rl.Stop()
	handler := NewHandler(rl, false)

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer serverConn.Close()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer clientConn.Close()

	buf := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(buf[0:2], msgTypeBindingRequest)
	binary.BigEndian.PutUint16(buf[2:4], 0)
	binary.BigEndian.PutUint32(buf[4:8], MagicCookie)

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	// Send 5 packets rapidly.
	for i := 0; i < 5; i++ {
		binary.BigEndian.PutUint16(buf[8:10], uint16(i)) // vary transaction
		clientConn.WriteToUDP(buf, serverAddr)
	}

	// Only the first 2 should get responses.
	responses := 0
	for i := 0; i < 5; i++ {
		readBuf := make([]byte, 1500)
		serverConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, src, err := serverConn.ReadFromUDP(readBuf)
		if err != nil {
			break
		}
		pkt := make([]byte, n)
		copy(pkt, readBuf[:n])
		handler.HandlePacket(serverConn, pkt, src)
	}

	// Count responses client receives.
	clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		_, _, err := clientConn.ReadFromUDP(make([]byte, 1500))
		if err != nil {
			break
		}
		responses++
	}

	if responses > 2 {
		t.Errorf("expected at most 2 responses due to rate limiting, got %d", responses)
	}
}

// --- XOR-MAPPED-ADDRESS Round-Trip ---

func TestXORMappedAddressRoundTrip(t *testing.T) {
	testCases := []struct {
		ip   string
		port int
	}{
		{"10.0.0.1", 80},
		{"192.168.1.1", 3478},
		{"172.16.0.100", 65535},
		{"255.255.255.255", 1},
	}

	for _, tc := range testCases {
		req := &Message{Type: msgTypeBindingRequest}
		for i := 0; i < 12; i++ {
			req.Transaction[i] = byte(i + 42)
		}

		srcAddr := &net.UDPAddr{
			IP:   net.ParseIP(tc.ip).To4(),
			Port: tc.port,
		}

		resp, err := BuildBindingResponse(req, srcAddr)
		if err != nil {
			t.Fatalf("build error: %v", err)
		}

		// Find and decode XOR-MAPPED-ADDRESS.
		offset := HeaderSize
		msgLen := int(binary.BigEndian.Uint16(resp[2:4]))
		end := HeaderSize + msgLen
		for offset+4 <= end {
			attrType := binary.BigEndian.Uint16(resp[offset : offset+2])
			attrLen := int(binary.BigEndian.Uint16(resp[offset+2 : offset+4]))
			if attrType == attrTypeXORMappedAddress {
				xorPort := binary.BigEndian.Uint16(resp[offset+6 : offset+8])
				decodedPort := int(xorPort ^ uint16(MagicCookie>>16))
				if decodedPort != tc.port {
					t.Errorf("%s:%d: decoded port = %d", tc.ip, tc.port, decodedPort)
				}

				xorIP := resp[offset+8 : offset+12]
				decodedIP := make(net.IP, 4)
				for i := 0; i < 4; i++ {
					decodedIP[i] = xorIP[i] ^ byte(MagicCookie>>(24-uint(i)*8))
				}
				if !decodedIP.Equal(srcAddr.IP) {
					t.Errorf("%s:%d: decoded IP = %v", tc.ip, tc.port, decodedIP)
				}
				return
			}
			offset += 4 + attrLen + (4-attrLen%4)%4
		}
		t.Errorf("%s:%d: XOR-MAPPED-ADDRESS not found", tc.ip, tc.port)
	}
}

// --- Message String ---

func TestMessageString(t *testing.T) {
	msg := &Message{
		Type:        0x0001,
		Length:      0,
		Cookie:      MagicCookie,
		Transaction: [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
	}
	s := msg.String()
	if s == "" {
		t.Error("String() returned empty")
	}
}
