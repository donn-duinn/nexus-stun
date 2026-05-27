// Package main implements an RFC 8489 compliant STUN server.
//
// Message format (RFC 8489 Section 6):
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |0 0|     STUN Message Type     |         Message Length        |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                         Magic Cookie                          |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                                                               |
//  |                     Transaction ID (96 bits)                  |
//  |                                                               |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// STUN protocol constants (RFC 8489).
const (
	// MagicCookie is the fixed value 0x2112A442 in STUN messages.
	MagicCookie uint32 = 0x2112A442

	// HeaderSize is the minimum STUN message header size (20 bytes).
	HeaderSize = 20

	// MaxMessageSize is the maximum allowed STUN message size.
	MaxMessageSize = 65535

	// Message type constants.
	msgTypeBindingRequest uint16 = 0x0001
	msgTypeBindingResponse uint16 = 0x0101

	// Attribute type constants.
	attrTypeMappedAddress     uint16 = 0x0001
	attrTypeXORMappedAddress  uint16 = 0x0020
	attrTypeSoftware          uint16 = 0x8022
	attrTypeFingerprint       uint16 = 0x8028

	// Address family constants.
	addrFamilyIPv4 byte = 0x01
	addrFamilyIPv6 byte = 0x02
)

// ServerName is the SOFTWARE attribute value.
const ServerName = "nexus-stun/1.0"

// Message represents a parsed STUN message.
type Message struct {
	Type        uint16
	Length      uint16
	Cookie      uint32
	Transaction [12]byte
	Attributes  []Attribute
}

// Attribute represents a single STUN attribute.
type Attribute struct {
	Type   uint16
	Length uint16
	Value  []byte
}

// Errors returned by the parser.
var (
	ErrTooShort       = errors.New("stun: message too short")
	ErrBadLength      = errors.New("stun: message length field exceeds data")
	ErrBadMagicCookie = errors.New("stun: invalid magic cookie")
	ErrNotBinding     = errors.New("stun: not a binding request")
)

// Parse decodes a raw STUN message from bytes.
// Returns an error if the message is malformed or not a Binding Request.
func Parse(data []byte) (*Message, error) {
	if len(data) < HeaderSize {
		return nil, ErrTooShort
	}

	msgLen := binary.BigEndian.Uint16(data[2:4])
	if int(msgLen)+HeaderSize > len(data) {
		return nil, ErrBadLength
	}

	cookie := binary.BigEndian.Uint32(data[4:8])
	if cookie != MagicCookie {
		return nil, ErrBadMagicCookie
	}

	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != msgTypeBindingRequest {
		return nil, ErrNotBinding
	}

	msg := &Message{
		Type:   msgType,
		Length: msgLen,
		Cookie: cookie,
	}
	copy(msg.Transaction[:], data[8:20])

	// Parse attributes.
	offset := HeaderSize
	end := HeaderSize + int(msgLen)
	for offset < end {
		if offset+4 > end {
			break
		}
		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		attrEnd := offset + 4 + int(attrLen)
		if attrEnd > end {
			break
		}
		val := make([]byte, attrLen)
		copy(val, data[offset+4:attrEnd])
		msg.Attributes = append(msg.Attributes, Attribute{
			Type:   attrType,
			Length: attrLen,
			Value:  val,
		})
		// Attributes are padded to 4-byte boundaries.
		offset = attrEnd + (4-int(attrLen)%4)%4
	}

	return msg, nil
}

// BuildBindingResponse constructs a Binding Success Response for the given
// request, including XOR-MAPPED-ADDRESS, SOFTWARE, and FINGERPRINT attributes.
func BuildBindingResponse(req *Message, srcAddr *net.UDPAddr) ([]byte, error) {
	// Determine if the source is IPv4 or IPv6.
	var family byte
	var xorIP []byte
	var xorPort uint16

	srcIP4 := srcAddr.IP.To4()
	if srcIP4 != nil {
		family = addrFamilyIPv4
		xorIP = make([]byte, 4)
		for i := 0; i < 4; i++ {
			xorIP[i] = srcIP4[i] ^ byte(MagicCookie>>(24-uint(i)*8))
		}
	} else {
		family = addrFamilyIPv6
		srcIP16 := srcAddr.IP.To16()
		xorIP = make([]byte, 16)
		cookieBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(cookieBytes, MagicCookie)
		for i := 0; i < 4; i++ {
			xorIP[i] = srcIP16[i] ^ cookieBytes[i]
		}
		for i := 0; i < 12; i++ {
			xorIP[4+i] = srcIP16[4+i] ^ req.Transaction[i]
		}
	}

	xorPort = uint16(srcAddr.Port) ^ uint16(MagicCookie>>16)

	// Build XOR-MAPPED-ADDRESS attribute (RFC 8489 Section 14.2).
	xorAttrLen := 4 + len(xorIP) // 1+1+2 + IP
	xorAttr := make([]byte, xorAttrLen)
	xorAttr[0] = 0 // reserved
	xorAttr[1] = family
	binary.BigEndian.PutUint16(xorAttr[2:4], xorPort)
	copy(xorAttr[4:], xorIP)

	// Build SOFTWARE attribute.
	swBytes := []byte(ServerName)
	swLen := len(swBytes)
	// Pad to 4-byte boundary.
	swPadded := make([]byte, swLen+(4-swLen%4)%4)
	copy(swPadded, swBytes)

	// Calculate total message length (without FINGERPRINT for now).
	bodyLen := 4 + len(xorAttr) + 4 + len(swPadded)
	// Add FINGERPRINT attribute (8 bytes: 4 type/len + 4 CRC32).
	bodyLen += 8

	// Total message = header + body.
	totalLen := HeaderSize + bodyLen
	buf := make([]byte, totalLen)

	// Header.
	binary.BigEndian.PutUint16(buf[0:2], msgTypeBindingResponse)
	binary.BigEndian.PutUint16(buf[2:4], uint16(bodyLen))
	binary.BigEndian.PutUint32(buf[4:8], MagicCookie)
	copy(buf[8:20], req.Transaction[:])

	// XOR-MAPPED-ADDRESS attribute.
	offset := HeaderSize
	binary.BigEndian.PutUint16(buf[offset:offset+2], attrTypeXORMappedAddress)
	binary.BigEndian.PutUint16(buf[offset+2:offset+4], uint16(len(xorAttr)))
	copy(buf[offset+4:], xorAttr)
	offset += 4 + len(xorAttr)

	// SOFTWARE attribute.
	binary.BigEndian.PutUint16(buf[offset:offset+2], attrTypeSoftware)
	binary.BigEndian.PutUint16(buf[offset+2:offset+4], uint16(len(swPadded)))
	copy(buf[offset+4:], swPadded)
	offset += 4 + len(swPadded)

	// FINGERPRINT attribute (CRC32 of everything before it, XOR'd with
	// 0x5354554e per RFC 8489 Section 14.7).
	binary.BigEndian.PutUint16(buf[offset:offset+2], attrTypeFingerprint)
	binary.BigEndian.PutUint16(buf[offset+2:offset+4], 4)
	crc := crc32Checksum(buf[:offset])
	binary.BigEndian.PutUint32(buf[offset+4:offset+8], crc^0x5354554e)

	return buf, nil
}

// crc32Checksum computes CRC-32 (ISO 3309 / ITU-T V.42) without the
// standard library's hash/crc32 to keep the implementation self-contained.
func crc32Checksum(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc ^= uint32(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
	}
	return crc ^ 0xFFFFFFFF
}

// ValidateFingerprint checks the FINGERPRINT attribute if present.
func ValidateFingerprint(data []byte) bool {
	if len(data) < HeaderSize {
		return false
	}
	msgLen := binary.BigEndian.Uint16(data[2:4])
	msgEnd := HeaderSize + int(msgLen)
	if msgEnd > len(data) {
		return false
	}
	// Scan attributes to find FINGERPRINT.
	offset := HeaderSize
	var fpOffset int
	found := false
	for offset+4 <= msgEnd {
		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		attrEnd := offset + 4 + attrLen
		if attrEnd > msgEnd {
			break
		}
		if attrType == attrTypeFingerprint && attrLen == 4 {
			fpOffset = offset
			found = true
			break
		}
		offset = attrEnd + (4-attrLen%4)%4
	}
	if !found {
		return true // No fingerprint to validate.
	}

	storedCRC := binary.BigEndian.Uint32(data[fpOffset+4 : fpOffset+8])
	computed := crc32Checksum(data[:fpOffset]) ^ 0x5354554e
	return storedCRC == computed
}

// String returns a human-readable dump of a Message (for debugging).
func (m *Message) String() string {
	return fmt.Sprintf("STUN{type=0x%04x, len=%d, txn=%x, attrs=%d}",
		m.Type, m.Length, m.Transaction, len(m.Attributes))
}
