package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// NoiseHandshake implements a simplified Noise_XX pattern for key exchange.
// This provides:
// 1. Mutual authentication (both parties prove identity)
// 2. Forward secrecy (ephemeral keys)
// 3. Identity hiding (identity keys encrypted after first message)
type NoiseHandshake struct {
	staticKey    [32]byte // long-term identity key
	ephemeralKey [32]byte // per-session ephemeral key
	remoteStatic [32]byte // remote party's identity key
	remoteEphemeral [32]byte
	handshakeHash [32]byte // chaining key
	initialized  bool
}

// NewNoiseHandshake creates a new Noise_XX handshake state.
func NewNoiseHandshake(staticKey [32]byte) *NoiseHandshake {
	h := &NoiseHandshake{
		staticKey: staticKey,
	}
	// Initialize handshake hash with protocol name
	protocolName := "Noise_XX_25519_ChaChaPoly_SHA256"
	h.handshakeHash = sha256.Sum256([]byte(protocolName))
	h.initialized = true
	return h
}

// WriteMessageA creates the first handshake message (-> e).
func (h *NoiseHandshake) WriteMessageA() ([]byte, error) {
	if !h.initialized {
		return nil, fmt.Errorf("handshake not initialized")
	}

	// Generate ephemeral key pair
	var err error
	if _, err = rand.Read(h.ephemeralKey[:]); err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}
	h.ephemeralKey[0] &= 248
	h.ephemeralKey[31] = (h.ephemeralKey[31] & 127) | 64

	var ephemeralPublic [32]byte
	curve25519.ScalarBaseMult(&ephemeralPublic, &h.ephemeralKey)

	// Mix ephemeral public key into handshake hash
	h.mixHash(ephemeralPublic[:])

	// Message: e
	msg := make([]byte, 32)
	copy(msg, ephemeralPublic[:])

	return msg, nil
}

// ReadMessageA processes the first handshake message and creates the second (-> e, ee, s, es).
func (h *NoiseHandshake) ReadMessageA(msg []byte) ([]byte, error) {
	if len(msg) < 32 {
		return nil, fmt.Errorf("message A too short")
	}

	// Read remote ephemeral key
	copy(h.remoteEphemeral[:], msg[:32])
	h.mixHash(h.remoteEphemeral[:])

	// Generate our ephemeral key
	if _, err := rand.Read(h.ephemeralKey[:]); err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}
	h.ephemeralKey[0] &= 248
	h.ephemeralKey[31] = (h.ephemeralKey[31] & 127) | 64

	var ephemeralPublic [32]byte
	curve25519.ScalarBaseMult(&ephemeralPublic, &h.ephemeralKey)

	// ee: DH(ephemeral, remote_ephemeral)
	sharedEE, err := curve25519.X25519(h.ephemeralKey[:], h.remoteEphemeral[:])
	if err != nil {
		return nil, fmt.Errorf("DH ee: %w", err)
	}
	h.mixKey(sharedEE)

	// Encrypt static key (s)
	cipher, err := chacha20poly1305.New(h.handshakeHash[:])
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	var staticPublic [32]byte
	curve25519.ScalarBaseMult(&staticPublic, &h.staticKey)

	encryptedStatic := cipher.Seal(nil, make([]byte, 12), staticPublic[:], nil)
	h.mixHash(encryptedStatic)

	// es: DH(static, remote_ephemeral)
	sharedES, err := curve25519.X25519(h.staticKey[:], h.remoteEphemeral[:])
	if err != nil {
		return nil, fmt.Errorf("DH es: %w", err)
	}
	h.mixKey(sharedES)

	// Build message: e, ee, s, es
	response := make([]byte, 0, 32+len(encryptedStatic))
	response = append(response, ephemeralPublic[:]...)
	response = append(response, encryptedStatic...)

	return response, nil
}

// ReadMessageB processes the second handshake message and extracts the remote identity.
func (h *NoiseHandshake) ReadMessageB(msg []byte) error {
	if len(msg) < 64 {
		return fmt.Errorf("message B too short")
	}

	// Read remote ephemeral
	copy(h.remoteEphemeral[:], msg[:32])
	h.mixHash(h.remoteEphemeral[:])

	// ee: DH(ephemeral, remote_ephemeral)
	sharedEE, err := curve25519.X25519(h.ephemeralKey[:], h.remoteEphemeral[:])
	if err != nil {
		return fmt.Errorf("DH ee: %w", err)
	}
	h.mixKey(sharedEE)

	// Decrypt remote static key
	cipher, err := chacha20poly1305.New(h.handshakeHash[:])
	if err != nil {
		return fmt.Errorf("creating cipher: %w", err)
	}

	encryptedStatic := msg[32:]
	staticBytes, err := cipher.Open(nil, make([]byte, 12), encryptedStatic, nil)
	if err != nil {
		return fmt.Errorf("decrypting static key: %w", err)
	}
	h.mixHash(encryptedStatic)

	copy(h.remoteStatic[:], staticBytes[:32])

	// es: DH(ephemeral, remote_static)
	sharedES, err := curve25519.X25519(h.ephemeralKey[:], h.remoteStatic[:])
	if err != nil {
		return fmt.Errorf("DH es: %w", err)
	}
	h.mixKey(sharedES)

	slog.Info("Noise handshake completed", "remote_key", base64.StdEncoding.EncodeToString(h.remoteStatic[:]))
	return nil
}

// GetRemoteStatic returns the remote party's identity key (valid after handshake).
func (h *NoiseHandshake) GetRemoteStatic() [32]byte {
	return h.remoteStatic
}

// GetSessionKey derives a symmetric session key from the handshake state.
func (h *NoiseHandshake) GetSessionKey() [32]byte {
	return h.handshakeHash
}

func (h *NoiseHandshake) mixHash(data []byte) {
	hh := sha256.New()
	hh.Write(h.handshakeHash[:])
	hh.Write(data)
	copy(h.handshakeHash[:], hh.Sum(nil))
}

func (h *NoiseHandshake) mixKey(input []byte) {
	hh := sha256.New()
	hh.Write(h.handshakeHash[:])
	hh.Write(input)
	copy(h.handshakeHash[:], hh.Sum(nil))
}

// Encrypt encrypts data using the session key (ChaCha20-Poly1305).
func Encrypt(key [32]byte, plaintext []byte) ([]byte, error) {
	cipher, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext := cipher.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using the session key (ChaCha20-Poly1305).
func Decrypt(key [32]byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 12 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	cipher, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	nonce := ciphertext[:12]
	plaintext, err := cipher.Open(nil, nonce, ciphertext[12:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}
