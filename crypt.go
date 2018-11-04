package crypt

import (
	"hash"
	"io"
)

// Config contains configurations of crypt
type Config struct {
	HashFunc     func() hash.Hash
	Random       io.Reader
	CipherSuites []byte
}

const (
	// AES256GCM specifies the cipher suite AES-GCM with 256 bit keys.
	AES256GCM byte = iota
	// CHACHA20POLY1305 specifies the cipher suite ChaCha20Poly1305 with 256 bit keys.
	CHACHA20POLY1305
)
