package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/gob"
	"io"

	"github.com/minio/sio"
	"golang.org/x/crypto/sha3"
)

// Encrypter can encrypt data with RSA public key
type Encrypter struct {
	PublicKey *rsa.PublicKey
	Config    *Config
}

// NewEncrypter create a new encrypter
func NewEncrypter(publicKey []byte, config *Config) (*Encrypter, error) {
	enc := &Encrypter{
		PublicKey: &rsa.PublicKey{},
		Config: &Config{
			HashFunc:     sha3.New512,
			Random:       rand.Reader,
			CipherSuites: []byte{AES256GCM},
		},
	}

	if err := gob.NewDecoder(bytes.NewReader(publicKey)).Decode(enc.PublicKey); err != nil {
		return nil, err
	}

	if config != nil {
		if config.HashFunc != nil {
			enc.Config.HashFunc = config.HashFunc
		}
		if config.Random != nil {
			enc.Config.Random = config.Random
		}
		if config.CipherSuites != nil {
			enc.Config.CipherSuites = config.CipherSuites
		}
	}

	return enc, nil
}

// EncryptData will Encrypt data from certain data format
func (enc *Encrypter) EncryptData(dataReader io.Reader) (*bytes.Buffer, error) {
	encryptKey, dataBuffer := make([]byte, 32), bytes.NewBuffer([]byte{})

	if _, err := io.ReadFull(enc.Config.Random, encryptKey); err != nil {
		return nil, err
	} else if encryptedKey, err := rsa.EncryptOAEP(enc.Config.HashFunc(), enc.Config.Random, enc.PublicKey, encryptKey, []byte("id")); err != nil {
		return nil, err
	} else if _, err := dataBuffer.Write(encryptedKey); err != nil {
		return nil, err
	} else if _, err := sio.Encrypt(
		dataBuffer,
		dataReader,
		sio.Config{
			MinVersion:   sio.Version20,
			MaxVersion:   sio.Version20,
			CipherSuites: enc.Config.CipherSuites,
			Key:          encryptKey,
		},
	); err != nil {
		return nil, err
	}

	return dataBuffer, nil
}
