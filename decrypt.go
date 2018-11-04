package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/gob"
	"io"
	"io/ioutil"

	"github.com/minio/sio"
	"golang.org/x/crypto/sha3"
)

// Decrypter can decrypt data with RSA private key
type Decrypter struct {
	PrivateKey *rsa.PrivateKey
	Config     *Config
}

// NewDecrypter create a new decrypter
func NewDecrypter(privateKey []byte, config *Config) (*Decrypter, error) {
	dec := &Decrypter{
		PrivateKey: &rsa.PrivateKey{},
		Config: &Config{
			HashFunc:     sha3.New512,
			Random:       rand.Reader,
			CipherSuites: []byte{AES256GCM},
		},
	}

	if err := gob.NewDecoder(bytes.NewReader(privateKey)).Decode(dec.PrivateKey); err != nil {
		return nil, err
	}

	if config != nil {
		if config.HashFunc != nil {
			dec.Config.HashFunc = config.HashFunc
		}
		if config.Random != nil {
			dec.Config.Random = config.Random
		}
		if config.CipherSuites != nil {
			dec.Config.CipherSuites = config.CipherSuites
		}
	}

	return dec, nil
}

// DecryptData will decrypt data from certain data format
func (dec *Decrypter) DecryptData(dataReader io.Reader) (*bytes.Buffer, error) {
	dataBuffer := bytes.NewBuffer([]byte{})

	if dataByte, err := ioutil.ReadAll(dataReader); err != nil {
		return nil, err
	} else if decryptKey, err := rsa.DecryptOAEP(
		dec.Config.HashFunc(),
		dec.Config.Random,
		dec.PrivateKey,
		dataByte[:dec.PrivateKey.Size()],
		[]byte("id"),
	); err != nil {
		return nil, err
	} else if _, err := sio.Decrypt(
		dataBuffer,
		bytes.NewBuffer(dataByte[dec.PrivateKey.Size():]),
		sio.Config{
			MinVersion:   sio.Version20,
			MaxVersion:   sio.Version20,
			CipherSuites: dec.Config.CipherSuites,
			Key:          decryptKey,
		},
	); err != nil {
		return nil, err
	}

	return dataBuffer, nil
}
