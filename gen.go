package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/gob"
	"fmt"
)

// PrintKeyPair in gob encoding
func PrintKeyPair(bits int) {
	b := bytes.NewBuffer([]byte{})

	key, _ := rsa.GenerateKey(rand.Reader, bits)

	gob.NewEncoder(b).Encode(key)
	fmt.Println("Private:")
	printByte(b.Bytes(), 64)

	b.Reset()

	gob.NewEncoder(b).Encode(key.PublicKey)
	fmt.Println("\n\n\nPublic:")
	printByte(b.Bytes(), 64)
}

func printByte(bytes []byte, width int) {
	for i, val := range bytes {
		if i%width == 0 && i > 0 {
			fmt.Print("\n")
		}
		fmt.Printf("%0#2x, ", val)
	}
	fmt.Print("\n")
}
