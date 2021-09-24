package block_cipher

import (
	"bytes"
	"fmt"
)

type Padding interface {
	Add(data []byte) ([]byte, error)
	Remove(data []byte) ([]byte, error)
}

type PKCS7Padding struct {
	BlockSize int
}

func (p PKCS7Padding) Add(data []byte) ([]byte, error) {
	var padding = p.BlockSize - (len(data) % p.BlockSize)
	return append(data, bytes.Repeat([]byte{byte(padding)}, padding)...), nil
}

func (p PKCS7Padding) Remove(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%p.BlockSize != 0 {
		return nil, fmt.Errorf("block_cipher: PKCS7Padding.Remove: invalid data")
	}

	var padding = int(data[len(data)-1])
	if padding > len(data) {
		return nil, fmt.Errorf("block_cipher: PKCS7Padding.Remove: padding too large: %d", padding)
	}
	for i := len(data) - padding; i < len(data); i++ {
		if int(data[i]) != padding {
			return nil, fmt.Errorf("block_cipher: PKCS7Padding.Remove: invalid padding char at index %d: %d", i, data[i])
		}
	}

	return data[:len(data)-padding], nil
}

var _ Padding = (*PKCS7Padding)(nil)
