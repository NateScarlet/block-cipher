package block_cipher

import (
	"bytes"
	"crypto/cipher"
	"io"
	"sync"
)

type Encrypter struct {
	BlockMode cipher.BlockMode
	Writer    io.Writer
	mu        sync.Mutex
	closed    bool
	b         bytes.Buffer
	Padding   Padding
}

func (e *Encrypter) flush() (n int, err error) {
	var size = e.BlockMode.BlockSize()
	var block = make([]byte, size)
	for e.b.Len() > size {
		_, err = e.b.Read(block)
		if err != nil {
			return
		}
		n += size
		e.BlockMode.CryptBlocks(block, block)
		_, err = e.Writer.Write(block)
		if err != nil {
			return
		}
	}
	return
}

func (e *Encrypter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		panic("block_cipher: (*Encrypter).Write: already closed")
	}

	n, err = e.b.Write(p)
	if err != nil {
		return
	}
	_, err = e.flush()
	if err != nil {
		return
	}
	return
}

func (e *Encrypter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var finalBlock, err = e.Padding.Add(e.b.Bytes())
	if err != nil {
		return err
	}
	e.BlockMode.CryptBlocks(finalBlock, finalBlock)
	_, err = e.Writer.Write(finalBlock)
	if err != nil {
		return err
	}

	e.closed = true
	return nil
}

var _ io.WriteCloser = (*Encrypter)(nil)

func NewEncrypter(w io.Writer, blockMode cipher.BlockMode, padding Padding) *Encrypter {
	return &Encrypter{
		BlockMode: blockMode,
		Writer:    w,
		Padding:   padding,
	}
}
