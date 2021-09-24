package block_cipher

import (
	"bytes"
	"crypto/cipher"
	"io"
	"sync"
)

type Decrypter struct {
	BlockMode cipher.BlockMode
	r         io.Reader
	mu        sync.Mutex
	drained   bool
	b         bytes.Buffer
	Padding   Padding
}

func (e *Decrypter) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	var block = make([]byte, e.BlockMode.BlockSize())
	// need a extra block to handle EOF, so use `<=`` not `<``.
	for !e.drained && e.b.Len() <= len(p) {
		var read int
		read, err = io.ReadFull(e.r, block)
		n += read
		if err == io.EOF {
			e.drained = true
			var b []byte
			b, err = e.Padding.Remove(e.b.Bytes())
			if err != nil {
				return
			}
			e.b = *bytes.NewBuffer(b)
			break
		} else if err != nil {
			return
		}
		e.BlockMode.CryptBlocks(block, block)
		_, err = e.b.Write(block)
		if err != nil {
			return
		}
	}

	return e.b.Read(p)
}

var _ io.Reader = (*Decrypter)(nil)

func NewDecrypter(r io.Reader, blockMode cipher.BlockMode, padding Padding) *Decrypter {
	return &Decrypter{
		BlockMode: blockMode,
		r:         r,
		Padding:   padding,
	}
}
