package block_cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"testing"
)

func ExampleNewEncrypter() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte("exampleplaintext")

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	var b = new(bytes.Buffer)
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	_, err = b.Write(iv)
	if err != nil {
		panic(err)
	}
	var encrypter = NewEncrypter(
		b,
		mode,
		PKCS7Padding{BlockSize: mode.BlockSize()},
	)

	_, err = encrypter.Write(plaintext)
	if err != nil {
		panic(err)
	}
	// Apply padding
	err = encrypter.Close()
	if err != nil {
		panic(err)
	}

	var ciphertext = b.String()
	fmt.Printf("%x\n", ciphertext)
}

func ExampleNewDecrypter() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	ciphertext, _ := hex.DecodeString("e941c68ffb6923cb18b443ace9f2c9a8dcc211878499f30e6cedc2976861d324da501e9ec759a9f18f7e3ad99df885de")
	var r = bytes.NewBuffer(ciphertext)

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if r.Len() < aes.BlockSize {
		panic("ciphertext too short")
	}
	// iv := ciphertext[:aes.BlockSize]
	// ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if r.Len()%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// iv not important because we will just discard first block
	var iv = make([]byte, 16)
	mode := cipher.NewCBCDecrypter(block, iv)
	var decrypter = NewDecrypter(
		r,
		mode,
		PKCS7Padding{BlockSize: mode.BlockSize()},
	)

	// Discard first block
	_, err = io.ReadFull(decrypter, iv)
	if err != nil {
		return
	}

	plaintext, err := ioutil.ReadAll(decrypter)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", plaintext)
	if string(plaintext) != "exampleplaintext" {
		panic("wrong decrypt result")
	}
}

func TestExample(t *testing.T) {
	ExampleNewEncrypter()
	ExampleNewDecrypter()
}
