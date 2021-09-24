package block_cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
)

func ExampleNewEncrypter() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	// input is not required to be multiple of block size
	plaintext := []byte("exampleplaintext1")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// use fixed iv to generate fixed output.
	iv := make([]byte, aes.BlockSize)
	// for real code, it should be random generated like this:
	//
	// if _, err := io.ReadFull(rand.Reader, iv); err != nil {
	// 	panic(err)
	// }

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
	// Output:
	// 00000000000000000000000000000000f42512e1e4039213bd449ba47faa1b7462f03fa1e07038731853874f62af9c4b
}

func ExampleNewDecrypter() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	ciphertext, _ := hex.DecodeString("00000000000000000000000000000000f42512e1e4039213bd449ba47faa1b7462f03fa1e07038731853874f62af9c4b")
	var r = bytes.NewBuffer(ciphertext)

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if r.Len() < aes.BlockSize {
		panic("ciphertext too short")
	}

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
	// Output:
	// exampleplaintext1
}
