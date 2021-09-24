# block cipher

[![godev](https://img.shields.io/static/v1?label=godev&message=reference&color=00add8)](https://pkg.go.dev/github.com/NateScarlet/block-cipher/pkg)

Encrypt/Decrypt stream with a padded block algorithm (e.g. AES-CBC with PKCS7 padding)

Memory efficient, only need 2 block size buffer to decrypt and 1 block size buffer to encrypt.

`Encrypter` implements `io.WriteCloser`

`Decrypter` implements `io.Reader`

See go doc for AES-CBC example.
