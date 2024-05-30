package internal

import(
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Fungsi decrypt untuk mendekripsikan value
func (e *Encrypter) Decrypt(value string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}

	intvalue := data[:aes.BlockSize]
	hmac := data[aes.BlockSize : aes.BlockSize+32]
	ciphers := data[aes.BlockSize+32:]

	if e.hashEquals(hmac, e.hash(append(intvalue, ciphers...))) {
		return nil, errors.New("hash tidak cocok")
	}

	block, err := aes.NewCipher(e.enkripsi)
	if err != nil {
		return nil, err
	}

	text := make([]byte, len(ciphers))
	stream := cipher.NewCFBDecrypter(block, intvalue)
	stream.XORKeyStream(text, ciphers)

	return text, nil
}

// Fungsi hash untuk merubah value menjadi hash HMAC 
func (e *Encrypter) hash(value []byte) []byte {
	mac := hmac.New(sha256.New, e.auntetikasi)
	mac.Write(value)
	return mac.Sum(nil)
}

// Fungsi untuk membandingkan antara dua value hash
func (e *Encrypter) hashEquals(a, b []byte) bool {
	return hmac.Equal(a, b)
}