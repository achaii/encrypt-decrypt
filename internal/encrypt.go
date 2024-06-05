package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// Fungsi untuk membuat instance baru 
func NewEncrypter(enkripsi, auntetikasi []byte) (*Encrypter, error) {
	if len(enkripsi) > 32 {
		return nil, errors.New("enkripsi tidak valid, panjang enkripsi melebihi 32 karakter")
	}

	if auntetikasi == nil {
		auntetikasi = enkripsi
	} else if len(auntetikasi) > 32 {
		return nil, errors.New("autentikasi tidak valid, panjang autentikasi melebihi 32 karakter")
	}

	return &Encrypter{enkripsi: enkripsi, auntetikasi: auntetikasi}, nil
}

// Fungsi untuk mengenkripsikan value
func (e *Encrypter) Encrypt(value []byte) (string, error) {
	intValue := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, intValue); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(e.enkripsi)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(value))
	stream := cipher.NewCFBEncrypter(block, intValue)
	stream.XORKeyStream(ciphertext, value)

	hmac := e.hash(append(intValue, ciphertext...))
	result := append(intValue, hmac...)
	result = append(result, ciphertext...)

	return base64.StdEncoding.EncodeToString(result), nil
}