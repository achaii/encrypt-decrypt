package main

import (
	"fmt"
	"github.com/achaii/encrypt-decrypt/internal"
)

func main() {
	//32 karakter
	enkripsi := []byte("abcdefghijklmnopqrstupwxyz123456")
	auntetikasi := []byte("654321zyxwputsrqponmlkjihgfedcba")

	//Memasukan nilai enkripsi dan auntetikasi pada fungsi NewEncrypter
	encrypter, err := internal.NewEncrypter(enkripsi, auntetikasi)
	if err != nil {
		fmt.Println(err)
		return
	}

	//Memasukan tulisan untuk di enkripsi
	text := []byte("Jennaira De Rafaella")
	encrypted, err := encrypter.Encrypt(text)
	if err != nil {
		fmt.Println("Enkripsi error:", err)
		return
	}

	fmt.Println("Hasil enkripsi:", encrypted)

	//Mengembalikan tulisan yang sudan di enkripsi ke normal
	decrypted, err := encrypter.Decrypt(encrypted)
	if err != nil {
		fmt.Println("Dekripsi error:", err)
		return
	}

	fmt.Println("Hasil dekripsi:", string(decrypted))
}
