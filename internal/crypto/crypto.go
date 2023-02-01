package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

type DerivedKey struct {
	// 256-bit key
	Mac []byte
	// 256-bit key
	Chacha []byte
	// 128-bit key
	Filename []byte
}

// DeriveKey derives a key from the password and salt using argon2id function, it returns
// a DerivedKey struct which contains the main encryption key, the hmac key and filename key
func DeriveKey(password, salt []byte) *DerivedKey {
	// 256 bits for chacha20, 256 bits for hmac and 128 bits for AES-GCM to encrypt the filenames
	keyLen := 32 + 32 + 16
	k := argon2.IDKey(password, salt, 8, 256*1024, 4, uint32(keyLen))
	return &DerivedKey{
		Mac:      k[:32],
		Chacha:   k[32 : keyLen-16],
		Filename: k[keyLen-16:],
	}
}

func RandomBytes(len int) []byte {
	buf := make([]byte, len)
	_, err := rand.Read(buf)
	if err != nil {
		panic("out of randomness: " + err.Error())
	}
	return buf
}
