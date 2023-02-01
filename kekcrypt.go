package kekcrypt

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/chacha20"

	"github.com/d4c5d1e0/kekcrypt/internal/crypto"
)

const (
	NonceSize = chacha20.NonceSizeX
	SaltSize  = 16
	HMacSize  = sha512.Size
)

var (
	HMacFunc             = sha512.New
	ErrBadAuthentication = errors.New("wrong mac signature")
)

type FileHeader struct {
	EncodedFilename []byte
	Salt            []byte
	Nonce           []byte
	totalSize       uint16
}

func EncryptFilename(key []byte, filename string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("kekcrypt: filename: %w", err)
	}

	c, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kekcrypt: gcm: %w", err)
	}

	plaintext := []byte(filename)
	nonce := crypto.RandomBytes(c.NonceSize())

	dst := c.Seal(nil, nonce, plaintext, nil)
	dst = append(dst, nonce...)

	return dst, nil
}

func DecryptFilename(key, filename []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("kekcrypt: filename: %w", err)
	}

	c, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("kekcrypt: gcm: %w", err)
	}

	offset := len(filename) - c.NonceSize()
	ciphertext, nonce := filename[0:offset], filename[offset:]

	dst, err := c.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("kekcrypt: open: %w", err)
	}

	return string(dst), nil
}

// MarshalBinary encodes to the following
//	+------------------------------------------------------------+
//	| totalSize | len(filename) | encodedFilename | nonce | salt |
//	+------------------------------------------------------------+
func (f *FileHeader) MarshalBinary() []byte {
	totalSize := SaltSize +
		NonceSize +
		len(f.EncodedFilename) +
		4 // 2 for the totalSize len and 2 for the filename len

	var buf bytes.Buffer
	buf.Grow(totalSize)

	sizes := make([]byte, 4)
	binary.BigEndian.PutUint16(sizes[:2], uint16(totalSize))
	binary.BigEndian.PutUint16(sizes[2:], uint16(len(f.EncodedFilename)))

	buf.Write(sizes)
	buf.Write(f.EncodedFilename)
	buf.Write(f.Nonce)
	buf.Write(f.Salt)

	return buf.Bytes()
}

func ParseHeader(f string) (*FileHeader, error) {
	file, err := os.Open(f)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	val, err := reader.Peek(2)
	if err != nil {
		return nil, err
	}

	totalSize := binary.BigEndian.Uint16(val)

	buf := make([]byte, totalSize)
	_, err = reader.Read(buf)
	if err != nil {
		return nil, err
	}

	filenameLen := binary.BigEndian.Uint16(buf[2:4])
	filename := buf[4 : filenameLen+4]
	secret := buf[len(buf)-(SaltSize+NonceSize):]

	return &FileHeader{
		EncodedFilename: filename,
		Salt:            secret[NonceSize:],
		Nonce:           secret[:NonceSize],
		totalSize:       totalSize,
	}, nil
}
