package kekcrypt

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/d4c5d1e0/kekcrypt/internal/crypto"
)

type Encrypter struct {
	header      *FileHeader
	key         *crypto.DerivedKey
	nonce, salt []byte
	path        string
	wr          *crypto.StreamWriter
	f           *os.File
	out         *os.File
	fSize       int64
	written     uint64
}

// NewEncrypter accept the target file path, the derived key and the salt returns
// a new Encrypter instance necessary to encrypt the file
func NewEncrypter(path string, key *crypto.DerivedKey, salt []byte) *Encrypter {
	nonce := crypto.RandomBytes(NonceSize)
	return &Encrypter{
		path:  path,
		key:   key,
		salt:  salt,
		nonce: nonce,
		header: &FileHeader{
			Salt:  salt,
			Nonce: nonce,
		},
	}
}

func (e *Encrypter) Encrypt(out string) error {
	var err error

	e.f, err = os.Open(e.path)
	if err != nil {
		return fmt.Errorf("encrypter: open: %w", err)
	}
	defer e.f.Close()

	if out == "" {
		out = e.path + ".kek"
	}

	e.out, err = os.OpenFile(out, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return fmt.Errorf("encrypter: open: %w", err)
	}
	defer e.out.Close()

	e.wr, err = crypto.NewEncryptStreamWriter(e.key, e.nonce, e.out)
	if err != nil {
		return fmt.Errorf("encrypter: writer: %w", err)
	}

	_, rawFile := filepath.Split(e.path)

	e.header.EncodedFilename, err = EncryptFilename(e.key.Filename, rawFile)
	if err != nil {
		return fmt.Errorf("encrypter: filename encrypt: %w", err)
	}

	err = e.process()
	if err != nil {
		return fmt.Errorf("encrypter: process: %w", err)
	}

	return nil
}

func (e *Encrypter) process() error {
	header := e.header.MarshalBinary()
	// write to file
	e.out.Write(header)
	// update mac
	e.wr.H.Write(header)

	_, err := io.Copy(e.wr, e.f)
	if err != nil && err != io.EOF {
		return err
	}

	e.out.Write(e.wr.Sum())
	return nil
}
