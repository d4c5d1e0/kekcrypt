package kekcrypt

import (
	"crypto/hmac"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/d4c5d1e0/kekcrypt/internal/crypto"
)

type Decrypter struct {
	fPath   string
	f       *os.File
	str     *crypto.StreamReader
	key     *crypto.DerivedKey
	nonce   []byte
	hmacPos int64
	header  *FileHeader
	out     *os.File
}

func NewDecrypter(path string, key *crypto.DerivedKey, header *FileHeader) *Decrypter {
	return &Decrypter{
		fPath:  path,
		key:    key,
		nonce:  header.Nonce,
		header: header,
	}
}

func (d *Decrypter) Decrypt(out string) error {
	var err error
	d.f, err = os.Open(d.fPath)
	if err != nil {
		return fmt.Errorf("hmac: open: %w", err)
	}
	defer d.f.Close()
	// validate authenticity of data
	err = d.updateMac()
	if err != nil {
		return fmt.Errorf("kekcrypt: decrypt: %w", err)
	}

	defaultName, err := DecryptFilename(d.key.Filename, d.header.EncodedFilename)
	if err != nil {
		return fmt.Errorf("kekcrypt: decrypt: filename: %w", err)
	}

	if len(out) == 0 {
		dir, _ := filepath.Split(d.fPath)
		out = filepath.Join(dir, defaultName)
	}

	d.out, err = os.OpenFile(out, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return fmt.Errorf("kekcrypt: decrypt: %w", err)
	}
	defer d.out.Close()

	d.str, err = crypto.NewDecryptStreamReader(d.key, d.nonce, d.f)
	if err != nil {
		return fmt.Errorf("kekcrypt: reader: %w", err)
	}

	err = d.process()
	if err != nil {
		return fmt.Errorf("kekcrypt: process: %w", err)
	}

	return nil
}

func (d *Decrypter) process() error {
	// retarget reader
	_, err := d.f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	// skip fileHeader
	trash := make([]byte, d.header.totalSize)
	_, err = d.f.Read(trash)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	_, err = io.CopyN(d.out, d.str, d.hmacPos-int64(d.header.totalSize))
	if err != nil && err != io.EOF {
		return fmt.Errorf("copy: %w", err)
	}

	return nil
}

func (d *Decrypter) updateMac() error {
	var err error

	h := hmac.New(HMacFunc, d.key.Mac)

	sig := make([]byte, HMacSize)
	d.hmacPos, err = d.f.Seek(-HMacSize, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("hmac: %w", err)
	}
	// read the last 64 bytes
	_, err = io.ReadFull(d.f, sig)
	if err != nil {
		return fmt.Errorf("hmac: readfull: %w", err)
	}
	// retarget the reader
	_, err = d.f.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("hmac: seek: %w", err)
	}
	// flush all our file to our hmac
	_, err = io.CopyN(h, d.f, d.hmacPos)
	if err != nil {
		return fmt.Errorf("hmac: copy: %w", err)
	}

	if !hmac.Equal(h.Sum(nil), sig) {
		return ErrBadAuthentication
	}

	return nil
}
