package crypto

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20"
)

type StreamWriter struct {
	S   cipher.Stream
	W   io.Writer
	H   hash.Hash
	Err error // unused
}

// NewEncryptStreamWriter is a modified version of cipher.StreamWriter which support authentication.
// It accepts the derived key, the nonce and the target io.Writer, will return an error if it is unable
// to instantiate the underlying cipher
func NewEncryptStreamWriter(key *DerivedKey, nonce []byte, wr io.Writer) (*StreamWriter, error) {
	c, err := chacha20.NewUnauthenticatedCipher(key.Chacha, nonce)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	return &StreamWriter{S: c, W: wr, H: hmac.New(sha512.New, key.Mac)}, nil
}

// Write encrypt the given buffer to the underlying io.Writer and
// also making sure to update the hash state accordingly
func (w *StreamWriter) Write(src []byte) (n int, err error) {
	c := make([]byte, len(src))
	w.S.XORKeyStream(c, src)
	// update
	w.H.Write(c)
	n, err = w.W.Write(c)
	if n != len(src) && err == nil { // should never happen
		err = io.ErrShortWrite
	}
	return
}

// Sum returns the hmac digest
func (w *StreamWriter) Sum() []byte {
	return w.H.Sum(nil)
}

type StreamReader struct {
	S   cipher.Stream
	R   io.Reader
	Err error // unused
}

// NewDecryptStreamReader is a modified version of cipher.StreamReader which support authentication.
// It accepts the derived key, the nonce and the target io.Reader, will return an error if it is unable
// to instantiate the underlying cipher
func NewDecryptStreamReader(key *DerivedKey, nonce []byte, reader io.Reader) (*StreamReader, error) {
	c, err := chacha20.NewUnauthenticatedCipher(key.Chacha, nonce)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}

	return &StreamReader{S: c, R: reader}, nil
}

func (r *StreamReader) Read(dst []byte) (n int, err error) {
	n, err = r.R.Read(dst)
	r.S.XORKeyStream(dst[:n], dst[:n])
	return
}
