package crypto_test

import (
	"testing"

	"github.com/d4c5d1e0/kekcrypt"
	"github.com/d4c5d1e0/kekcrypt/internal/crypto"
	"github.com/stretchr/testify/assert"
)

func TestDeriveKey(t *testing.T) {
	password := crypto.RandomBytes(5)
	salt := crypto.RandomBytes(kekcrypt.SaltSize)

	key := crypto.DeriveKey(password, salt)

	assert.Equal(t, len(key.Chacha), 32)
	assert.Equal(t, len(key.Mac), 32)
	assert.Equal(t, len(key.Filename), 16)
}
