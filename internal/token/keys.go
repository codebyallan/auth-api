package token

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/codebyallan/auth-api/internal/common"
)

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	if path == "" {
		return nil, common.ErrMissingKeyPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, common.ErrInvalidPrivateKey
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, common.ErrInvalidPrivateKey
	}
	return key, nil
}
