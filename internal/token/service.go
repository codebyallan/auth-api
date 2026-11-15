package token

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"time"

	"github.com/codebyallan/auth-api/internal/common"
	"github.com/golang-jwt/jwt/v5"
)

var ()

type TokenService struct {
	tokenConfig TokenConfig
	privateKey  *rsa.PrivateKey
}

func NewTokenService(tokenConfig TokenConfig, privateKey *rsa.PrivateKey) (*TokenService, error) {
	if privateKey == nil {
		return nil, common.ErrNilPrivateKey
	}
	if tokenConfig.Issuer == "" {
		return nil, common.ErrMissingIssuer
	}
	if tokenConfig.Audience == "" {
		return nil, common.ErrMissingAudience
	}
	if tokenConfig.KeyID == "" {
		return nil, common.ErrMissingKeyID
	}
	if tokenConfig.AccessTokenTTL <= 0 {
		return nil, common.ErrInvalidTTL
	}
	return &TokenService{tokenConfig: tokenConfig, privateKey: privateKey}, nil
}

func (ts *TokenService) GenerateAccessToken(userID, email string) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(ts.tokenConfig.AccessTokenTTL)

	claims := accessClaims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ts.tokenConfig.Issuer,
			Audience:  jwt.ClaimStrings{ts.tokenConfig.Audience},
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = ts.tokenConfig.KeyID

	signed, err := token.SignedString(ts.privateKey)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

func (ts *TokenService) JWKS() JWKS {
	pub := &ts.privateKey.PublicKey
	return JWKS{Keys: []JWK{{
		Kty: "RSA",
		Kid: ts.tokenConfig.KeyID,
		Alg: "RS256",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
}
