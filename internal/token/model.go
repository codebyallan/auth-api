package token

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenConfig struct {
	Issuer          string
	Audience        string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	KeyID           string
}
type accessClaims struct {
	UserID string `json:"uid"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}
