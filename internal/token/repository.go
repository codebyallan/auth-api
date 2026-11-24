package token

import "time"

type TokenRepository interface {
	GenerateAccessToken(userID, email string) (string, time.Time, error)
	GenerateRefreshToken() (string, error)
	GetRefreshTokenTTL() time.Duration
}
