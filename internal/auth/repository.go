package auth

import (
	"context"
	"time"
)

type RefreshTokenRepository interface {
	CreateRefreshToken(ctx context.Context, refreshToken *RefreshToken) error
	FindByTokenHash(ctx context.Context, refreshTokenHash string) (RefreshToken, error)
	ClaimRefreshToken(ctx context.Context, hash string, now time.Time) (RefreshToken, error)
	RevokeFamily(ctx context.Context, refreshTokenFamily string) error
}
