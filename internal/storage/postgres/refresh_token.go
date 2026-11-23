package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/codebyallan/auth-api/internal/auth"
	"github.com/codebyallan/auth-api/internal/common"
)

type RefreshTokenRepo struct {
	db *sql.DB
}

func NewRefreshTokenRepo(db *sql.DB) *RefreshTokenRepo {
	return &RefreshTokenRepo{db: db}
}

var _ auth.RefreshTokenRepository = (*RefreshTokenRepo)(nil)

func (r *RefreshTokenRepo) CreateRefreshToken(ctx context.Context, refreshToken *auth.RefreshToken) error {
	var revokedAt any
	if refreshToken.RevokedAt != nil {
		t := refreshToken.RevokedAt.UTC()
		revokedAt = t
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens (id, user_id, family_id, token_hash, expires_at, revoked_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		refreshToken.ID,
		refreshToken.UserID,
		refreshToken.FamilyID,
		refreshToken.TokenHash,
		refreshToken.ExpiresAt.UTC(),
		revokedAt,
		refreshToken.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	return nil
}

func (r *RefreshTokenRepo) FindByTokenHash(ctx context.Context, refreshTokenHash string) (auth.RefreshToken, error) {
	var refreshToken auth.RefreshToken
	err := r.db.QueryRowContext(ctx,
		`SELECT id, user_id, family_id, token_hash, expires_at, revoked_at, created_at
		 FROM refresh_tokens
		 WHERE token_hash = $1`,
		refreshTokenHash,
	).Scan(
		&refreshToken.ID,
		&refreshToken.UserID,
		&refreshToken.FamilyID,
		&refreshToken.TokenHash,
		&refreshToken.ExpiresAt,
		&refreshToken.RevokedAt,
		&refreshToken.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.RefreshToken{}, common.ErrNotFound
	}
	if err != nil {
		return auth.RefreshToken{}, fmt.Errorf("find refresh token by hash: %w", err)
	}
	return refreshToken, nil
}

func (r *RefreshTokenRepo) ClaimRefreshToken(ctx context.Context, tokenHash string, now time.Time) (auth.RefreshToken, error) {
	var refreshToken auth.RefreshToken
	err := r.db.QueryRowContext(ctx,
		`UPDATE refresh_tokens
		 SET revoked_at = $2
		 WHERE token_hash = $1
		   AND revoked_at IS NULL
		   AND expires_at > $2
		 RETURNING id, user_id, family_id, token_hash, expires_at, revoked_at, created_at`,
		tokenHash,
		now.UTC(),
	).Scan(
		&refreshToken.ID,
		&refreshToken.UserID,
		&refreshToken.FamilyID,
		&refreshToken.TokenHash,
		&refreshToken.ExpiresAt,
		&refreshToken.RevokedAt,
		&refreshToken.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.RefreshToken{}, common.ErrNotFound
	}
	if err != nil {
		return auth.RefreshToken{}, fmt.Errorf("claim refresh token: %w", err)
	}
	return refreshToken, nil
}

func (r *RefreshTokenRepo) RevokeFamily(ctx context.Context, refreshTokenFamily string, now time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE refresh_tokens
		 SET revoked_at = $1
		 WHERE family_id = $2
		   AND revoked_at IS NULL`,
		now.UTC(),
		refreshTokenFamily,
	)
	if err != nil {
		return fmt.Errorf("revoke refresh token family: %w", err)
	}
	return nil
}
