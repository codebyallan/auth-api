package auth

import "time"

type RefreshToken struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	FamilyID  string     `json:"family_id"`
	TokenHash string     `json:"-"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	CreatedAt time.Time  `json:"created_at"`
}
