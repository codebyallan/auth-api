package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/codebyallan/auth-api/internal/common"
	"github.com/codebyallan/auth-api/internal/token"
	"github.com/codebyallan/auth-api/internal/user"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	userRepository         user.UserRepository
	refreshTokenRepository RefreshTokenRepository
	tokenService           *token.TokenService
}

func NewAuthService(userRepository user.UserRepository, refreshTokenRepository RefreshTokenRepository, tokenService *token.TokenService) *AuthService {
	return &AuthService{userRepository: userRepository, refreshTokenRepository: refreshTokenRepository, tokenService: tokenService}
}

func (as *AuthService) Register(ctx context.Context, request RegisterRequest) (AuthResponse, error) {
	email, err := normalizeEmail(request.Email)
	if err != nil {
		return AuthResponse{}, err
	}

	if err := validatePassword(request.Password); err != nil {
		return AuthResponse{}, err
	}

	_, err = as.userRepository.FindByEmail(ctx, email)
	switch {
	case err == nil:
		return AuthResponse{}, common.ErrEmailInUse
	case errors.Is(err, common.ErrNotFound):
	default:
		return AuthResponse{}, fmt.Errorf("find user by email: %w", err)
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("hash password: %w", err)
	}

	newUser := user.User{
		ID:           uuid.New().String(),
		Email:        email,
		PasswordHash: string(passwordHash),
		CreatedAt:    time.Now().UTC(),
	}
	if err := as.userRepository.Create(ctx, &newUser); err != nil {
		return AuthResponse{}, fmt.Errorf("create user: %w", err)
	}
	return as.issueSession(ctx, newUser.ID, email, nil)
}

func (as *AuthService) Login(ctx context.Context, request LoginRequest) (AuthResponse, error) {
	email, err := normalizeEmail(request.Email)
	if err != nil {
		return AuthResponse{}, common.ErrInvalidCredentials
	}

	foundUser, err := as.userRepository.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, common.ErrNotFound) {
			return AuthResponse{}, common.ErrInvalidCredentials
		}
		return AuthResponse{}, fmt.Errorf("find user by email: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.PasswordHash), []byte(request.Password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return AuthResponse{}, common.ErrInvalidCredentials
		}
		return AuthResponse{}, fmt.Errorf("compare password: %w", err)
	}
	return as.issueSession(ctx, foundUser.ID, email, nil)
}

func (as *AuthService) Refresh(ctx context.Context, refreshToken string) (AuthResponse, error) {
	hash := token.HashRefreshToken(refreshToken)
	now := time.Now()

	claimed, err := as.refreshTokenRepository.ClaimRefreshToken(ctx, hash, now)
	switch {
	case err == nil:
	case errors.Is(err, common.ErrNotFound):
		stored, findErr := as.refreshTokenRepository.FindByTokenHash(ctx, hash)
		if findErr != nil {
			if errors.Is(findErr, common.ErrNotFound) {
				return AuthResponse{}, common.ErrInvalidRefreshToken
			}
			return AuthResponse{}, fmt.Errorf("find refresh token: %w", findErr)
		}
		if stored.RevokedAt != nil {
			if revokeErr := as.refreshTokenRepository.RevokeFamily(ctx, stored.FamilyID); revokeErr != nil {
				return AuthResponse{}, fmt.Errorf("revoke family refresh token: %w", revokeErr)
			}
		}
		return AuthResponse{}, common.ErrInvalidRefreshToken
	default:
		return AuthResponse{}, fmt.Errorf("claim refresh token: %w", err)
	}

	foundUser, err := as.userRepository.FindByID(ctx, claimed.UserID)
	if err != nil {
		if errors.Is(err, common.ErrNotFound) {
			return AuthResponse{}, common.ErrInvalidRefreshToken
		}
		return AuthResponse{}, fmt.Errorf("find user by id: %w", err)
	}

	return as.issueSession(ctx, foundUser.ID, foundUser.Email, &claimed.FamilyID)
}

func (as *AuthService) Logout(ctx context.Context, refreshToken string) error {
	hash := token.HashRefreshToken(refreshToken)

	stored, err := as.refreshTokenRepository.FindByTokenHash(ctx, hash)
	if err != nil {
		if errors.Is(err, common.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("find refresh token: %w", err)
	}

	if err := as.refreshTokenRepository.RevokeFamily(ctx, stored.FamilyID); err != nil {
		return fmt.Errorf("revoke family refresh token: %w", err)
	}
	return nil
}

func (as *AuthService) issueSession(ctx context.Context, userID, email string, existsFamilyID *string) (AuthResponse, error) {
	accessToken, accessExpiresAt, err := as.tokenService.GenerateAccessToken(userID, email)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("generate access token: %w", err)
	}

	rawToken, err := as.tokenService.GenerateRefreshToken()
	if err != nil {
		return AuthResponse{}, fmt.Errorf("generate refresh token: %w", err)
	}
	var familyID string
	if existsFamilyID == nil {
		familyID = uuid.New().String()
	} else {
		familyID = *existsFamilyID
	}
	now := time.Now().UTC()
	refreshToken := RefreshToken{
		ID:        uuid.New().String(),
		UserID:    userID,
		FamilyID:  familyID,
		TokenHash: token.HashRefreshToken(rawToken),
		ExpiresAt: now.Add(as.tokenService.GetRefreshTokenTTL()),
		CreatedAt: now,
	}
	if err := as.refreshTokenRepository.CreateRefreshToken(ctx, &refreshToken); err != nil {
		return AuthResponse{}, fmt.Errorf("create refresh token: %w", err)
	}

	return AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: rawToken,
		TokenType:    "Bearer",
		ExpiresAt:    accessExpiresAt.Unix(),
	}, nil
}

var emailPattern = regexp.MustCompile(`^[a-z0-9!#$%&'*+/=?^_{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

func normalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if len(email) > maxEmailLen || !emailPattern.MatchString(email) {
		return "", common.ErrEmailInvalid
	}
	if strings.IndexByte(email, '@') > maxLocalPartLen {
		return "", common.ErrEmailInvalid
	}
	return email, nil
}

func validatePassword(password string) error {
	if len(password) < minPasswordLen {
		return common.ErrPasswordTooShort
	}
	if len(password) > maxPasswordLen {
		return common.ErrPasswordTooLong
	}
	return nil
}
