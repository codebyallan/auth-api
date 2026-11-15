package auth

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/codebyallan/auth-api/internal/common"
	"github.com/codebyallan/auth-api/internal/token"
	"github.com/codebyallan/auth-api/internal/user"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	userRepository user.UserRepository
	tokenService   *token.TokenService
}

func NewAuthService(userRepository user.UserRepository, tokenService *token.TokenService) *AuthService {
	return &AuthService{userRepository: userRepository, tokenService: tokenService}
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

	return as.authResponse(newUser.ID, email)
}

func (as *AuthService) Login(ctx context.Context, request LoginRequest) (AuthResponse, error) {
	email, err := normalizeEmail(request.Email)
	if err != nil {
		return AuthResponse{}, common.ErrInvalidCredentials
	}

	user, err := as.userRepository.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, common.ErrNotFound) {
			return AuthResponse{}, common.ErrInvalidCredentials
		}
		return AuthResponse{}, fmt.Errorf("find user by email: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return AuthResponse{}, common.ErrInvalidCredentials
		}
		return AuthResponse{}, fmt.Errorf("compare password: %w", err)
	}

	return as.authResponse(user.ID, user.Email)
}

func (as *AuthService) authResponse(userID string, email string) (AuthResponse, error) {
	accessToken, expiresAt, err := as.tokenService.GenerateAccessToken(userID, email)
	if err != nil {
		return AuthResponse{}, fmt.Errorf("generate token: %w", err)
	}
	return AuthResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresAt:   expiresAt.Unix(),
	}, nil
}

func normalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if _, err := mail.ParseAddress(email); err != nil {
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
