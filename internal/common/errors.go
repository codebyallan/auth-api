package common

import "errors"

var (
	ErrNotFound           = errors.New("not found")
	ErrEmailInvalid       = errors.New("email invalid")
	ErrEmailInUse         = errors.New("email is already in use")
	ErrPasswordTooShort   = errors.New("password must have at least 8 characters")
	ErrPasswordTooLong    = errors.New("password must have at most 72 bytes")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrNilPrivateKey      = errors.New("private key is required")
	ErrInvalidTTL         = errors.New("access token TTL must be greater than zero")
	ErrMissingIssuer      = errors.New("issuer is required")
	ErrMissingAudience    = errors.New("audience is required")
	ErrMissingKeyID       = errors.New("key id is required")
)
