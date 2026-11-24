package auth

import (
	"errors"
	"log"
	"net/http"

	"github.com/codebyallan/auth-api/internal/common"
	"github.com/codebyallan/auth-api/internal/httpx"
)

type AuthHandler struct {
	authService *AuthService
}

func NewAuthHandler(authService *AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (ah *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	res, err := ah.authService.Register(r.Context(), req)
	if err != nil {
		status, message := statusFor(err)
		if status == http.StatusInternalServerError {
			log.Printf("register: %v", err)
		}
		httpx.WriteError(w, status, message)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, res)
}

func (ah *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	res, err := ah.authService.Login(r.Context(), req)
	if err != nil {
		status, message := statusFor(err)
		if status == http.StatusInternalServerError {
			log.Printf("login: %v", err)
		}
		httpx.WriteError(w, status, message)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (ah *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	res, err := ah.authService.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		status, message := statusFor(err)
		if status == http.StatusInternalServerError {
			log.Printf("refresh: %v", err)
		}
		httpx.WriteError(w, status, message)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (ah *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req LogoutRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	if err := ah.authService.Logout(r.Context(), req.RefreshToken); err != nil {
		status, message := statusFor(err)
		if status == http.StatusInternalServerError {
			log.Printf("logout: %v", err)
		}
		httpx.WriteError(w, status, message)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeDecodeError(w http.ResponseWriter, err error) {
	if errors.Is(err, httpx.ErrBodyTooLarge) {
		httpx.WriteError(w, http.StatusRequestEntityTooLarge, httpx.ErrBodyTooLarge.Error())
		return
	}
	httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
}

func statusFor(err error) (int, string) {
	if errors.Is(err, common.ErrEmailInvalid) {
		return http.StatusBadRequest, common.ErrEmailInvalid.Error()

	}
	if errors.Is(err, common.ErrEmailInUse) {
		return http.StatusConflict, common.ErrEmailInUse.Error()

	}
	if errors.Is(err, common.ErrPasswordTooShort) {
		return http.StatusBadRequest, common.ErrPasswordTooShort.Error()

	}
	if errors.Is(err, common.ErrPasswordTooLong) {
		return http.StatusBadRequest, common.ErrPasswordTooLong.Error()

	}
	if errors.Is(err, common.ErrInvalidCredentials) {
		return http.StatusUnauthorized, common.ErrInvalidCredentials.Error()
	}
	if errors.Is(err, common.ErrInvalidRefreshToken) {
		return http.StatusUnauthorized, common.ErrInvalidRefreshToken.Error()
	}
	return http.StatusInternalServerError, "internal server error"
}
