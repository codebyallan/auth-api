package auth

import (
	"encoding/json"
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
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
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
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
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
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
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
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
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
