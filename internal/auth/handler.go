package auth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/codebyallan/auth-api/internal/common"
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
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	res, err := ah.authService.Register(r.Context(), req)
	if err != nil {
		status, message := statusFor(err)
		if status == http.StatusInternalServerError {
			log.Printf("register: %v", err)
		}
		writeError(w, status, message)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (ah *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	res, err := ah.authService.Login(r.Context(), req)
	if err != nil {
		status, message := statusFor(err)
		if status == http.StatusInternalServerError {
			log.Printf("login: %v", err)
		}
		writeError(w, status, message)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
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
	return http.StatusInternalServerError, "internal server error"
}
