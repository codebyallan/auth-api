package token

import (
	"encoding/json"
	"net/http"
)

type TokenHandler struct {
	tokenService *TokenService
}

func NewTokenHandler(tokenService *TokenService) *TokenHandler {
	return &TokenHandler{tokenService: tokenService}
}

func (th *TokenHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(th.tokenService.JWKS())
}
