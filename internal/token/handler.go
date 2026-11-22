package token

import (
	"net/http"

	"github.com/codebyallan/auth-api/internal/httpx"
)

type TokenHandler struct {
	tokenService *TokenService
}

func NewTokenHandler(tokenService *TokenService) *TokenHandler {
	return &TokenHandler{tokenService: tokenService}
}

func (th *TokenHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, th.tokenService.JWKS())
}
