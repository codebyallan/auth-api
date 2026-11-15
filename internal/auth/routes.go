package auth

import "net/http"

func (ah *AuthHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/register", ah.Register)
	mux.HandleFunc("POST /auth/login", ah.Login)
}
