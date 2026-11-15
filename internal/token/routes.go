package token

import "net/http"

func (th *TokenHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/jwks.json", th.JWKS)
}
