package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/codebyallan/auth-api/internal/auth"
	"github.com/codebyallan/auth-api/internal/platform"
	"github.com/codebyallan/auth-api/internal/storage/postgres"
	"github.com/codebyallan/auth-api/internal/token"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	privateKey, err := token.LoadPrivateKey(os.Getenv("JWT_PRIVATE_KEY_PATH"))
	if err != nil {
		log.Fatal(err)
	}

	db, err := platform.NewPostgresDB(dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	issuer, err := token.NewTokenService(token.TokenConfig{
		Issuer:         "auth-api",
		Audience:       "auth-api",
		AccessTokenTTL: 15 * time.Minute,
		KeyID:          "auth-key-1",
	}, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	repo := postgres.NewUserRepo(db)
	authHandler := auth.NewAuthHandler(auth.NewAuthService(repo, issuer))
	tokenHandler := token.NewTokenHandler(issuer)

	mux := http.NewServeMux()
	authHandler.RegisterRoutes(mux)
	tokenHandler.RegisterRoutes(mux)

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("listening on %s", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}
