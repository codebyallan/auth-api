package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/codebyallan/auth-api/internal/auth"
	"github.com/codebyallan/auth-api/internal/storage/postgres"
	"github.com/codebyallan/auth-api/internal/token"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("no .env file found, relying on environment variables")
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	privateKey, err := token.LoadPrivateKey(os.Getenv("JWT_PRIVATE_KEY_PATH"))
	if err != nil {
		log.Fatal(err)
	}

	db, err := postgres.NewPostgresDB(dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	tokenService, err := token.NewTokenService(token.TokenConfig{
		Issuer:          "auth-api",
		Audience:        "auth-api",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * (24 * time.Hour),
		KeyID:           "auth-key-1",
	}, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	userRepo := postgres.NewUserRepo(db)
	refreshTokenRepo := postgres.NewRefreshTokenRepo(db)
	authHandler := auth.NewAuthHandler(auth.NewAuthService(userRepo, refreshTokenRepo, tokenService))
	tokenHandler := token.NewTokenHandler(tokenService)

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	select {
	case err := <-serverErrors:
		log.Fatalf("server error: %v", err)
	case <-ctx.Done():
		log.Println("shutdown signal received, shutting down gracefully...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
			if err := srv.Close(); err != nil {
				log.Printf("error closing server: %v", err)
			}
		}
		log.Println("server stopped successfully")
	}
}
