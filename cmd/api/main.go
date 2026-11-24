package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/codebyallan/auth-api/internal/auth"
	"github.com/codebyallan/auth-api/internal/cleanup"
	"github.com/codebyallan/auth-api/internal/config"
	"github.com/codebyallan/auth-api/internal/storage/postgres"
	"github.com/codebyallan/auth-api/internal/token"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := token.LoadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	db, err := postgres.NewPostgresDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	tokenService, err := token.NewTokenService(cfg.Token, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	userRepo := postgres.NewUserRepo(db)
	refreshTokenRepo := postgres.NewRefreshTokenRepo(db)

	log.Printf("cleanup config: interval=%s expired_retention=%s revoked_retention=%s batch=%d max_batches=%d timeout=%s",
		cfg.Cleanup.Interval, cfg.Cleanup.ExpiredRetention, cfg.Cleanup.RevokedRetention, cfg.Cleanup.BatchSize, cfg.Cleanup.MaxBatches, cfg.Cleanup.Timeout)

	authHandler := auth.NewAuthHandler(auth.NewAuthService(userRepo, refreshTokenRepo, tokenService))
	tokenHandler := token.NewTokenHandler(tokenService)

	mux := http.NewServeMux()
	authHandler.RegisterRoutes(mux)
	tokenHandler.RegisterRoutes(mux)

	srv := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           mux,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner := cleanup.Start(ctx, refreshTokenRepo, cfg.Cleanup)

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

		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
			if err := srv.Close(); err != nil {
				log.Printf("error closing server: %v", err)
			}
		}
		runner.Wait()
		log.Println("server stopped successfully")
	}
}
