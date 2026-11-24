package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/codebyallan/auth-api/internal/cleanup"
	"github.com/codebyallan/auth-api/internal/common"
	"github.com/codebyallan/auth-api/internal/token"
	"github.com/joho/godotenv"
)

const (
	jwtIssuer   = "auth-api"
	jwtAudience = "auth-api"
	jwtKeyID    = "auth-key-1"

	defaultAccessTokenTTL  = 15 * time.Minute
	defaultRefreshTokenTTL = 30 * 24 * time.Hour

	defaultHTTPAddr          = ":8080"
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 10 * time.Second
	defaultWriteTimeout      = 10 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultShutdownTimeout   = 10 * time.Second

	defaultCleanupInterval   = 24 * time.Hour
	defaultExpiredRetention  = 7 * 24 * time.Hour
	defaultRevokedRetention  = 30 * 24 * time.Hour
	defaultCleanupBatchSize  = 1000
	defaultCleanupMaxBatches = 100
	defaultCleanupTimeout    = 5 * time.Minute
)

type Config struct {
	DatabaseURL    string
	PrivateKeyPath string
	Token          token.TokenConfig
	Cleanup        cleanup.Config
	HTTP           HTTPConfig
}

type HTTPConfig struct {
	Addr              string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

func Load() (Config, error) {
	if err := godotenv.Load(); err != nil {
		log.Println("no .env file found, relying on environment variables")
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return Config{}, common.ErrMissingDatabaseURL
	}

	keyPath := os.Getenv("JWT_PRIVATE_KEY_PATH")
	if keyPath == "" {
		return Config{}, common.ErrMissingKeyPath
	}

	return Config{
		DatabaseURL:    dsn,
		PrivateKeyPath: keyPath,
		Token: token.TokenConfig{
			Issuer:          jwtIssuer,
			Audience:        jwtAudience,
			KeyID:           jwtKeyID,
			AccessTokenTTL:  defaultAccessTokenTTL,
			RefreshTokenTTL: defaultRefreshTokenTTL,
		},
		Cleanup: cleanup.Config{
			Interval:         durationEnv("CLEANUP_INTERVAL", defaultCleanupInterval),
			ExpiredRetention: durationEnv("EXPIRED_TOKEN_RETENTION", defaultExpiredRetention),
			RevokedRetention: durationEnv("REVOKED_TOKEN_RETENTION", defaultRevokedRetention),
			BatchSize:        intEnv("CLEANUP_BATCH_SIZE", defaultCleanupBatchSize),
			MaxBatches:       intEnv("CLEANUP_MAX_BATCHES", defaultCleanupMaxBatches),
			Timeout:          durationEnv("CLEANUP_TIMEOUT", defaultCleanupTimeout),
		},
		HTTP: HTTPConfig{
			Addr:              stringEnv("HTTP_ADDR", defaultHTTPAddr),
			ReadHeaderTimeout: defaultReadHeaderTimeout,
			ReadTimeout:       defaultReadTimeout,
			WriteTimeout:      defaultWriteTimeout,
			IdleTimeout:       defaultIdleTimeout,
			ShutdownTimeout:   defaultShutdownTimeout,
		},
	}, nil
}

func durationEnv(key string, def time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	v, err := time.ParseDuration(raw)
	if err != nil || v <= 0 {
		log.Printf("invalid %s=%q, using default %s", key, raw, def)
		return def
	}
	return v
}

func intEnv(key string, def int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		log.Printf("invalid %s=%q, using default %d", key, raw, def)
		return def
	}
	return v
}

func stringEnv(key, def string) string {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	return raw
}
