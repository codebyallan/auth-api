package cleanup

import (
	"context"
	"log"
	"time"
)

type Repository interface {
	CleanupExpired(ctx context.Context, expiredBefore, revokedBefore time.Time, batchSize, maxBatches int) (int64, error)
}

type Config struct {
	Interval         time.Duration
	ExpiredRetention time.Duration
	RevokedRetention time.Duration
	BatchSize        int
	MaxBatches       int
	Timeout          time.Duration
}

type Runner struct {
	done chan struct{}
}

func Start(ctx context.Context, repo Repository, cfg Config) *Runner {
	r := &Runner{done: make(chan struct{})}
	go func() {
		defer close(r.done)
		runCycle(ctx, repo, cfg)
		ticker := time.NewTicker(cfg.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runCycle(ctx, repo, cfg)
			}
		}
	}()
	return r
}

func (r *Runner) Wait() {
	<-r.done
}

func runCycle(ctx context.Context, repo Repository, cfg Config) {
	cycleCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	expiredBefore := time.Now().UTC().Add(-cfg.ExpiredRetention)
	revokedBefore := time.Now().UTC().Add(-cfg.RevokedRetention)
	start := time.Now()
	n, err := repo.CleanupExpired(cycleCtx, expiredBefore, revokedBefore, cfg.BatchSize, cfg.MaxBatches)
	if err != nil {
		log.Printf("cleanup error: %v", err)
		return
	}
	log.Printf("cleanup removed %d tokens in %s", n, time.Since(start))
}
