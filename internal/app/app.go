package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	grpcApp "github.com/synnfluxx/TrustMeBroID/internal/app/grpc"
	httpApp "github.com/synnfluxx/TrustMeBroID/internal/app/http"
	"github.com/synnfluxx/TrustMeBroID/internal/config"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/encryptor"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	"github.com/synnfluxx/TrustMeBroID/internal/services/auth"
	"github.com/synnfluxx/TrustMeBroID/internal/services/email"
	"github.com/synnfluxx/TrustMeBroID/internal/storage/postgres"
	redisStorage "github.com/synnfluxx/TrustMeBroID/internal/storage/redis"
)

type App struct {
	GRPCSrv *grpcApp.App
	HTTPSrv *httpApp.App
}

// New wires the dependency graph. It takes the config struct rather than a
// positional list: the previous signature had eighteen parameters, five of them
// time.Duration, so swapping two of them compiled cleanly and changed token
// lifetimes in production.
func New(log *slog.Logger, cfg *config.Config) *App {
	storage := mustOpenPostgres(log, cfg)
	redis := mustOpenRedis(log, cfg)

	emailService := email.NewEmailService(log, &cfg.SMTP)

	ctx, cancel := context.WithCancel(context.Background())
	startReaper(ctx, log, storage, cfg.DB.ReaperDelay)

	ph := encryptor.NewPasswordHasher()
	authService := auth.New(log, storage, storage, storage, storage, redis, ph,
		cfg.AccessTokenTTL, cfg.RefreshTokenTTL, emailService)

	log.Info("dependencies ready, constructing servers")

	return &App{
		GRPCSrv: grpcApp.New(log, authService, cfg.GRPC.Port, cancel, cfg.GRPC.Rps, cfg.GRPC.Burst, cfg.Env),
		HTTPSrv: httpApp.NewHTTPApp(storage, log, redis,
			cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.HTTP.CleanerDelay, cfg.HTTP.Rps, cfg.HTTP.Burst),
	}
}

func mustOpenPostgres(log *slog.Logger, cfg *config.Config) *postgres.Storage {
	start := time.Now()
	log.Info("connecting to postgres",
		slog.String("host", cfg.DB.Host),
		slog.Int("port", cfg.DB.Port),
		slog.String("sslmode", cfg.DB.SSLMode))

	storage, err := postgres.New(cfg.DB.ConnectionString, log)
	if err != nil {
		// A failed dependency at startup is fatal, but it should say which
		// dependency and why before the process goes away. panic(err) printed
		// a bare error with no context about what was being connected to.
		log.Error("cannot connect to postgres, refusing to start",
			slog.String("host", cfg.DB.Host),
			slog.Int("port", cfg.DB.Port),
			sl.Err(err), sl.Since(start))
		os.Exit(1)
	}

	log.Info("postgres connected", sl.Since(start))
	return storage
}

func mustOpenRedis(log *slog.Logger, cfg *config.Config) *redisStorage.Storage {
	start := time.Now()
	addr := fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port)
	usingURL := cfg.Redis.ConnectionString != ""

	log.Info("connecting to redis",
		slog.String("addr", addr),
		slog.Bool("from_connection_string", usingURL),
		slog.Duration("dial_timeout", cfg.Redis.Timeout),
		slog.Int("max_retries", cfg.Redis.Retries))

	redis, err := redisStorage.NewRedis(addr, cfg.Redis.Timeout, cfg.Redis.Retries, cfg.Redis.ConnectionString)
	if err != nil {
		log.Error("cannot connect to redis, refusing to start",
			slog.String("addr", addr),
			slog.String("impact", "refresh tokens cannot be issued or validated"),
			sl.Err(err), sl.Since(start))
		os.Exit(1)
	}

	log.Info("redis connected", sl.Since(start))
	return redis
}

// reaper is the slice of storage the background sweep needs. Narrowing it to
// one method keeps the loop testable without a database.
type reaper interface {
	Reaper(ctx context.Context) ([]int64, error)
}

// startReaper removes users whose soft-delete grace period has expired. It runs
// unattended, so each pass reports what it did: a reaper that silently stops
// deleting is otherwise invisible until the table grows.
func startReaper(ctx context.Context, log *slog.Logger, storage reaper, delay time.Duration) {
	log.Info("starting deleted-user reaper", slog.Duration("interval", delay))
	startReaperLoop(ctx, log, storage, delay)
}

// startReaperLoop runs the sweep and returns a stop function.
func startReaperLoop(ctx context.Context, log *slog.Logger, storage reaper, delay time.Duration) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		reaperLog := log.With(slog.String(logger.KeyOp, "app.reaper"))
		ticker := time.NewTicker(delay)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				reaperLog.Info("reaper stopped")
				return
			case <-ticker.C:
				start := time.Now()
				deleted, err := storage.Reaper(ctx)
				if err != nil {
					// Logged and swallowed on purpose: one failed sweep must
					// not end the loop.
					reaperLog.Error("reaper pass failed",
						slog.String(logger.KeyOutcome, logger.OutcomeFailed),
						sl.Err(err), sl.Since(start))
					continue
				}
				if len(deleted) == 0 {
					reaperLog.Debug("reaper pass found nothing to delete", sl.Since(start))
					continue
				}
				reaperLog.Info("reaper deleted expired users",
					slog.Int("count", len(deleted)),
					slog.Any("user_ids", deleted),
					slog.String(logger.KeyOutcome, logger.OutcomeSuccess),
					sl.Since(start))
			}
		}
	}()

	return cancel
}
