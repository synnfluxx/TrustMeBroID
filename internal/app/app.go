package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	grpcApp "github.com/synnfluxx/TrustMeBroID/internal/app/grpc"
	httpApp "github.com/synnfluxx/TrustMeBroID/internal/app/http"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/encryptor"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	"github.com/synnfluxx/TrustMeBroID/internal/services/auth"
	"github.com/synnfluxx/TrustMeBroID/internal/storage/postgres"
	redisStorage "github.com/synnfluxx/TrustMeBroID/internal/storage/redis"
)

var ReaperDelay = 5 * time.Hour

type App struct {
	GRPCSrv *grpcApp.App
	HTTPSrv *httpApp.App
}

func New(log *slog.Logger, grpcPort, grpcRPS, httpRPS int, storagePath string, redisPort, redisRetries int, redisHost string, redisTimeout, accessTokenTTL, refreshTokenTTL time.Duration) *App {
	storage, err := postgres.New(storagePath)
	if err != nil {
		panic(err)
	}

	redis, err := redisStorage.NewRedis(fmt.Sprintf("%s:%d", redisHost, redisPort), redisTimeout, redisRetries)
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func(ctx context.Context) {
		ticker := time.NewTicker(ReaperDelay)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				log.Info("Trying to delete old RIP users")
				deleted, err := storage.Reaper(context.Background())
				if err != nil {
					log.Warn("storage reaper error", sl.Err(err))
				} else {
					log.Info("storage reaper deleted successfully with users", slog.Attr{Key: "deleted users", Value: slog.AnyValue(deleted)})
				}
			}
		} //TODO: run in constructor
	}(ctx)

	ph := encryptor.NewPasswordHasher()
	authService := auth.New(log, storage, storage, storage, storage, redis, ph, accessTokenTTL, refreshTokenTTL)

	return &App{
		GRPCSrv: grpcApp.New(log, authService, grpcPort, cancel, grpcRPS),
		HTTPSrv: httpApp.NewHTTPApp(storage, log, redis, accessTokenTTL, refreshTokenTTL, httpRPS),
	}
}
