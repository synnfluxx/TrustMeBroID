package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	grpcApp "github.com/synnfluxx/TrustMeBroID/internal/app/grpc"
	httpApp "github.com/synnfluxx/TrustMeBroID/internal/app/http"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	"github.com/synnfluxx/TrustMeBroID/internal/services/auth"
	"github.com/synnfluxx/TrustMeBroID/internal/storage/postgres"
	storage_redis "github.com/synnfluxx/TrustMeBroID/internal/storage/redis"
)

type App struct {
	GRPCSrv *grpcApp.App
	HTTPSrv *httpApp.App
}

func New(log *slog.Logger, grpcPort int, storagePath string, redisPort, redisRetries int, redisHost string, redisTimeout, accessTokenTTL, refreshTokenTTL time.Duration) (*App) {
	storage, err := postgres.New(storagePath)
	if err != nil {
		panic(err)
	}

	redis, err := storage_redis.MustNewRedis(fmt.Sprintf("%s:%d", redisHost, redisPort), redisTimeout, redisRetries)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			log.Info("Trying to delete old RIP users")
			deleted, err := storage.Reaper(context.Background())
			if err != nil {
				log.Warn("storage reaper error", sl.Err(err))
			} else {
				log.Info("storage reaper deleted successfully with users", slog.Attr{Key: "deleted users",Value: slog.AnyValue(deleted)})
			}
			time.Sleep(5*time.Hour)
		}
	}()

	authService, err := auth.New(log, storage, storage, storage, storage, storage, redis, accessTokenTTL, refreshTokenTTL)
	if err != nil {
		panic(err)
	}

	grpcApp := grpcApp.New(log, authService, grpcPort)
	httpApp := httpApp.NewHTTPApp(storage, log, redis, accessTokenTTL, refreshTokenTTL)

	return &App{
		GRPCSrv: grpcApp,
		HTTPSrv: httpApp,
	}
}
