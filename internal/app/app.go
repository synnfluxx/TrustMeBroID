package app

import (
	"context"
	"log/slog"
	"time"

	grpcApp "github.com/synnfluxx/TrustMeBroID/internal/app/grpc"
	httpApp "github.com/synnfluxx/TrustMeBroID/internal/app/http"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	"github.com/synnfluxx/TrustMeBroID/internal/services/auth"
	"github.com/synnfluxx/TrustMeBroID/internal/storage/postgres"
)

type App struct {
	GRPCSrv *grpcApp.App
	HTTPSrv *httpApp.App
}

func New(log *slog.Logger, grpcPort int, storagePath string, tokenTTL time.Duration) *App {
	storage, err := postgres.New(storagePath)
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

	authService := auth.New(log, storage, storage, storage, storage, storage, tokenTTL)

	grpcApp := grpcApp.New(log, authService, grpcPort)
	httpApp := httpApp.NewHTTPApp(storage, log, tokenTTL)

	return &App{
		GRPCSrv: grpcApp,
		HTTPSrv: httpApp,
	}
}
