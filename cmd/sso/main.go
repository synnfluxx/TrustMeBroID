package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/dusted-go/logging/v2/handlers/prettylog"
	"github.com/joho/godotenv"
	"github.com/synnfluxx/TrustMeBroID/internal/app"
	"github.com/synnfluxx/TrustMeBroID/internal/config"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func init() {
	godotenv.Load()
}

func main() {
	cfg := config.MustLoad()

	log := setupLogger(cfg.Env)

	log.Info("starting sso server")

	application := app.New(log, cfg.GRPC.Port, cfg.GRPC.Rps, cfg.HTTP.Rps, cfg.DB.ConnectionString, cfg.Redis.Port, cfg.Redis.Retries, cfg.Redis.Host, cfg.Redis.Timeout, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)

	go application.GRPCSrv.MustRun()
	go application.HTTPSrv.MustRun()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	sig := <-stop
	log.Info("stopping application", slog.String("signal", sig.String()))

	application.GRPCSrv.Stop()
	err := application.HTTPSrv.Stop()
	if err != nil {
		log.Warn("error while trying to close http server")
	}

	log.Info("application stop")
}

func setupLogger(env string) *slog.Logger {
	var handler slog.Handler
	switch env {
	case envLocal:
		handler = prettylog.NewHandler(&slog.HandlerOptions{Level: slog.LevelDebug})
	case envDev:
		handler = prettylog.NewHandler(&slog.HandlerOptions{Level: slog.LevelDebug})
	case envProd:
		handler = prettylog.NewHandler(&slog.HandlerOptions{Level: slog.LevelInfo})
	}

	log := slog.New(handler)

	return log
}
