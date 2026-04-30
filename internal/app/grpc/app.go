package grpcApp

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"os"

	authgrpc "github.com/synnfluxx/TrustMeBroID/internal/grpc/auth"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type App struct {
	log          *slog.Logger
	gRPCServer   *grpc.Server
	port         int
	ReaperCancel context.CancelFunc
}

func New(log *slog.Logger, authService authgrpc.Auth, port int, cancel context.CancelFunc, rps int) *App {
	gRPCServer := grpc.NewServer(grpc.ChainUnaryInterceptor(RateLimiterInterceptor(rate.NewLimiter(rate.Limit(rps), rps)), LoggerInterceptor(log), AdminRequestsInterceptor())) //TODO: add burst to config

	authgrpc.Register(gRPCServer, authService)
	reflection.Register(gRPCServer)

	return &App{
		log:          log,
		gRPCServer:   gRPCServer,
		port:         port,
		ReaperCancel: cancel,
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	const op = "grpcapp.Run"

	log := a.log.With(slog.String("op", op), slog.Int("port", a.port))

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("grpc server is running", slog.String("addr", l.Addr().String()))

	if err := a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *App) Stop() {
	const op = "grpcapp.Stop"

	a.log.With(slog.String("op", op)).Info("stopping gRPC server", slog.Int("port", a.port))

	a.gRPCServer.GracefulStop()
	a.ReaperCancel()
}

func validateToken(token string) bool {
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(os.Getenv("ADMIN_TOKEN")), []byte(token)) == 1
}
