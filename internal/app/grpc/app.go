package grpcApp

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	authgrpc "github.com/synnfluxx/TrustMeBroID/internal/grpc/auth"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// adminTokenHeader is the metadata key carrying the shared admin credential.
const adminTokenHeader = "x-admin-token"

type App struct {
	log          *slog.Logger
	gRPCServer   *grpc.Server
	port         int
	env          string
	ReaperCancel context.CancelFunc
}

func New(log *slog.Logger, authService authgrpc.Auth, port int, cancel context.CancelFunc, rps, burst int, env string) *App {
	// Outermost first. Recovery wraps everything so a panic anywhere still
	// produces a log record; the request id is established next so every record
	// after it is correlated; the access log sits outside the limiter and the
	// admin guard so their rejections are recorded too.
	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			RecoveryInterceptor(log),
			RequestIDInterceptor(log),
			LoggerInterceptor(log),
			RateLimiterInterceptor(log, rate.NewLimiter(rate.Limit(rps), burst)),
			AdminRequestsInterceptor(log),
		),
	)

	authgrpc.Register(server, authService)

	// Reflection lets any client enumerate the whole API. That is a debugging
	// convenience in development and an information leak on a port that is
	// published to the internet, so it is gated on the environment.
	if env != logger.EnvProd {
		reflection.Register(server)
		log.Info("grpc reflection enabled", slog.String("env", env))
	} else {
		log.Info("grpc reflection disabled in production")
	}

	return &App{
		log:          log,
		gRPCServer:   server,
		port:         port,
		env:          env,
		ReaperCancel: cancel,
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		a.log.Error("grpc server terminated",
			slog.Int("port", a.port),
			slog.String(logger.KeyOutcome, logger.OutcomeFailed),
			sl.Err(err))
		os.Exit(1)
	}
}

func (a *App) Run() error {
	const op = "grpcapp.Run"
	log := a.log.With(slog.String(logger.KeyOp, op), slog.Int("port", a.port))

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		log.Error("cannot bind grpc port", sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("grpc server listening",
		slog.String("addr", l.Addr().String()),
		slog.String("transport", "plaintext h2c"))

	if err := a.gRPCServer.Serve(l); err != nil {
		log.Error("grpc server stopped serving", sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *App) Stop() {
	const op = "grpcapp.Stop"
	log := a.log.With(slog.String(logger.KeyOp, op), slog.Int("port", a.port))

	start := time.Now()
	log.Info("draining grpc server")

	a.gRPCServer.GracefulStop()
	a.ReaperCancel()

	log.Info("grpc server stopped", sl.Since(start))
}

// validateToken compares the presented admin credential in constant time.
func validateToken(token string) bool {
	if token == "" {
		return false
	}
	expected := os.Getenv("ADMIN_TOKEN")
	if expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(token)) == 1
}
