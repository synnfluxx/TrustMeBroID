package grpcApp

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"time"

	authgrpc "github.com/synnfluxx/TrustMeBroID/internal/grpc/auth"
	ssov1 "gitlab.com/synnfluxx/protos/sso/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       int
}

var adminMethods = []string{
	ssov1.Auth_RegisterApp_FullMethodName,
	ssov1.Auth_DeleteUser_FullMethodName,
	ssov1.Auth_DeleteAdmin_FullMethodName,
	ssov1.Auth_DeleteApp_FullMethodName,
	ssov1.Auth_UpdateRefreshToken_FullMethodName,
}

func isAdminMethod(method string) bool {
	return slices.Contains(adminMethods, method)
}

func AdminRequestsInterceptor() grpc.UnaryServerInterceptor {
return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	if isAdminMethod(info.FullMethod) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.PermissionDenied, "error while extracting metadata")
		}

		tokens := md["x-admin-token"]
		if len(tokens) == 0 {
			return nil, status.Error(codes.PermissionDenied, "auth endpoinds must be with x-admin-token field")
		}

		if !validateToken(tokens[0]) {
			return nil, status.Error(codes.PermissionDenied, "invalid token")
		}
	}

	return handler(ctx, req)
}
}

func LoggerInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		start := time.Now()

		resp, err = handler(ctx, req)
		duration := time.Since(start)

		if err != nil {
			log.Error("grpc request", "method", info.FullMethod, "duration", duration.Milliseconds(), "error", err)
		} else {
			log.Info("grpc request", "method", info.FullMethod, "duration", duration.Milliseconds())
		}

		return resp, err
	}
}

func New(log *slog.Logger, authService authgrpc.Auth, port int) *App {
	gRPCServer := grpc.NewServer(grpc.ChainUnaryInterceptor(LoggerInterceptor(log), AdminRequestsInterceptor()))

	authgrpc.Register(gRPCServer, authService)
	reflection.Register(gRPCServer)

	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
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
}

func validateToken(token string) bool {
	return subtle.ConstantTimeCompare([]byte(os.Getenv("ADMIN_TOKEN")), []byte(token)) == 1
}
