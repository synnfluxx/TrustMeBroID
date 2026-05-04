package grpcApp

import (
	"context"
	"log/slog"
	"slices"
	"time"

	ssov1 "gitlab.com/synnfluxx/protos/sso/gen"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var adminMethods = []string{
	ssov1.Auth_RegisterApp_FullMethodName,
	ssov1.Auth_DeleteUser_FullMethodName,
	ssov1.Auth_DeleteAdmin_FullMethodName,
	ssov1.Auth_DeleteApp_FullMethodName,
	ssov1.Auth_UpdateRefreshToken_FullMethodName,
	ssov1.Auth_MakeAdmin_FullMethodName,
	ssov1.Auth_Logout_FullMethodName,
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

func RateLimiterInterceptor(limiter *rate.Limiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		if !limiter.Allow() {
			return nil, status.Errorf(codes.ResourceExhausted, "%s have been rejected by rate limiting.", info.FullMethod)
		}

		return handler(ctx, req)
	}
}
