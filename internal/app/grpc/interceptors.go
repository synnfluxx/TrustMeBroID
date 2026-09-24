package grpcApp

import (
	"context"
	"log/slog"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	ssov1 "gitlab.com/synnfluxx/protos/sso/gen"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
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

// shortMethod turns "/auth.Auth/Login" into "Login" for the log's method field,
// keeping the full path in a separate attribute for exact matching.
func shortMethod(full string) string {
	if i := strings.LastIndex(full, "/"); i >= 0 && i+1 < len(full) {
		return full[i+1:]
	}
	return full
}

func peerAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return ""
}

// RecoveryInterceptor turns a panic in a handler into an Internal error plus a
// log record with the stack.
//
// grpc-go does not recover panics itself: without this, a nil dereference in
// any handler takes the whole SSO process down and the only evidence is a
// stack on stderr with no request context attached.
func RecoveryInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.From(ctx, log).Error("panic in grpc handler",
					slog.String("method", shortMethod(info.FullMethod)),
					slog.String("full_method", info.FullMethod),
					slog.Any("panic", r),
					slog.String("stack", string(debug.Stack())),
					slog.String(logger.KeyOutcome, logger.OutcomeFailed),
				)
				err = status.Error(codes.Internal, "internal server error")
				resp = nil
			}
		}()
		return handler(ctx, req)
	}
}

// RequestIDInterceptor adopts the caller's correlation id, or mints one, and
// binds a logger carrying it to the context. Every record produced downstream —
// service, storage, email — then joins up with the AuraLift request that caused
// it, which is the only practical way to follow a failure across the two
// services.
func RequestIDInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		id := ""
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if values := md.Get(logger.RequestIDHeader); len(values) > 0 {
				id = values[0]
			}
		}
		inherited := id != ""
		if !inherited {
			id = uuid.NewString()
		}

		ctx, _ = logger.WithRequestID(ctx, log, id)

		// Echo it back so the caller can tie its own record to ours even when
		// it did not send one.
		_ = grpc.SetHeader(ctx, metadata.Pairs(logger.RequestIDHeader, id))

		return handler(ctx, req)
	}
}

// LoggerInterceptor writes one access record per call.
//
// The level follows the gRPC code: a wrong password is not an operational
// problem and must not page anyone, while codes.Internal always must. The
// previous implementation logged every error at Error level, which made
// failed logins indistinguishable from outages.
func LoggerInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		reqLog := logger.From(ctx, log)

		reqLog.Debug("grpc call started",
			slog.String("method", shortMethod(info.FullMethod)),
			slog.String("peer", peerAddr(ctx)))

		resp, err := handler(ctx, req)

		code := status.Code(err)
		attrs := []any{
			slog.String("method", shortMethod(info.FullMethod)),
			slog.String("full_method", info.FullMethod),
			slog.String("grpc_code", code.String()),
			slog.String("peer", peerAddr(ctx)),
			sl.Since(start),
		}

		switch {
		case err == nil:
			attrs = append(attrs, slog.String(logger.KeyOutcome, logger.OutcomeSuccess))
			reqLog.Info("grpc call completed", attrs...)
		case isClientFault(code):
			attrs = append(attrs,
				slog.String(logger.KeyOutcome, logger.OutcomeRejected),
				slog.String("grpc_message", status.Convert(err).Message()))
			reqLog.Warn("grpc call rejected", attrs...)
		default:
			attrs = append(attrs,
				slog.String(logger.KeyOutcome, logger.OutcomeFailed),
				sl.Err(err))
			reqLog.Error("grpc call failed", attrs...)
		}

		return resp, err
	}
}

// isClientFault separates "the caller asked for something invalid" from "we
// broke". Only the second class deserves an error-level record.
func isClientFault(code codes.Code) bool {
	switch code {
	case codes.InvalidArgument, codes.NotFound, codes.AlreadyExists,
		codes.PermissionDenied, codes.Unauthenticated, codes.FailedPrecondition,
		codes.OutOfRange, codes.Canceled, codes.ResourceExhausted:
		return true
	default:
		return false
	}
}

// AdminRequestsInterceptor guards the methods that can delete users and
// applications. Every rejection is logged: repeated failures here are the
// signature of someone probing the admin surface, and previously they were
// indistinguishable from any other error.
func AdminRequestsInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !isAdminMethod(info.FullMethod) {
			return handler(ctx, req)
		}

		reqLog := logger.From(ctx, log).With(
			slog.String("method", shortMethod(info.FullMethod)),
			slog.String("peer", peerAddr(ctx)),
			slog.Bool("admin_method", true),
		)

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			reqLog.Warn("admin call rejected: no metadata on the request",
				slog.String("reason", "missing_metadata"))
			return nil, status.Error(codes.PermissionDenied, "missing metadata")
		}

		tokens := md.Get(adminTokenHeader)
		if len(tokens) == 0 {
			reqLog.Warn("admin call rejected: admin token header absent",
				slog.String("reason", "missing_token"),
				slog.String("expected_header", adminTokenHeader))
			return nil, status.Error(codes.PermissionDenied, "admin token required")
		}

		if !validateToken(tokens[0]) {
			// The fingerprint lets an operator confirm whether a caller is
			// sending a stale token or an unrelated one, without the log
			// holding a usable credential.
			reqLog.Warn("admin call rejected: admin token mismatch",
				slog.String("reason", "invalid_token"),
				sl.Token("presented", tokens[0]))
			return nil, status.Error(codes.PermissionDenied, "invalid admin token")
		}

		reqLog.Info("admin call authorised")
		return handler(ctx, req)
	}
}

// RateLimiterInterceptor sheds load once the process-wide budget is spent.
// Rejections are logged at warn with the configured limit attached, because the
// usual cause is that the limit is set far below real traffic.
func RateLimiterInterceptor(log *slog.Logger, limiter *rate.Limiter) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !limiter.Allow() {
			logger.From(ctx, log).Warn("grpc call shed by rate limiter",
				slog.String("method", shortMethod(info.FullMethod)),
				slog.String("peer", peerAddr(ctx)),
				slog.Float64("limit_rps", float64(limiter.Limit())),
				slog.Int("burst", limiter.Burst()),
				slog.String("scope", "process-wide"),
				slog.String(logger.KeyOutcome, logger.OutcomeRejected),
			)
			return nil, status.Errorf(codes.ResourceExhausted, "%s rejected by rate limiting", info.FullMethod)
		}
		return handler(ctx, req)
	}
}
