package grpcApp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger"
	discardHandler "github.com/synnfluxx/TrustMeBroID/internal/lib/logger/handlers/discardHandler"
	ssov1 "gitlab.com/synnfluxx/protos/sso/gen"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func info(method string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: method}
}

func okHandler(_ context.Context, _ any) (any, error) { return "ok", nil }

// ------------------------------------------------------------- Recovery ----

func TestRecoveryInterceptor_TurnsPanicIntoInternal(t *testing.T) {
	interceptor := RecoveryInterceptor(discardHandler.NewDiscardLogger())

	resp, err := interceptor(context.Background(), nil, info("/auth.Auth/Login"),
		func(context.Context, any) (any, error) { panic("boom") })

	require.Nil(t, resp)
	require.Equal(t, codes.Internal, status.Code(err))
	// The panic value must not reach the caller.
	require.NotContains(t, status.Convert(err).Message(), "boom")
}

func TestRecoveryInterceptor_SurvivesNilDereference(t *testing.T) {
	interceptor := RecoveryInterceptor(discardHandler.NewDiscardLogger())

	require.NotPanics(t, func() {
		_, err := interceptor(context.Background(), nil, info("/auth.Auth/Login"),
			func(context.Context, any) (any, error) {
				var m map[string]string
				m["x"] = "y" // assignment to entry in nil map
				return nil, nil
			})
		require.Equal(t, codes.Internal, status.Code(err))
	})
}

func TestRecoveryInterceptor_PassesThroughNormalCalls(t *testing.T) {
	interceptor := RecoveryInterceptor(discardHandler.NewDiscardLogger())

	resp, err := interceptor(context.Background(), nil, info("/auth.Auth/Login"), okHandler)

	require.NoError(t, err)
	require.Equal(t, "ok", resp)
}

func TestRecoveryInterceptor_PreservesHandlerErrors(t *testing.T) {
	interceptor := RecoveryInterceptor(discardHandler.NewDiscardLogger())
	want := status.Error(codes.NotFound, "nope")

	_, err := interceptor(context.Background(), nil, info("/auth.Auth/Login"),
		func(context.Context, any) (any, error) { return nil, want })

	require.Equal(t, codes.NotFound, status.Code(err))
}

// ------------------------------------------------------------ RequestID ----

func TestRequestIDInterceptor_AdoptsIncomingID(t *testing.T) {
	interceptor := RequestIDInterceptor(discardHandler.NewDiscardLogger())
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(logger.RequestIDHeader, "upstream-id"))

	var seen string
	_, err := interceptor(ctx, nil, info("/auth.Auth/Login"),
		func(c context.Context, _ any) (any, error) {
			seen = logger.RequestID(c)
			return nil, nil
		})

	require.NoError(t, err)
	require.Equal(t, "upstream-id", seen, "the caller's correlation id must be reused")
}

func TestRequestIDInterceptor_MintsWhenAbsent(t *testing.T) {
	interceptor := RequestIDInterceptor(discardHandler.NewDiscardLogger())

	var seen string
	_, err := interceptor(context.Background(), nil, info("/auth.Auth/Login"),
		func(c context.Context, _ any) (any, error) {
			seen = logger.RequestID(c)
			return nil, nil
		})

	require.NoError(t, err)
	require.NotEmpty(t, seen)
	require.Len(t, seen, 36, "expected a uuid")
}

func TestRequestIDInterceptor_BindsLoggerToContext(t *testing.T) {
	base := discardHandler.NewDiscardLogger()
	interceptor := RequestIDInterceptor(base)

	var bound bool
	_, err := interceptor(context.Background(), nil, info("/auth.Auth/Login"),
		func(c context.Context, _ any) (any, error) {
			bound = logger.From(c, nil) != nil
			return nil, nil
		})

	require.NoError(t, err)
	require.True(t, bound)
}

// ---------------------------------------------------------- Admin guard ----

func TestAdminRequestsInterceptor_NonAdminMethodsPassFreely(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "the-admin-token")
	interceptor := AdminRequestsInterceptor(discardHandler.NewDiscardLogger())

	resp, err := interceptor(context.Background(), nil, info(ssov1.Auth_Login_FullMethodName), okHandler)

	require.NoError(t, err)
	require.Equal(t, "ok", resp)
}

func TestAdminRequestsInterceptor_RejectsWithoutToken(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "the-admin-token")
	interceptor := AdminRequestsInterceptor(discardHandler.NewDiscardLogger())

	cases := []struct {
		name string
		ctx  context.Context
	}{
		{"no metadata", context.Background()},
		{"metadata without the header", metadata.NewIncomingContext(context.Background(), metadata.Pairs("other", "v"))},
		{"wrong token", metadata.NewIncomingContext(context.Background(), metadata.Pairs(adminTokenHeader, "guess"))},
		{"empty token", metadata.NewIncomingContext(context.Background(), metadata.Pairs(adminTokenHeader, ""))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			_, err := interceptor(tc.ctx, nil, info(ssov1.Auth_DeleteUser_FullMethodName),
				func(context.Context, any) (any, error) { called = true; return nil, nil })

			require.Equal(t, codes.PermissionDenied, status.Code(err))
			require.False(t, called, "the guarded handler must not run")
		})
	}
}

func TestAdminRequestsInterceptor_AcceptsCorrectToken(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "the-admin-token")
	interceptor := AdminRequestsInterceptor(discardHandler.NewDiscardLogger())
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(adminTokenHeader, "the-admin-token"))

	resp, err := interceptor(ctx, nil, info(ssov1.Auth_DeleteUser_FullMethodName), okHandler)

	require.NoError(t, err)
	require.Equal(t, "ok", resp)
}

// Every destructive method must be behind the guard. A method added to the
// service but forgotten here would be reachable by anyone.
func TestAdminMethods_CoverEveryDestructiveOperation(t *testing.T) {
	mustGuard := []string{
		ssov1.Auth_RegisterApp_FullMethodName,
		ssov1.Auth_DeleteUser_FullMethodName,
		ssov1.Auth_DeleteAdmin_FullMethodName,
		ssov1.Auth_DeleteApp_FullMethodName,
		ssov1.Auth_MakeAdmin_FullMethodName,
		ssov1.Auth_UpdateRefreshToken_FullMethodName,
		ssov1.Auth_Logout_FullMethodName,
	}
	for _, m := range mustGuard {
		require.True(t, isAdminMethod(m), "%s must require the admin token", m)
	}

	mustBeOpen := []string{
		ssov1.Auth_Login_FullMethodName,
		ssov1.Auth_Register_FullMethodName,
		ssov1.Auth_IsAdmin_FullMethodName,
	}
	for _, m := range mustBeOpen {
		require.False(t, isAdminMethod(m), "%s must stay callable by the app", m)
	}
}

// An empty ADMIN_TOKEN must not turn into "any token is accepted".
func TestValidateToken_EmptyEnvRejectsEverything(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "")

	require.False(t, validateToken(""))
	require.False(t, validateToken("anything"))
}

func TestValidateToken_ExactMatchOnly(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "the-admin-token")

	require.True(t, validateToken("the-admin-token"))
	require.False(t, validateToken("the-admin-toke"))
	require.False(t, validateToken("the-admin-tokenX"))
	require.False(t, validateToken("THE-ADMIN-TOKEN"))
	require.False(t, validateToken(""))
}

// ----------------------------------------------------------- Rate limit ----

func TestRateLimiterInterceptor_ShedsOnceBudgetIsSpent(t *testing.T) {
	// burst 1 means the second call in the same instant is refused.
	limiter := rate.NewLimiter(rate.Limit(1), 1)
	interceptor := RateLimiterInterceptor(discardHandler.NewDiscardLogger(), limiter)

	_, err := interceptor(context.Background(), nil, info("/auth.Auth/Login"), okHandler)
	require.NoError(t, err)

	called := false
	_, err = interceptor(context.Background(), nil, info("/auth.Auth/Login"),
		func(context.Context, any) (any, error) { called = true; return nil, nil })

	require.Equal(t, codes.ResourceExhausted, status.Code(err))
	require.False(t, called)
}

// The limiter is process-wide, so traffic to one method starves every other.
func TestRateLimiterInterceptor_IsSharedAcrossMethods(t *testing.T) {
	limiter := rate.NewLimiter(rate.Limit(1), 1)
	interceptor := RateLimiterInterceptor(discardHandler.NewDiscardLogger(), limiter)

	_, err := interceptor(context.Background(), nil, info(ssov1.Auth_Login_FullMethodName), okHandler)
	require.NoError(t, err)

	_, err = interceptor(context.Background(), nil, info(ssov1.Auth_Register_FullMethodName), okHandler)
	require.Equal(t, codes.ResourceExhausted, status.Code(err),
		"a different method shares the same budget")
}

// -------------------------------------------------------------- Logging ----

func TestLoggerInterceptor_PassesResultsThrough(t *testing.T) {
	interceptor := LoggerInterceptor(discardHandler.NewDiscardLogger())

	resp, err := interceptor(context.Background(), nil, info("/auth.Auth/Login"), okHandler)
	require.NoError(t, err)
	require.Equal(t, "ok", resp)

	want := status.Error(codes.NotFound, "nope")
	_, err = interceptor(context.Background(), nil, info("/auth.Auth/Login"),
		func(context.Context, any) (any, error) { return nil, want })
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestIsClientFault(t *testing.T) {
	clientSide := []codes.Code{
		codes.InvalidArgument, codes.NotFound, codes.AlreadyExists,
		codes.PermissionDenied, codes.Unauthenticated, codes.ResourceExhausted,
	}
	for _, c := range clientSide {
		require.True(t, isClientFault(c), "%s should not be an error-level record", c)
	}

	serverSide := []codes.Code{codes.Internal, codes.Unknown, codes.Unavailable, codes.DataLoss}
	for _, c := range serverSide {
		require.False(t, isClientFault(c), "%s must be reported as our failure", c)
	}
}

func TestShortMethod(t *testing.T) {
	require.Equal(t, "Login", shortMethod("/auth.Auth/Login"))
	require.Equal(t, "bare", shortMethod("bare"))
	require.Equal(t, "/", shortMethod("/"))
}

func TestPeerAddr_EmptyWithoutPeer(t *testing.T) {
	require.Empty(t, peerAddr(context.Background()))
}

// ------------------------------------------------------------- Together ----

// The chain must behave as configured in New: a panic inside a guarded handler
// still returns Internal rather than killing the process.
func TestChainRecoversPanicInsideGuardedMethod(t *testing.T) {
	t.Setenv("ADMIN_TOKEN", "the-admin-token")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(adminTokenHeader, "the-admin-token"))
	log := discardHandler.NewDiscardLogger()

	recovery := RecoveryInterceptor(log)
	admin := AdminRequestsInterceptor(log)

	_, err := recovery(ctx, nil, info(ssov1.Auth_DeleteUser_FullMethodName),
		func(c context.Context, r any) (any, error) {
			return admin(c, r, info(ssov1.Auth_DeleteUser_FullMethodName),
				func(context.Context, any) (any, error) { panic(errors.New("handler bug")) })
		})

	require.Equal(t, codes.Internal, status.Code(err))
	require.False(t, strings.Contains(status.Convert(err).Message(), "handler bug"))
}
