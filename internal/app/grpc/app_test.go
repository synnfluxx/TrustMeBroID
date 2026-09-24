package grpcApp

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger"
	discardHandler "github.com/synnfluxx/TrustMeBroID/internal/lib/logger/handlers/discardHandler"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection/grpc_reflection_v1"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// startServer boots the real server on an ephemeral port and returns its
// address. Auth is nil: these tests exercise the server lifecycle and the
// reflection gate, never a handler.
func startServer(t *testing.T, env string) (*App, string) {
	t.Helper()

	port := freePort(t)
	_, cancel := context.WithCancel(context.Background())
	app := New(discardHandler.NewDiscardLogger(), nil, port, cancel, 100, 100, env)

	go app.MustRun()
	t.Cleanup(app.Stop)

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 5*time.Second, 25*time.Millisecond, "server never started listening")

	return app, addr
}

func reflectionEnabled(t *testing.T, addr string) bool {
	t.Helper()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	stream, err := grpc_reflection_v1.NewServerReflectionClient(conn).ServerReflectionInfo(ctx)
	if err != nil {
		return false
	}
	if err := stream.Send(&grpc_reflection_v1.ServerReflectionRequest{
		MessageRequest: &grpc_reflection_v1.ServerReflectionRequest_ListServices{},
	}); err != nil {
		return false
	}
	_, err = stream.Recv()
	return err == nil
}

// Reflection lets any caller enumerate the whole API. The gRPC port is
// published on all interfaces, so it must be off in production.
func TestNew_ReflectionIsDisabledInProduction(t *testing.T) {
	_, addr := startServer(t, logger.EnvProd)

	require.False(t, reflectionEnabled(t, addr), "reflection must not answer in prod")
}

func TestNew_ReflectionIsEnabledOutsideProduction(t *testing.T) {
	_, addr := startServer(t, logger.EnvLocal)

	require.True(t, reflectionEnabled(t, addr), "reflection is a development convenience")
}

func TestRun_FailsWhenThePortIsTaken(t *testing.T) {
	port := freePort(t)
	holder, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(port)))
	require.NoError(t, err)
	defer holder.Close()

	_, cancel := context.WithCancel(context.Background())
	app := New(discardHandler.NewDiscardLogger(), nil, port, cancel, 100, 100, logger.EnvLocal)

	require.Error(t, app.Run())
}

// Stop must also release the reaper, otherwise the background goroutine
// outlives the server.
func TestStop_CancelsTheReaper(t *testing.T) {
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	app := New(discardHandler.NewDiscardLogger(), nil, port, cancel, 100, 100, logger.EnvLocal)

	go app.MustRun()
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 5*time.Second, 25*time.Millisecond)

	app.Stop()

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel the reaper context")
	}
}

func TestStop_ClosesTheListener(t *testing.T) {
	app, addr := startServer(t, logger.EnvLocal)

	app.Stop()

	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return true
		}
		_ = conn.Close()
		return false
	}, 5*time.Second, 25*time.Millisecond, "the port is still accepting connections")
}
