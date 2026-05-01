package suite

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/joho/godotenv"
	"github.com/synnfluxx/TrustMeBroID/internal/config"
	ssov1 "gitlab.com/synnfluxx/protos/sso/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	grpcHost = "localhost"
)

type Suite struct {
	*testing.T
	Cfg        *config.Config
	AuthClient ssov1.AuthClient
	AppID      int64
	AppSecret  string
}

func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()

	_ = godotenv.Load("../.env", ".env")
	cfg := config.MustLoadByPath("../config/local.yaml")

	ctx, cancelCtx := context.WithTimeout(context.Background(), cfg.GRPC.Timeout)

	cc, err := grpc.NewClient(grpcAddress(cfg), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc server connection failed: %v", err)
	}

	authClient := ssov1.NewAuthClient(cc)
	appName := "test-" + gofakeit.LetterN(8) + strconv.FormatInt(time.Now().UnixNano(), 10)
	appRedirectURI := "http://localhost:3000/auth/callback"

	resp, err := authClient.RegisterApp(adminContext(context.Background()), &ssov1.RegisterAppRequest{
		AppName:     appName,
		RedirectUri: appRedirectURI,
	})
	if err != nil {
		if serverUnavailable(err) {
			cancelCtx()
			_ = cc.Close()
			t.Skipf("integration server is unavailable at %s: %v", grpcAddress(cfg), err)
		}
		t.Fatalf("test app creating error: %v", err)
	}

	t.Cleanup(func() {
		t.Helper()
		cancelCtx()
		_ = cc.Close()

		if _, err := authClient.DeleteApp(adminContext(context.Background()), &ssov1.DeleteAppRequest{
			AppId: resp.AppId,
		}); err != nil {
			t.Fatalf("error while deleting app: %v", err)
		}
	})

	return ctx, &Suite{
		T:          t,
		Cfg:        cfg,
		AuthClient: ssov1.NewAuthClient(cc),
		AppID:      resp.GetAppId(),
		AppSecret:  resp.GetSecret(),
	}
}

func grpcAddress(cfg *config.Config) string {
	return net.JoinHostPort(grpcHost, strconv.Itoa(int(cfg.GRPC.Port)))
}

func adminContext(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "x-admin-token", os.Getenv("ADMIN_TOKEN"))
}

func serverUnavailable(err error) bool {
	if err == nil {
		return false
	}

	return errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(err.Error(), "connection refused") ||
		strings.Contains(err.Error(), "connection error") ||
		strings.Contains(err.Error(), "Error while dialing")
}
