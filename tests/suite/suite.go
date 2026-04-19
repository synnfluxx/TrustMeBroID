package suite

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/synnfluxx/TrustMeBroID/internal/config"
	"github.com/synnfluxx/TrustMeBroID/internal/services/auth"
	ssov1 "gitlab.com/synnfluxx/protos/sso/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

var testAppRequest = &ssov1.RegisterAppRequest{
	AppName: "test",
}

func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()

	cfg := config.MustLoadByPath("../config/local.yaml")

	ctx, cancelCtx := context.WithTimeout(context.Background(), cfg.GRPC.Timeout)

	cc, err := grpc.NewClient(grpcAddress(cfg), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc server connection failed: %v", err)
	}

	authClient := ssov1.NewAuthClient(cc)

	resp, err := authClient.RegisterApp(context.Background(), testAppRequest)
	if err != nil {
		if err == auth.ErrAppExists {
			t.Logf("Test App Already Exists!")
		} else {
			t.Fatalf("test app creating error: %v", err)
		}
	}

	t.Cleanup(func() {
		t.Helper()
		cancelCtx()
		_ = cc.Close()

		if _, err := authClient.DeleteApp(context.Background(), &ssov1.DeleteAppRequest{
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
