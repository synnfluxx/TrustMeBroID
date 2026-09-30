package authgrpc

import (
	"context"
	"testing"

	ssov1 "github.com/synnfluxx/TrustMeBroID/api/sso/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A handler whose name does not match its rpc still compiles: the embedded
// UnimplementedAuthServer supplies the missing method, and the mismatch only
// shows up in production as codes.Unimplemented. Reflection cannot see it —
// the promoted method reports the outer type — so drive each rpc through the
// service descriptor instead. The stub answers Unimplemented to anything;
// a real handler rejects the empty request, or trips the bare mock. Either
// way it is not the stub.
func TestEveryRPCReachesItsOwnHandler(t *testing.T) {
	api := &serverAPI{auth: &MockAuth{}}
	empty := func(any) error { return nil }

	for _, rpc := range ssov1.Auth_ServiceDesc.Methods {
		t.Run(rpc.MethodName, func(t *testing.T) {
			var err error
			func() {
				defer func() { _ = recover() }()
				_, err = rpc.Handler(api, context.Background(), empty, nil)
			}()

			if status.Code(err) == codes.Unimplemented {
				t.Errorf("rpc %s falls through to the generated stub: the handler is named something else", rpc.MethodName)
			}
		})
	}
}
