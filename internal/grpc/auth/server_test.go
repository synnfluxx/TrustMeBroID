package authgrpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/synnfluxx/TrustMeBroID/internal/services/auth"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
	ssov1 "gitlab.com/synnfluxx/protos/sso/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLogin(t *testing.T) {
	tests := []struct {
		name                 string
		req                  *ssov1.LoginRequest
		mockBehavior         func(m *AuthMock)
		expectedCode         codes.Code
		expectedToken        string
		expectedRefreshToken string
	}{
		{
			name: "Success",
			req: &ssov1.LoginRequest{
				Identifier: &ssov1.LoginRequest_Email{
					Email: "test@example.com",
				},
				Password: "Password123",
				AppId:    1,
			},
			mockBehavior: func(m *AuthMock) {
				m.On("LoginByEmail", mock.Anything, "test@example.com", "Password123", int64(1)).
					Return("valid-token", "refresh-valid-token", nil)
			},
			expectedCode:         codes.OK,
			expectedToken:        "valid-token",
			expectedRefreshToken: "refresh-valid-token",
		},
		{
			name: "InvalidEmail",
			req: &ssov1.LoginRequest{
				Identifier: &ssov1.LoginRequest_Email{
					Email: "invalid-email",
				},
				Password: "Password123",
				AppId:    1,
			},
			mockBehavior: func(m *AuthMock) {},
			expectedCode: codes.InvalidArgument,
		},
		{
			name: "UserNotFound",
			req: &ssov1.LoginRequest{
				Identifier: &ssov1.LoginRequest_Email{
					Email: "notfound@example.com",
				},
				Password: "Password123",
				AppId:    1,
			},
			mockBehavior: func(m *AuthMock) {
				m.On("LoginByEmail", mock.Anything, "notfound@example.com", "Password123", int64(1)).
					Return("", "", storage.ErrUserNotFound)
			},
			expectedCode: codes.NotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authMock := new(AuthMock)
			tt.mockBehavior(authMock)
			srv := &serverAPI{auth: authMock}

			resp, err := srv.Login(context.Background(), tt.req)

			if tt.expectedCode == codes.OK {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedToken, resp.AccessToken)
				assert.Equal(t, tt.expectedRefreshToken, resp.RefreshToken)
			} else {
				st, ok := status.FromError(err)
				assert.True(t, ok)
				assert.Equal(t, tt.expectedCode, st.Code())
			}
		})
	}
}

func TestRegisterApp(t *testing.T) {
	authMock := new(AuthMock)
	srv := &serverAPI{auth: authMock}
	t.Run("AppExists", func(t *testing.T) {
		authMock.On("RegisterApp", mock.Anything, "ExistingApp").
			Return(0, "", auth.ErrAppExists)

		req := &ssov1.RegisterAppRequest{
			AppName: "ExistingApp",
		}
		_, err := srv.RegisterApp(context.Background(), req)
		st, _ := status.FromError(err)
		assert.Equal(t, codes.AlreadyExists, st.Code())
	})
}
