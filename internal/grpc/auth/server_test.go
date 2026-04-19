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

type AuthMock struct {
	mock.Mock
}

func (m *AuthMock) LoginByEmail(ctx context.Context, email string, password string, appID int64) (token string, err error) {
	args := m.Called(ctx, email, password, appID)
	return args.Get(0).(string), args.Error(1)
}

func (m *AuthMock) LoginByUsername(ctx context.Context, username, password string, appID int64) (token string, err error) {
	args := m.Called(ctx, username, password, appID)
	return args.Get(0).(string), args.Error(1)
}

func (m *AuthMock) DeleteUserByUsername(ctx context.Context, username string, appID int64) error {
	args := m.Called(ctx, username, appID)
	return args.Error(1)
}

func (m *AuthMock) DeleteUserByEmail(ctx context.Context, email string, appID int64) error {
	args := m.Called(ctx, email, appID)
	return args.Error(1)
}

func (m *AuthMock) DeleteUserByUserID(ctx context.Context, userID, appID int64) error {
	args := m.Called(ctx, userID, appID)
	return args.Error(1)
}

func (m *AuthMock) DeleteAdminByUserID(ctx context.Context, appID, userID int64) error {
	args := m.Called(ctx, appID, userID)
	return args.Error(1)
}

func (m *AuthMock) DeleteAdminByEmail(ctx context.Context, appID int64, email string) error {
	args := m.Called(ctx, appID, email)
	return args.Error(1)
}

func (m *AuthMock) DeleteAdminByUsername(ctx context.Context, appID int64, username string) error {
	args := m.Called(ctx, appID, username)
	return args.Error(1)
}

func (m *AuthMock) DeleteApp(ctx context.Context, appID int64) error {
	args := m.Called(ctx, appID)
	return args.Error(1)
}

func (m *AuthMock) Login(ctx context.Context, email, username, password string, appID int64) (string, error) {
	args := m.Called(ctx, email, password, appID)
	return args.String(0), args.Error(1)
}

func (m *AuthMock) RegisterNewUser(ctx context.Context, email, username, password string, appID int64) (int64, error) {
	args := m.Called(ctx, email, username, password, appID)
	return int64(args.Int(0)), args.Error(1)
}

func (m *AuthMock) IsAdmin(ctx context.Context, userID int64, appID int64) (bool, error) {
	args := m.Called(ctx, userID, appID)
	return args.Bool(0), args.Error(1)
}

func (m *AuthMock) RegisterApp(ctx context.Context, appName string) (int64, string, error) {
	args := m.Called(ctx, appName)
	return int64(args.Int(0)), args.String(1), args.Error(2)
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name          string
		req           *ssov1.LoginRequest
		mockBehavior  func(m *AuthMock)
		expectedCode  codes.Code
		expectedToken string
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
				m.On("Login", mock.Anything, "test@example.com", "Password123", int64(1)).
					Return("valid-token", nil)
			},
			expectedCode:  codes.OK,
			expectedToken: "valid-token",
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
				m.On("Login", mock.Anything, "notfound@example.com", "Password123", int64(1)).
					Return("", storage.ErrUserNotFound)
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
				assert.Equal(t, tt.expectedToken, resp.Token)
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
		secret := "1234567890123456" // 16 chars
		authMock.On("RegisterApp", mock.Anything, "ExistingApp", secret).
			Return(0, auth.ErrAppExists)

		req := &ssov1.RegisterAppRequest{
			AppName: "ExistingApp",
		}
		_, err := srv.RegisterApp(context.Background(), req)
		st, _ := status.FromError(err)
		assert.Equal(t, codes.AlreadyExists, st.Code())
	})
}
