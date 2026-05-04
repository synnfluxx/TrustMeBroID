package authgrpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	"github.com/synnfluxx/TrustMeBroID/internal/services/auth"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
	ssov1 "gitlab.com/synnfluxx/protos/sso/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type MockAuth struct {
	mock.Mock
}

func (m *MockAuth) Login(ctx context.Context, identifier models.UserIdentifier, password string, appID int64) (string, string, error) {
	args := m.Called(ctx, identifier, password, appID)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockAuth) RegisterNewUser(ctx context.Context, email, username, password string, appID int64) (int64, error) {
	args := m.Called(ctx, email, username, password, appID)
	return int64(args.Int(0)), args.Error(1)
}

func (m *MockAuth) RefreshToken(ctx context.Context, token string) (string, error) {
	args := m.Called(ctx, token)
	return args.String(0), args.Error(1)
}

func (m *MockAuth) UpdateRefreshToken(ctx context.Context, token string) (string, error) {
	args := m.Called(ctx, token)
	return args.String(0), args.Error(1)
}

func (m *MockAuth) DeleteUser(ctx context.Context, identifier models.UserIdentifier, appID int64) error {
	args := m.Called(ctx, identifier, appID)
	return args.Error(0)
}

func (m *MockAuth) DeleteAdmin(ctx context.Context, identifier models.UserIdentifier, appID int64) error {
	args := m.Called(ctx, identifier, appID)
	return args.Error(0)
} // DON'T TESTED

func (m *MockAuth) DeleteApp(ctx context.Context, appID int64) error {
	args := m.Called(ctx, appID)
	return args.Error(0)
} // DON'T TESTED

func (m *MockAuth) IsAdmin(ctx context.Context, userID, appID int64) (bool, error) {
	args := m.Called(ctx, userID, appID)
	return args.Bool(0), args.Error(1)
} // DON'T TESTED

func (m *MockAuth) MakeAdmin(ctx context.Context, userID, appID int64) (int64, error) {
	args := m.Called(ctx, userID, appID)
	return int64(args.Int(0)), args.Error(1)
} // DON'T TESTED

func (m *MockAuth) RegisterApp(ctx context.Context, name, redirectURI string) (int64, string, error) {
	panic("implement me!")
} // DON'T TESTED

func (m *MockAuth) Logout(ctx context.Context, token string) error {
	panic("implement me")
} // DON'T TESTED

func TestLogin(t *testing.T) {
	tests := []struct {
		name      string
		req       *ssov1.LoginRequest
		mockSetup func(m *MockAuth)
		wantCode  codes.Code
		wantErr   bool
	}{
		{
			name: "success email exact identifier",
			req: &ssov1.LoginRequest{
				AppId: 1,
				Identifier: &ssov1.LoginRequest_Email{
					Email: "test@mail.com",
				},
				Password: "Password1",
			},
			mockSetup: func(m *MockAuth) {
				m.On("Login",
					mock.Anything,
					mock.MatchedBy(func(id models.UserIdentifier) bool {
						return id.Email != nil && *id.Email == "test@mail.com"
					}),
					"Password1",
					int64(1),
				).Return("access", "refresh", nil)
			},
			wantCode: codes.OK,
		},
		{
			name: "success username",
			req: &ssov1.LoginRequest{
				AppId: 1,
				Identifier: &ssov1.LoginRequest_Username{
					Username: "user123",
				},
				Password: "Password1",
			},
			mockSetup: func(m *MockAuth) {
				m.On("Login",
					mock.Anything,
					mock.MatchedBy(func(id models.UserIdentifier) bool {
						return id.Username != nil && *id.Username == "user123"
					}),
					"Password1",
					int64(1),
				).Return("access", "refresh", nil)
			},
			wantCode: codes.OK,
		},
		{
			name: "invalid credentials",
			req: &ssov1.LoginRequest{
				AppId: 1,
				Identifier: &ssov1.LoginRequest_Email{
					Email: "bad@mail.com",
				},
				Password: "Password1",
			},
			mockSetup: func(m *MockAuth) {
				m.On("Login", mock.Anything, mock.Anything, "Password1", int64(1)).
					Return("", "", auth.ErrInvalidCredentials)
			},
			wantCode: codes.NotFound,
			wantErr:  true,
		},
		{
			name: "invalid password format",
			req: &ssov1.LoginRequest{
				AppId: 1,
				Identifier: &ssov1.LoginRequest_Email{
					Email: "test@mail.com",
				},
				Password: "123",
			},
			mockSetup: func(m *MockAuth) {},
			wantCode:  codes.InvalidArgument,
			wantErr:   true,
		},
		{
			name: "missing app_id",
			req: &ssov1.LoginRequest{
				AppId: 0,
			},
			mockSetup: func(m *MockAuth) {},
			wantCode:  codes.InvalidArgument,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := new(MockAuth)
			tt.mockSetup(m)

			s := &serverAPI{auth: m}

			resp, err := s.Login(context.Background(), tt.req)

			if tt.wantErr {
				require.Error(t, err)
				st, _ := status.FromError(err)
				require.Equal(t, tt.wantCode, st.Code())
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			m.AssertExpectations(t)
		})
	}
}

func TestDeleteUser(t *testing.T) {
	tests := []struct {
		name      string
		req       *ssov1.DeleteUserRequest
		mockSetup func(m *MockAuth)
		wantCode  codes.Code
		wantErr   bool
	}{
		{
			name: "delete by email",
			req: &ssov1.DeleteUserRequest{
				AppId: 1,
				Identifier: &ssov1.DeleteUserRequest_Email{
					Email: "test@mail.com",
				},
			},
			mockSetup: func(m *MockAuth) {
				m.On("DeleteUser",
					mock.Anything,
					mock.MatchedBy(func(id models.UserIdentifier) bool {
						return id.Email != nil && *id.Email == "test@mail.com"
					}),
					int64(1),
				).Return(nil)
			},
			wantCode: codes.OK,
		},
		{
			name: "delete by username",
			req: &ssov1.DeleteUserRequest{
				AppId: 1,
				Identifier: &ssov1.DeleteUserRequest_Username{
					Username: "user123",
				},
			},
			mockSetup: func(m *MockAuth) {
				m.On("DeleteUser",
					mock.Anything,
					mock.MatchedBy(func(id models.UserIdentifier) bool {
						return id.Username != nil && *id.Username == "user123"
					}),
					int64(1),
				).Return(nil)
			},
			wantCode: codes.OK,
		},
		{
			name: "delete by userID",
			req: &ssov1.DeleteUserRequest{
				AppId: 1,
				Identifier: &ssov1.DeleteUserRequest_UserId{
					UserId: 42,
				},
			},
			mockSetup: func(m *MockAuth) {
				m.On("DeleteUser",
					mock.Anything,
					mock.MatchedBy(func(id models.UserIdentifier) bool {
						return id.ID != nil && *id.ID == int64(42)
					}),
					int64(1),
				).Return(nil)
			},
			wantCode: codes.OK,
		},
		{
			name: "user not found",
			req: &ssov1.DeleteUserRequest{
				AppId: 1,
				Identifier: &ssov1.DeleteUserRequest_Email{
					Email: "ghost@mail.com",
				},
			},
			mockSetup: func(m *MockAuth) {
				m.On("DeleteUser", mock.Anything, mock.Anything, int64(1)).
					Return(storage.ErrUserNotFound)
			},
			wantCode: codes.InvalidArgument,
			wantErr:  true,
		},
		{
			name: "missing app_id",
			req: &ssov1.DeleteUserRequest{
				AppId: 0,
			},
			mockSetup: func(m *MockAuth) {},
			wantCode:  codes.InvalidArgument,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := new(MockAuth)
			tt.mockSetup(m)

			s := &serverAPI{auth: m}

			_, err := s.DeleteUser(context.Background(), tt.req)

			if tt.wantErr {
				require.Error(t, err)
				st, _ := status.FromError(err)
				require.Equal(t, tt.wantCode, st.Code())
				return
			}

			require.NoError(t, err)

			m.AssertExpectations(t)
		})
	}
}
