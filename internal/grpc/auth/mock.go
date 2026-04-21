package authgrpc

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type AuthMock struct {
	mock.Mock
}

func (m *AuthMock) LoginByEmail(ctx context.Context, email string, password string, appID int64) (string, string, error) {
	args := m.Called(ctx, email, password, appID)
	return args.Get(0).(string), args.Get(1).(string), args.Error(2)
}

func (m *AuthMock) LoginByUsername(ctx context.Context, username, password string, appID int64) (string, string, error) {
	args := m.Called(ctx, username, password, appID)
	return args.Get(0).(string), args.Get(1).(string), args.Error(2)
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

func (m *AuthMock) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	args := m.Called(ctx, refreshToken)
	return args.String(0), args.Error(1)
}

func (m *AuthMock) UpdateRefreshToken(ctx context.Context, token string) (string, error) {
	args := m.Called(ctx, token)
	return args.String(0), args.Error(1)
}
