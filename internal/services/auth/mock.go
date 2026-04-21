package auth

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
)

type mockStorage struct {
	mock.Mock
}

func (m *mockStorage) UserByUsername(ctx context.Context, username string, appID int64) (models.User, error) {
	args := m.Called(ctx, username, appID)
	return args.Get(0).(models.User), args.Error(1)
}

func (m *mockStorage) UserByEmail(ctx context.Context, email string, appID int64) (models.User, error) {
	args := m.Called(ctx, email, appID)
	return args.Get(0).(models.User), args.Error(1)
}

func (m *mockStorage) DeleteUserByUserID(ctx context.Context, userID int64, appID int64) error {
	args := m.Called(ctx, userID, appID)
	return args.Error(1)
}

func (m *mockStorage) DeleteUserByUsername(ctx context.Context, username string, appID int64) error {
	args := m.Called(ctx, username, appID)
	return args.Error(1)
}

func (m *mockStorage) DeleteUserByEmail(ctx context.Context, email string, appID int64) error {
	args := m.Called(ctx, email, appID)
	return args.Error(1)
}

func (m *mockStorage) DeleteApp(ctx context.Context, appID int64) error {
	args := m.Called(ctx, appID)
	return args.Error(1)
}

func (m *mockStorage) DeleteAdminByUserID(ctx context.Context, userID int64, appID int64) error {
	args := m.Called(ctx, userID, appID)
	return args.Error(1)
}

func (m *mockStorage) DeleteAdminByUsername(ctx context.Context, username string, appID int64) error {
	args := m.Called(ctx, username, appID)
	return args.Error(1)
}

func (m *mockStorage) DeleteAdminByEmail(ctx context.Context, email string, appID int64) error {
	args := m.Called(ctx, email, appID)
	return args.Error(1)
}

func (m *mockStorage) User(ctx context.Context, userID int64, appID int64) (models.User, error) {
	args := m.Called(ctx, userID, appID)
	return args.Get(0).(models.User), args.Error(1)
}

func (m *mockStorage) IsAdmin(ctx context.Context, userID int64, appID int64) (bool, error) {
	args := m.Called(ctx, userID, appID)
	return args.Bool(0), args.Error(1)
}

func (m *mockStorage) SaveUser(ctx context.Context, email string, username string, passHash []byte, appID int64) (int64, error) {
	args := m.Called(ctx, email, username, passHash, appID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockStorage) App(ctx context.Context, appID int64) (models.App, error) {
	args := m.Called(ctx, appID)
	return args.Get(0).(models.App), args.Error(1)
}

func (m *mockStorage) RegisterApp(ctx context.Context, appName string, appSecret string) (appID int64, err error) {
	args := m.Called(ctx, appName)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockStorage) SaveOAuthUser(ctx context.Context, email, username string, appID int64) (usr models.User, err error) {
	args := m.Called(ctx, email, username, appID)
	return args.Get(0).(models.User), args.Error(1)
}

func (m *mockStorage) Emails(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	return args.Get(0).([]string), args.Error(1)
}

func (m *mockStorage) Usernames(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	return args.Get(0).([]string), args.Error(1)
}

type mockRedisStorage struct {
	mock.Mock
}

func (m *mockRedisStorage) SaveRefreshToken(ctx context.Context, token string, userID int64, appID int64, ttl time.Duration) error {
	args := m.Called(ctx, token, userID, appID, ttl)
	return args.Error(0)
}

func (m *mockRedisStorage) SetNewRefreshToken(ctx context.Context, oldToken string, newToken string, ttl time.Duration) error {
	args := m.Called(ctx, oldToken, newToken, ttl)
	return args.Error(0)
}

func (m *mockRedisStorage) GetRefreshTokenFields(ctx context.Context, token string) (*models.RefreshTokenFields, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(*models.RefreshTokenFields), args.Error(1)
}
