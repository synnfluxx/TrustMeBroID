package auth

import (
	"context"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/handlers/discardHandler"
	"golang.org/x/crypto/bcrypt"
)

const (
	tokenTTL = time.Hour
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

func TestAuth_RegisterNewUser_Success(t *testing.T) {
	t.Parallel()
	log := discardHandler.NewDiscardLogger()
	storage := &mockStorage{}
	authService := New(log, storage, storage, storage, storage, storage, tokenTTL)

	app := models.App{
		Name:   gofakeit.Name(),
		Secret: gofakeit.Password(true, true, true, true, false, 16),
		ID:     1,
	}

	var (
		email      = gofakeit.Email()
		pw         = gofakeit.Password(true, true, true, false, false, 32)
		appID      = int64(1)
		expectedID = int64(0)
		username   = gofakeit.Username()
	)

	storage.On("SaveUser",
		mock.Anything,
		email,
		username,
		mock.MatchedBy(func(passHash []byte) bool {
			err := bcrypt.CompareHashAndPassword(passHash, []byte(pw))
			return err == nil
		}),
		appID,
	).Return(expectedID, nil)

	storage.On("App", mock.Anything, appID).Return(app, nil)

	uid, err := authService.RegisterNewUser(context.Background(), email, username, pw, appID)
	assert.NoError(t, err)
	assert.Equal(t, expectedID, uid)
	storage.AssertExpectations(t)
}

func TestAuth_RegisterNewApp_Success(t *testing.T) {
	t.Parallel()
	log := discardHandler.NewDiscardLogger()
	storage := &mockStorage{}
	authService := New(log, storage, storage, storage, storage, storage, tokenTTL)

	var (
		appName    = gofakeit.Name()
		expectedID = int64(0)
	)

	storage.On("RegisterApp",
		mock.Anything,
		appName,
		mock.Anything,
	).Return(expectedID, nil)

	aid, secret, err := authService.RegisterApp(context.Background(), appName)
	assert.NoError(t, err)
	assert.Equal(t, expectedID, aid)
	assert.NotNil(t, secret)
	storage.AssertExpectations(t)
}
