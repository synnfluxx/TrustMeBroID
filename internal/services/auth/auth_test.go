package auth

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	discardHandler "github.com/synnfluxx/TrustMeBroID/internal/lib/logger/handlers/discardHandler"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
)

const (
	testAccessTTL  = 3 * time.Minute
	testRefreshTTL = 24 * time.Hour
)

var errRedisDown = errors.New("redis down")

type MockStorage struct {
	mock.Mock
}

func (m *MockStorage) SaveUser(ctx context.Context, email, username string, passHash []byte, appID int64) (int64, error) {
	args := m.Called(ctx, email, username, passHash, appID)
	return int64(args.Int(0)), args.Error(1)
}

func (m *MockStorage) SaveOAuthUser(ctx context.Context, email, username string, appID int64) (models.User, error) {
	args := m.Called(ctx, email, username, appID)
	user, _ := args.Get(0).(models.User)
	return user, args.Error(1)
}

func (m *MockStorage) User(ctx context.Context, userID int64, appID int64) (models.User, error) {
	args := m.Called(ctx, userID, appID)
	user, _ := args.Get(0).(models.User)
	return user, args.Error(1)
}

func (m *MockStorage) IsAdmin(ctx context.Context, userID int64, appID int64) (bool, error) {
	args := m.Called(ctx, userID, appID)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorage) UserByUsername(ctx context.Context, username string, appID int64) (models.User, error) {
	args := m.Called(ctx, username, appID)
	user, _ := args.Get(0).(models.User)
	return user, args.Error(1)
}

func (m *MockStorage) UserByEmail(ctx context.Context, email string, appID int64) (models.User, error) {
	args := m.Called(ctx, email, appID)
	user, _ := args.Get(0).(models.User)
	return user, args.Error(1)
}

func (m *MockStorage) DeleteUserByUserID(ctx context.Context, userID int64, appID int64) error {
	args := m.Called(ctx, userID, appID)
	return args.Error(0)
}

func (m *MockStorage) DeleteUserByUsername(ctx context.Context, username string, appID int64) error {
	args := m.Called(ctx, username, appID)
	return args.Error(0)
}

func (m *MockStorage) DeleteUserByEmail(ctx context.Context, email string, appID int64) error {
	args := m.Called(ctx, email, appID)
	return args.Error(0)
}

func (m *MockStorage) MakeAdmin(ctx context.Context, userID, appID int64) (int64, error) {
	args := m.Called(ctx, userID, appID)
	return int64(args.Int(0)), args.Error(1)
}

func (m *MockStorage) DeleteAdminByUserID(ctx context.Context, userID int64, appID int64) error {
	args := m.Called(ctx, userID, appID)
	return args.Error(0)
}

func (m *MockStorage) DeleteAdminByUsername(ctx context.Context, username string, appID int64) error {
	args := m.Called(ctx, username, appID)
	return args.Error(0)
}

func (m *MockStorage) DeleteAdminByEmail(ctx context.Context, email string, appID int64) error {
	args := m.Called(ctx, email, appID)
	return args.Error(0)
}

func (m *MockStorage) App(ctx context.Context, appID int64) (models.App, error) {
	args := m.Called(ctx, appID)
	app, _ := args.Get(0).(models.App)
	return app, args.Error(1)
}

func (m *MockStorage) RegisterApp(ctx context.Context, appName string, appSecret, redirectURI string) (int64, error) {
	args := m.Called(ctx, appName, appSecret, redirectURI)
	return int64(args.Int(0)), args.Error(1)
}

func (m *MockStorage) DeleteApp(ctx context.Context, appID int64) error {
	args := m.Called(ctx, appID)
	return args.Error(0)
}

type MockJWTProvider struct {
	mock.Mock
}

func (m *MockJWTProvider) SaveRefreshToken(ctx context.Context, token string, userID int64, appID int64, ttl time.Duration) error {
	args := m.Called(ctx, token, userID, appID, ttl)
	return args.Error(0)
}

func (m *MockJWTProvider) SetNewRefreshToken(ctx context.Context, oldToken string, newToken string, ttl time.Duration) error {
	args := m.Called(ctx, oldToken, newToken, ttl)
	return args.Error(0)
}

func (m *MockJWTProvider) GetRefreshTokenFields(ctx context.Context, token string) (*models.RefreshTokenFields, error) {
	args := m.Called(ctx, token)
	fields, _ := args.Get(0).(*models.RefreshTokenFields)
	return fields, args.Error(1)
}

func (m *MockJWTProvider) Logout(ctx context.Context, token string) error {
	panic("implement me!")
} // DON'T TESTED

type MockPasswordVerifier struct {
	mock.Mock
}

func (m *MockPasswordVerifier) Compare(hash []byte, pw []byte) error {
	args := m.Called(hash, pw)
	return args.Error(0)
}

func newTestAuth() (*Auth, *MockStorage, *MockJWTProvider, *MockPasswordVerifier) {
	storageMock := new(MockStorage)
	jwtMock := new(MockJWTProvider)
	pwMock := new(MockPasswordVerifier)

	authService := New(
		discardHandler.NewDiscardLogger(),
		storageMock,
		storageMock,
		storageMock,
		storageMock,
		jwtMock,
		pwMock,
		testAccessTTL,
		testRefreshTTL,
	)

	return authService, storageMock, jwtMock, pwMock
}

func TestAuthLogin(t *testing.T) {
	testUser := models.User{ID: 42, Email: "test@mail.com", PassHash: []byte("hash")}
	testApp := models.App{ID: 7, Secret: "secret"}

	tests := []struct {
		name      string
		identifier models.UserIdentifier
		password  string
		appID     int64
		mockSetup func(s *MockStorage, j *MockJWTProvider, p *MockPasswordVerifier)
		wantErr   error
	}{
		{
			name: "success by email",
			identifier: models.UserIdentifier{
				Email: strPtr("test@mail.com"),
			},
			password: "Password1",
			appID:    7,
			mockSetup: func(s *MockStorage, j *MockJWTProvider, p *MockPasswordVerifier) {
				s.On("UserByEmail", mock.Anything, "test@mail.com", int64(7)).Return(testUser, nil)
				p.On("Compare", testUser.PassHash, []byte("Password1")).Return(nil)
				s.On("App", mock.Anything, int64(7)).Return(testApp, nil)
				j.On("SaveRefreshToken", mock.Anything, mock.AnythingOfType("string"), int64(42), int64(7), testRefreshTTL).Return(nil)
			},
		},
		{
			name: "success by username",
			identifier: models.UserIdentifier{
				Username: strPtr("user123"),
			},
			password: "Password1",
			appID:    7,
			mockSetup: func(s *MockStorage, j *MockJWTProvider, p *MockPasswordVerifier) {
				s.On("UserByUsername", mock.Anything, "user123", int64(7)).Return(testUser, nil)
				p.On("Compare", testUser.PassHash, []byte("Password1")).Return(nil)
				s.On("App", mock.Anything, int64(7)).Return(testApp, nil)
				j.On("SaveRefreshToken", mock.Anything, mock.AnythingOfType("string"), int64(42), int64(7), testRefreshTTL).Return(nil)
			},
		},
		{
			name: "invalid identifier",
			identifier: models.UserIdentifier{},
			password:   "Password1",
			appID:      7,
			mockSetup:  func(s *MockStorage, j *MockJWTProvider, p *MockPasswordVerifier) {},
			wantErr:    ErrInvalidIdentifier,
		},
		{
			name: "user not found becomes invalid credentials",
			identifier: models.UserIdentifier{
				Email: strPtr("missing@mail.com"),
			},
			password: "Password1",
			appID:    7,
			mockSetup: func(s *MockStorage, j *MockJWTProvider, p *MockPasswordVerifier) {
				s.On("UserByEmail", mock.Anything, "missing@mail.com", int64(7)).Return(models.User{}, storage.ErrUserNotFound)
			},
			wantErr: ErrInvalidCredentials,
		},
		{
			name: "password mismatch",
			identifier: models.UserIdentifier{
				Email: strPtr("test@mail.com"),
			},
			password: "Password1",
			appID:    7,
			mockSetup: func(s *MockStorage, j *MockJWTProvider, p *MockPasswordVerifier) {
				s.On("UserByEmail", mock.Anything, "test@mail.com", int64(7)).Return(testUser, nil)
				p.On("Compare", testUser.PassHash, []byte("Password1")).Return(errors.New("bad password"))
			},
			wantErr: ErrInvalidCredentials,
		},
		{
			name: "save refresh token failure",
			identifier: models.UserIdentifier{
				Email: strPtr("test@mail.com"),
			},
			password: "Password1",
			appID:    7,
			mockSetup: func(s *MockStorage, j *MockJWTProvider, p *MockPasswordVerifier) {
				s.On("UserByEmail", mock.Anything, "test@mail.com", int64(7)).Return(testUser, nil)
				p.On("Compare", testUser.PassHash, []byte("Password1")).Return(nil)
				s.On("App", mock.Anything, int64(7)).Return(testApp, nil)
				j.On("SaveRefreshToken", mock.Anything, mock.AnythingOfType("string"), int64(42), int64(7), testRefreshTTL).Return(errRedisDown)
			},
			wantErr: errRedisDown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService, storageMock, jwtMock, pwMock := newTestAuth()
			tt.mockSetup(storageMock, jwtMock, pwMock)

			accessToken, refreshToken, err := authService.Login(context.Background(), tt.identifier, tt.password, tt.appID)

			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, accessToken)
			require.NotEmpty(t, refreshToken)
			storageMock.AssertExpectations(t)
			jwtMock.AssertExpectations(t)
			pwMock.AssertExpectations(t)
		})
	}
}

func TestAuthRegisterNewUser(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		username  string
		password  string
		appID     int64
		mockSetup func(s *MockStorage)
		wantID    int64
		wantErr   error
	}{
		{
			name:     "success",
			email:    "test@mail.com",
			username: "user123",
			password: "Password1",
			appID:    1,
			mockSetup: func(s *MockStorage) {
				s.On("App", mock.Anything, int64(1)).Return(models.App{ID: 1}, nil)
				s.On("SaveUser", mock.Anything, "test@mail.com", "user123", mock.AnythingOfType("[]uint8"), int64(1)).Return(11, nil)
			},
			wantID: 11,
		},
		{
			name:     "app not found",
			email:    "test@mail.com",
			username: "user123",
			password: "Password1",
			appID:    1,
			mockSetup: func(s *MockStorage) {
				s.On("App", mock.Anything, int64(1)).Return(models.App{}, storage.ErrAppNotFound)
			},
			wantErr: storage.ErrAppNotFound,
		},
		{
			name:     "user exists",
			email:    "test@mail.com",
			username: "user123",
			password: "Password1",
			appID:    1,
			mockSetup: func(s *MockStorage) {
				s.On("App", mock.Anything, int64(1)).Return(models.App{ID: 1}, nil)
				s.On("SaveUser", mock.Anything, "test@mail.com", "user123", mock.AnythingOfType("[]uint8"), int64(1)).Return(0, storage.ErrUserExists)
			},
			wantErr: ErrUserExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService, storageMock, _, _ := newTestAuth()
			tt.mockSetup(storageMock)

			id, err := authService.RegisterNewUser(context.Background(), tt.email, tt.username, tt.password, tt.appID)

			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantID, id)
			storageMock.AssertExpectations(t)
		})
	}
}

func TestAuthDeleteUser(t *testing.T) {
	tests := []struct {
		name       string
		identifier models.UserIdentifier
		appID      int64
		mockSetup  func(s *MockStorage)
		wantErr    error
	}{
		{
			name: "delete by user id",
			identifier: models.UserIdentifier{
				ID: int64Ptr(42),
			},
			appID: 1,
			mockSetup: func(s *MockStorage) {
				s.On("DeleteUserByUserID", mock.Anything, int64(42), int64(1)).Return(nil)
			},
		},
		{
			name: "not found",
			identifier: models.UserIdentifier{
				Email: strPtr("missing@mail.com"),
			},
			appID: 1,
			mockSetup: func(s *MockStorage) {
				s.On("DeleteUserByEmail", mock.Anything, "missing@mail.com", int64(1)).Return(storage.ErrUserNotFound)
			},
			wantErr: ErrUserNotFound,
		},
		{
			name:       "invalid identifier",
			identifier: models.UserIdentifier{},
			appID:      1,
			mockSetup:  func(s *MockStorage) {},
			wantErr:    ErrInvalidIdentifier,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService, storageMock, _, _ := newTestAuth()
			tt.mockSetup(storageMock)

			err := authService.DeleteUser(context.Background(), tt.identifier, tt.appID)

			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			storageMock.AssertExpectations(t)
		})
	}
}

func TestAuthRegisterApp(t *testing.T) {
	prevKey := os.Getenv("MASTER_KEY")
	require.NoError(t, os.Setenv("MASTER_KEY", "12345678901234567890123456789012"))
	t.Cleanup(func() {
		_ = os.Setenv("MASTER_KEY", prevKey)
	})

	tests := []struct {
		name      string
		appName   string
		redirect  string
		mockSetup func(s *MockStorage)
		wantErr   error
	}{
		{
			name:     "success",
			appName:  "dashboard",
			redirect: "http://localhost:3000/callback",
			mockSetup: func(s *MockStorage) {
				s.On("RegisterApp", mock.Anything, "dashboard", mock.AnythingOfType("string"), "http://localhost:3000/callback").
					Return(9, nil)
			},
		},
		{
			name:     "app exists",
			appName:  "dashboard",
			redirect: "http://localhost:3000/callback",
			mockSetup: func(s *MockStorage) {
				s.On("RegisterApp", mock.Anything, "dashboard", mock.AnythingOfType("string"), "http://localhost:3000/callback").
					Return(0, storage.ErrAppExists)
			},
			wantErr: ErrAppExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService, storageMock, _, _ := newTestAuth()
			tt.mockSetup(storageMock)

			id, secret, err := authService.RegisterApp(context.Background(), tt.appName, tt.redirect)

			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, int64(9), id)
			require.NotEmpty(t, secret)
			storageMock.AssertExpectations(t)
		})
	}
}

func TestAuthRefreshToken(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		mockSetup func(s *MockStorage, j *MockJWTProvider)
		wantErr   error
	}{
		{
			name:  "success from app provider",
			token: "refresh-token",
			mockSetup: func(s *MockStorage, j *MockJWTProvider) {
				j.On("GetRefreshTokenFields", mock.Anything, "refresh-token").
					Return(&models.RefreshTokenFields{UserID: 42, AppId: 7}, nil)
				s.On("App", mock.Anything, int64(7)).
					Return(models.App{ID: 7, Secret: "secret"}, nil)
			},
		},
		{
			name:  "token not found",
			token: "missing-token",
			mockSetup: func(s *MockStorage, j *MockJWTProvider) {
				j.On("GetRefreshTokenFields", mock.Anything, "missing-token").
					Return((*models.RefreshTokenFields)(nil), storage.ErrTokenNotFound)
			},
			wantErr: storage.ErrTokenNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService, storageMock, jwtMock, _ := newTestAuth()
			tt.mockSetup(storageMock, jwtMock)

			token, err := authService.RefreshToken(context.Background(), tt.token)

			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, token)
			storageMock.AssertExpectations(t)
			jwtMock.AssertExpectations(t)
		})
	}
}

func strPtr(s string) *string {
	return &s
}

func int64Ptr(v int64) *int64 {
	return &v
}
