package auth

import (
	"context"
	"database/sql"
	"errors"
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

// argInt64 reads a mock return as int64 whether the test supplied an int or an
// int64. testify's args.Int panics on an int64, which is the type every id in
// this service actually has.
func argInt64(args mock.Arguments, index int) int64 {
	switch v := args.Get(index).(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case nil:
		return 0
	default:
		panic("unexpected id type in mock return")
	}
}

type MockStorage struct {
	mock.Mock
}

func (m *MockStorage) SaveUser(ctx context.Context, email, username string, passHash []byte, appID int64, verificationCode string) (int64, error) {
	args := m.Called(ctx, email, username, passHash, appID, verificationCode)
	return argInt64(args, 0), args.Error(1)
}

func (m *MockStorage) VerifyUser(ctx context.Context, email string, appID int64) error {
	args := m.Called(ctx, email, appID)
	return args.Error(0)
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
	return argInt64(args, 0), args.Error(1)
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
	return argInt64(args, 0), args.Error(1)
}

func (m *MockStorage) DeleteApp(ctx context.Context, appID int64) error {
	args := m.Called(ctx, appID)
	return args.Error(0)
}

func (m *MockStorage) UpdateVerificationToken(ctx context.Context, email string, appID int64, newToken string) error {
	args := m.Called(ctx, email, appID, newToken)
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
	args := m.Called(ctx, token)
	return args.Error(0)
}

type MockPasswordVerifier struct {
	mock.Mock
}

// MockEmailService stands in for the SMTP sender. Registration calls it on the
// success path, so it cannot be nil even in tests that never assert on it.
type MockEmailService struct {
	mock.Mock
}

func (m *MockEmailService) SendVerificationEmail(email, verificationToken string, url string) error {
	if len(m.ExpectedCalls) == 0 {
		return nil
	}
	args := m.Called(email, verificationToken, url)
	return args.Error(0)
}

func (m *MockPasswordVerifier) Compare(hash []byte, pw []byte) error {
	args := m.Called(hash, pw)
	return args.Error(0)
}

func newTestAuth() (*Auth, *MockStorage, *MockJWTProvider, *MockPasswordVerifier, *MockEmailService) {
	storageMock := new(MockStorage)
	jwtMock := new(MockJWTProvider)
	pwMock := new(MockPasswordVerifier)
	emailMock := new(MockEmailService)

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
		emailMock,
	)

	return authService, storageMock, jwtMock, pwMock, emailMock
}

// verifiedUser is the shape Login requires: without IsVerified the service
// refuses the login regardless of the password.
func verifiedUser(id int64) models.User {
	return models.User{
		ID:         id,
		Email:      "test@mail.com",
		Username:   "user123",
		PassHash:   []byte("hash"),
		IsVerified: true,
	}
}

func strPtr(s string) *string { return &s }
func i64Ptr(i int64) *int64   { return &i }

// withMasterKey installs a valid AES key for the duration of a test.
// RegisterApp reads MASTER_KEY from the process environment rather than from
// config, so it cannot be injected any other way.
func withMasterKey(t *testing.T) {
	t.Helper()
	t.Setenv("MASTER_KEY", "12345678901234567890123456789012")
}

// ---------------------------------------------------------------- Login ----

func TestLogin_SuccessByEachIdentifier(t *testing.T) {
	app := models.App{ID: 7, Secret: "app-secret"}

	cases := []struct {
		name       string
		identifier models.UserIdentifier
		expect     func(s *MockStorage)
	}{
		{
			name:       "by email",
			identifier: models.UserIdentifier{Email: strPtr("test@mail.com")},
			expect: func(s *MockStorage) {
				s.On("UserByEmail", mock.Anything, "test@mail.com", int64(7)).Return(verifiedUser(42), nil)
			},
		},
		{
			name:       "by username",
			identifier: models.UserIdentifier{Username: strPtr("user123")},
			expect: func(s *MockStorage) {
				s.On("UserByUsername", mock.Anything, "user123", int64(7)).Return(verifiedUser(42), nil)
			},
		},
		{
			name:       "by user id",
			identifier: models.UserIdentifier{ID: i64Ptr(42)},
			expect: func(s *MockStorage) {
				s.On("User", mock.Anything, int64(42), int64(7)).Return(verifiedUser(42), nil)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, storageMock, jwtMock, pwMock, _ := newTestAuth()
			tc.expect(storageMock)
			pwMock.On("Compare", []byte("hash"), []byte("Password1")).Return(nil)
			storageMock.On("App", mock.Anything, int64(7)).Return(app, nil)
			jwtMock.On("SaveRefreshToken", mock.Anything, mock.AnythingOfType("string"), int64(42), int64(7), testRefreshTTL).Return(nil)

			access, refresh, err := svc.Login(context.Background(), tc.identifier, "Password1", 7)

			require.NoError(t, err)
			require.NotEmpty(t, access)
			require.NotEmpty(t, refresh)
			require.NotEqual(t, access, refresh, "access and refresh tokens must not be identical")
			storageMock.AssertExpectations(t)
			jwtMock.AssertExpectations(t)
		})
	}
}

func TestLogin_Rejections(t *testing.T) {
	app := models.App{ID: 7, Secret: "app-secret"}

	cases := []struct {
		name    string
		setup   func(s *MockStorage, p *MockPasswordVerifier)
		wantErr error
	}{
		{
			name: "unknown account is reported as invalid credentials",
			setup: func(s *MockStorage, _ *MockPasswordVerifier) {
				s.On("UserByEmail", mock.Anything, "test@mail.com", int64(7)).
					Return(models.User{}, storage.ErrUserNotFound)
			},
			wantErr: ErrInvalidCredentials,
		},
		{
			// A soft-deleted account must not be distinguishable from a
			// missing one in the response.
			name: "soft-deleted account is reported as invalid credentials",
			setup: func(s *MockStorage, _ *MockPasswordVerifier) {
				s.On("UserByEmail", mock.Anything, "test@mail.com", int64(7)).
					Return(models.User{}, storage.ErrUserDeleted)
			},
			wantErr: ErrInvalidCredentials,
		},
		{
			name: "wrong password",
			setup: func(s *MockStorage, p *MockPasswordVerifier) {
				s.On("UserByEmail", mock.Anything, "test@mail.com", int64(7)).Return(verifiedUser(42), nil)
				p.On("Compare", []byte("hash"), []byte("Password1")).Return(errors.New("mismatch"))
			},
			wantErr: ErrInvalidCredentials,
		},
		{
			name: "unverified account",
			setup: func(s *MockStorage, p *MockPasswordVerifier) {
				user := verifiedUser(42)
				user.IsVerified = false
				s.On("UserByEmail", mock.Anything, "test@mail.com", int64(7)).Return(user, nil)
				p.On("Compare", []byte("hash"), []byte("Password1")).Return(nil)
			},
			wantErr: ErrUserNotVerified,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, storageMock, _, pwMock, _ := newTestAuth()
			tc.setup(storageMock, pwMock)
			_ = app

			access, refresh, err := svc.Login(context.Background(), models.UserIdentifier{Email: strPtr("test@mail.com")}, "Password1", 7)

			require.ErrorIs(t, err, tc.wantErr)
			require.Empty(t, access)
			require.Empty(t, refresh)
			storageMock.AssertExpectations(t)
		})
	}
}

// The verification check must run before any token is signed, otherwise an
// unverified account briefly gets a usable session.
func TestLogin_UnverifiedNeverReachesTokenIssue(t *testing.T) {
	svc, storageMock, jwtMock, pwMock, _ := newTestAuth()

	user := verifiedUser(42)
	user.IsVerified = false
	storageMock.On("UserByEmail", mock.Anything, "test@mail.com", int64(7)).Return(user, nil)
	pwMock.On("Compare", mock.Anything, mock.Anything).Return(nil)

	_, _, err := svc.Login(context.Background(), models.UserIdentifier{Email: strPtr("test@mail.com")}, "Password1", 7)

	require.ErrorIs(t, err, ErrUserNotVerified)
	jwtMock.AssertNotCalled(t, "SaveRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	storageMock.AssertNotCalled(t, "App", mock.Anything, mock.Anything)
}

func TestLogin_NoIdentifier(t *testing.T) {
	svc, _, _, _, _ := newTestAuth()

	_, _, err := svc.Login(context.Background(), models.UserIdentifier{}, "Password1", 7)

	require.ErrorIs(t, err, ErrInvalidIdentifier)
}

func TestLogin_LookupErrorIsNotMaskedAsBadCredentials(t *testing.T) {
	svc, storageMock, _, _, _ := newTestAuth()
	dbDown := errors.New("connection refused")
	storageMock.On("UserByEmail", mock.Anything, "test@mail.com", int64(7)).Return(models.User{}, dbDown)

	_, _, err := svc.Login(context.Background(), models.UserIdentifier{Email: strPtr("test@mail.com")}, "Password1", 7)

	require.ErrorIs(t, err, dbDown)
	require.NotErrorIs(t, err, ErrInvalidCredentials)
}

func TestLogin_RefreshTokenNotPersisted(t *testing.T) {
	svc, storageMock, jwtMock, pwMock, _ := newTestAuth()

	storageMock.On("UserByEmail", mock.Anything, "test@mail.com", int64(7)).Return(verifiedUser(42), nil)
	pwMock.On("Compare", mock.Anything, mock.Anything).Return(nil)
	storageMock.On("App", mock.Anything, int64(7)).Return(models.App{ID: 7, Secret: "s"}, nil)
	jwtMock.On("SaveRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errRedisDown)

	_, _, err := svc.Login(context.Background(), models.UserIdentifier{Email: strPtr("test@mail.com")}, "Password1", 7)

	require.ErrorIs(t, err, errRedisDown)
}

func TestLogin_AppLookupFailure(t *testing.T) {
	svc, storageMock, _, pwMock, _ := newTestAuth()

	storageMock.On("UserByEmail", mock.Anything, "test@mail.com", int64(7)).Return(verifiedUser(42), nil)
	pwMock.On("Compare", mock.Anything, mock.Anything).Return(nil)
	storageMock.On("App", mock.Anything, int64(7)).Return(models.App{}, storage.ErrAppNotFound)

	_, _, err := svc.Login(context.Background(), models.UserIdentifier{Email: strPtr("test@mail.com")}, "Password1", 7)

	require.ErrorIs(t, err, storage.ErrAppNotFound)
}

// --------------------------------------------------------------- Logout ----

func TestLogout(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, _, jwtMock, _, _ := newTestAuth()
		jwtMock.On("Logout", mock.Anything, "refresh-token").Return(nil)

		require.NoError(t, svc.Logout(context.Background(), "refresh-token"))
		jwtMock.AssertExpectations(t)
	})

	t.Run("token not found is surfaced", func(t *testing.T) {
		svc, _, jwtMock, _, _ := newTestAuth()
		jwtMock.On("Logout", mock.Anything, "gone").Return(storage.ErrTokenNotFound)

		require.ErrorIs(t, svc.Logout(context.Background(), "gone"), storage.ErrTokenNotFound)
	})
}

// ------------------------------------------------------------- Register ----

func TestRegisterNewUser_Success(t *testing.T) {
	svc, storageMock, _, _, emailMock := newTestAuth()

	app := models.App{ID: 1, Secret: "s", RedirectURI: "https://example.test"}
	storageMock.On("App", mock.Anything, int64(1)).Return(app, nil)
	storageMock.On("SaveUser", mock.Anything, "test@mail.com", "user123",
		mock.AnythingOfType("[]uint8"), int64(1), mock.AnythingOfType("string")).Return(int64(99), nil)
	emailMock.On("SendVerificationEmail", "test@mail.com", mock.AnythingOfType("string"), "https://example.test").Return(nil)

	id, err := svc.RegisterNewUser(context.Background(), "test@mail.com", "user123", "Password1", 1)

	require.NoError(t, err)
	require.Equal(t, int64(99), id)
	storageMock.AssertExpectations(t)
	emailMock.AssertExpectations(t)
}

// The verification code written to the database must be the same one that goes
// into the email, or the link can never validate.
func TestRegisterNewUser_StoredCodeMatchesEmailedCode(t *testing.T) {
	svc, storageMock, _, _, emailMock := newTestAuth()

	var stored, emailed string
	storageMock.On("App", mock.Anything, int64(1)).Return(models.App{ID: 1, RedirectURI: "https://example.test"}, nil)
	storageMock.On("SaveUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { stored = args.String(5) }).Return(int64(1), nil)
	emailMock.On("SendVerificationEmail", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { emailed = args.String(1) }).Return(nil)

	_, err := svc.RegisterNewUser(context.Background(), "test@mail.com", "user123", "Password1", 1)

	require.NoError(t, err)
	require.NotEmpty(t, stored)
	require.Equal(t, stored, emailed, "the emailed code must match the stored one")
}

func TestRegisterNewUser_PasswordIsHashedNotStored(t *testing.T) {
	svc, storageMock, _, _, emailMock := newTestAuth()

	var hash []byte
	storageMock.On("App", mock.Anything, int64(1)).Return(models.App{ID: 1}, nil)
	storageMock.On("SaveUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { hash = args.Get(3).([]byte) }).Return(int64(1), nil)
	emailMock.On("SendVerificationEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	_, err := svc.RegisterNewUser(context.Background(), "test@mail.com", "user123", "Password1", 1)

	require.NoError(t, err)
	require.NotEqual(t, "Password1", string(hash))
	require.True(t, len(hash) > 0)
	require.Contains(t, string(hash[:4]), "$2a", "expected a bcrypt hash")
}

func TestRegisterNewUser_Failures(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(s *MockStorage, e *MockEmailService)
		wantErr error
	}{
		{
			name: "unknown application",
			setup: func(s *MockStorage, _ *MockEmailService) {
				s.On("App", mock.Anything, int64(1)).Return(models.App{}, storage.ErrAppNotFound)
			},
			wantErr: storage.ErrAppNotFound,
		},
		{
			name: "duplicate account",
			setup: func(s *MockStorage, _ *MockEmailService) {
				s.On("App", mock.Anything, int64(1)).Return(models.App{ID: 1}, nil)
				s.On("SaveUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(int64(0), storage.ErrUserExists)
			},
			wantErr: ErrUserExists,
		},
		{
			// The account row is already committed at this point, so the
			// caller sees a failed registration for an account that exists.
			name: "email delivery failure",
			setup: func(s *MockStorage, e *MockEmailService) {
				s.On("App", mock.Anything, int64(1)).Return(models.App{ID: 1}, nil)
				s.On("SaveUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(int64(5), nil)
				e.On("SendVerificationEmail", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("smtp down"))
			},
			wantErr: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, storageMock, _, _, emailMock := newTestAuth()
			tc.setup(storageMock, emailMock)

			id, err := svc.RegisterNewUser(context.Background(), "test@mail.com", "user123", "Password1", 1)

			require.Error(t, err)
			require.Zero(t, id)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			}
			storageMock.AssertExpectations(t)
		})
	}
}

// ------------------------------------------------------------ Verify -------

func TestVerifyUserEmail(t *testing.T) {
	recent := sql.NullTime{Time: time.Now().Add(-time.Hour), Valid: true}
	stale := sql.NullTime{Time: time.Now().Add(-100 * time.Hour), Valid: true}
	app := models.App{ID: 1, Secret: "app-secret"}

	// Confirming proves ownership of the account, so it ends in a session.
	t.Run("confirms and issues a session", func(t *testing.T) {
		svc, storageMock, jwtMock, _, _ := newTestAuth()
		storageMock.On("UserByEmail", mock.Anything, "a@b.c", int64(1)).Return(models.User{
			ID: 3, VerificationCode: "code", LastTokenGeneratedTime: recent,
		}, nil)
		storageMock.On("VerifyUser", mock.Anything, "a@b.c", int64(1)).Return(nil)
		storageMock.On("App", mock.Anything, int64(1)).Return(app, nil)
		jwtMock.On("SaveRefreshToken", mock.Anything, mock.AnythingOfType("string"), int64(3), int64(1), testRefreshTTL).Return(nil)

		access, refresh, err := svc.VerifyUserEmail(context.Background(), "a@b.c", "code", 1)

		require.NoError(t, err)
		require.NotEmpty(t, access)
		require.NotEmpty(t, refresh)
		storageMock.AssertExpectations(t)
		jwtMock.AssertExpectations(t)
	})

	// The response is now a session, so a path that skipped the code check
	// would hand one to anyone who knows a registered address.
	t.Run("an already verified account still has to present the code", func(t *testing.T) {
		svc, storageMock, jwtMock, _, _ := newTestAuth()
		storageMock.On("UserByEmail", mock.Anything, "a@b.c", int64(1)).Return(models.User{
			ID: 3, IsVerified: true, VerificationCode: "expected", LastTokenGeneratedTime: recent,
		}, nil)

		access, refresh, err := svc.VerifyUserEmail(context.Background(), "a@b.c", "guessed", 1)

		require.ErrorIs(t, err, ErrInvalidCredentials)
		require.Empty(t, access)
		require.Empty(t, refresh)
		jwtMock.AssertNotCalled(t, "SaveRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a correct code on an already verified account is idempotent", func(t *testing.T) {
		svc, storageMock, jwtMock, _, _ := newTestAuth()
		storageMock.On("UserByEmail", mock.Anything, "a@b.c", int64(1)).Return(models.User{
			ID: 3, IsVerified: true, VerificationCode: "code", LastTokenGeneratedTime: recent,
		}, nil)
		storageMock.On("App", mock.Anything, int64(1)).Return(app, nil)
		jwtMock.On("SaveRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

		access, _, err := svc.VerifyUserEmail(context.Background(), "a@b.c", "code", 1)

		require.NoError(t, err)
		require.NotEmpty(t, access)
		// Nothing to write: the row is already marked verified.
		storageMock.AssertNotCalled(t, "VerifyUser", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("wrong code", func(t *testing.T) {
		svc, storageMock, jwtMock, _, _ := newTestAuth()
		storageMock.On("UserByEmail", mock.Anything, "a@b.c", int64(1)).Return(models.User{
			VerificationCode: "expected", LastTokenGeneratedTime: recent,
		}, nil)

		_, _, err := svc.VerifyUserEmail(context.Background(), "a@b.c", "presented", 1)

		require.ErrorIs(t, err, ErrInvalidCredentials)
		storageMock.AssertNotCalled(t, "VerifyUser", mock.Anything, mock.Anything, mock.Anything)
		jwtMock.AssertNotCalled(t, "SaveRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("expired code, checked before the code itself", func(t *testing.T) {
		svc, storageMock, _, _, _ := newTestAuth()
		storageMock.On("UserByEmail", mock.Anything, "a@b.c", int64(1)).Return(models.User{
			VerificationCode: "expected", LastTokenGeneratedTime: stale,
		}, nil)

		_, _, err := svc.VerifyUserEmail(context.Background(), "a@b.c", "wrong-too", 1)

		require.ErrorIs(t, err, ErrVerificationTokenExpired)
	})

	t.Run("unknown address", func(t *testing.T) {
		svc, storageMock, _, _, _ := newTestAuth()
		storageMock.On("UserByEmail", mock.Anything, "a@b.c", int64(1)).Return(models.User{}, storage.ErrUserNotFound)

		_, _, err := svc.VerifyUserEmail(context.Background(), "a@b.c", "code", 1)

		require.ErrorIs(t, err, ErrUserNotFound)
	})

	t.Run("missing issue timestamp does not enforce expiry", func(t *testing.T) {
		svc, storageMock, jwtMock, _, _ := newTestAuth()
		storageMock.On("UserByEmail", mock.Anything, "a@b.c", int64(1)).Return(models.User{
			ID: 3, VerificationCode: "code", LastTokenGeneratedTime: sql.NullTime{},
		}, nil)
		storageMock.On("VerifyUser", mock.Anything, "a@b.c", int64(1)).Return(nil)
		storageMock.On("App", mock.Anything, int64(1)).Return(app, nil)
		jwtMock.On("SaveRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

		_, _, err := svc.VerifyUserEmail(context.Background(), "a@b.c", "code", 1)

		require.NoError(t, err)
	})

	// The address is confirmed even when the session cannot be created, so the
	// caller must not be told the confirmation failed outright.
	t.Run("account is marked verified even if the session cannot be issued", func(t *testing.T) {
		svc, storageMock, jwtMock, _, _ := newTestAuth()
		storageMock.On("UserByEmail", mock.Anything, "a@b.c", int64(1)).Return(models.User{
			ID: 3, VerificationCode: "code", LastTokenGeneratedTime: recent,
		}, nil)
		storageMock.On("VerifyUser", mock.Anything, "a@b.c", int64(1)).Return(nil)
		storageMock.On("App", mock.Anything, int64(1)).Return(app, nil)
		jwtMock.On("SaveRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errRedisDown)

		_, _, err := svc.VerifyUserEmail(context.Background(), "a@b.c", "code", 1)

		require.ErrorIs(t, err, errRedisDown)
		storageMock.AssertCalled(t, "VerifyUser", mock.Anything, "a@b.c", int64(1))
	})
}

func TestGenerateNewVerificationToken(t *testing.T) {
	t.Run("rotates the code and mails the new one", func(t *testing.T) {
		svc, storageMock, _, _, emailMock := newTestAuth()

		var rotated, emailed string
		storageMock.On("UserByEmail", mock.Anything, "a@b.c", int64(1)).Return(models.User{ID: 3}, nil)
		storageMock.On("App", mock.Anything, int64(1)).Return(models.App{ID: 1, RedirectURI: "https://example.test"}, nil)
		storageMock.On("UpdateVerificationToken", mock.Anything, "a@b.c", int64(1), mock.AnythingOfType("string")).
			Run(func(args mock.Arguments) { rotated = args.String(3) }).Return(nil)
		emailMock.On("SendVerificationEmail", "a@b.c", mock.AnythingOfType("string"), "https://example.test").
			Run(func(args mock.Arguments) { emailed = args.String(1) }).Return(nil)

		require.NoError(t, svc.GenerateNewVerificationToken(context.Background(), "a@b.c", 1))
		require.NotEmpty(t, rotated)
		require.Equal(t, rotated, emailed)
		storageMock.AssertExpectations(t)
	})

	t.Run("unknown address", func(t *testing.T) {
		svc, storageMock, _, _, _ := newTestAuth()
		storageMock.On("UserByEmail", mock.Anything, "a@b.c", int64(1)).Return(models.User{}, storage.ErrUserNotFound)

		require.ErrorIs(t, svc.GenerateNewVerificationToken(context.Background(), "a@b.c", 1), ErrUserNotFound)
	})

	t.Run("unknown application", func(t *testing.T) {
		svc, storageMock, _, _, _ := newTestAuth()
		storageMock.On("UserByEmail", mock.Anything, "a@b.c", int64(1)).Return(models.User{ID: 3}, nil)
		storageMock.On("App", mock.Anything, int64(1)).Return(models.App{}, storage.ErrAppNotFound)

		require.ErrorIs(t, svc.GenerateNewVerificationToken(context.Background(), "a@b.c", 1), storage.ErrAppNotFound)
	})

	t.Run("delivery failure leaves the old code already invalidated", func(t *testing.T) {
		// Documents a real ordering hazard: the code is rotated before the
		// send, so a failed send leaves the user with no working link at all.
		svc, storageMock, _, _, emailMock := newTestAuth()
		storageMock.On("UserByEmail", mock.Anything, "a@b.c", int64(1)).Return(models.User{ID: 3}, nil)
		storageMock.On("App", mock.Anything, int64(1)).Return(models.App{ID: 1}, nil)
		storageMock.On("UpdateVerificationToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
		emailMock.On("SendVerificationEmail", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("smtp down"))

		require.Error(t, svc.GenerateNewVerificationToken(context.Background(), "a@b.c", 1))
		storageMock.AssertCalled(t, "UpdateVerificationToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

// ---------------------------------------------------------- Admin rights ----

func TestMakeAdmin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, storageMock, _, _, _ := newTestAuth()
		storageMock.On("MakeAdmin", mock.Anything, int64(42), int64(1)).Return(int64(9), nil)

		uid, err := svc.MakeAdmin(context.Background(), 42, 1)

		require.NoError(t, err)
		require.Equal(t, int64(9), uid)
	})

	t.Run("unknown user", func(t *testing.T) {
		svc, storageMock, _, _, _ := newTestAuth()
		storageMock.On("MakeAdmin", mock.Anything, int64(42), int64(1)).Return(int64(0), storage.ErrUserNotFound)

		_, err := svc.MakeAdmin(context.Background(), 42, 1)

		require.ErrorIs(t, err, ErrUserNotFound)
	})
}

func TestIsAdmin(t *testing.T) {
	cases := []struct {
		name    string
		ret     bool
		retErr  error
		want    bool
		wantErr error
	}{
		{name: "is admin", ret: true, want: true},
		{name: "is not admin", ret: false, want: false},
		{name: "unknown user", retErr: storage.ErrUserNotFound, wantErr: storage.ErrUserNotFound},
		{name: "unknown app", retErr: storage.ErrAppNotFound, wantErr: storage.ErrAppNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, storageMock, _, _, _ := newTestAuth()
			storageMock.On("IsAdmin", mock.Anything, int64(42), int64(1)).Return(tc.ret, tc.retErr)

			got, err := svc.IsAdmin(context.Background(), 42, 1)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestDeleteAdmin_EachIdentifier(t *testing.T) {
	cases := []struct {
		name       string
		identifier models.UserIdentifier
		method     string
		arg        any
	}{
		{"by id", models.UserIdentifier{ID: i64Ptr(42)}, "DeleteAdminByUserID", int64(42)},
		{"by username", models.UserIdentifier{Username: strPtr("user123")}, "DeleteAdminByUsername", "user123"},
		{"by email", models.UserIdentifier{Email: strPtr("a@b.c")}, "DeleteAdminByEmail", "a@b.c"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, storageMock, _, _, _ := newTestAuth()
			storageMock.On(tc.method, mock.Anything, tc.arg, int64(1)).Return(nil)

			require.NoError(t, svc.DeleteAdmin(context.Background(), tc.identifier, 1))
			storageMock.AssertExpectations(t)
		})
	}

	t.Run("no identifier", func(t *testing.T) {
		svc, _, _, _, _ := newTestAuth()
		require.ErrorIs(t, svc.DeleteAdmin(context.Background(), models.UserIdentifier{}, 1), ErrInvalidIdentifier)
	})
}

// ----------------------------------------------------------- Delete user ----

func TestDeleteUser_EachIdentifier(t *testing.T) {
	cases := []struct {
		name       string
		identifier models.UserIdentifier
		method     string
		arg        any
	}{
		{"by id", models.UserIdentifier{ID: i64Ptr(42)}, "DeleteUserByUserID", int64(42)},
		{"by username", models.UserIdentifier{Username: strPtr("user123")}, "DeleteUserByUsername", "user123"},
		{"by email", models.UserIdentifier{Email: strPtr("a@b.c")}, "DeleteUserByEmail", "a@b.c"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, storageMock, _, _, _ := newTestAuth()
			storageMock.On(tc.method, mock.Anything, tc.arg, int64(1)).Return(nil)

			require.NoError(t, svc.DeleteUser(context.Background(), tc.identifier, 1))
			storageMock.AssertExpectations(t)
		})

		t.Run(tc.name+" not found", func(t *testing.T) {
			svc, storageMock, _, _, _ := newTestAuth()
			storageMock.On(tc.method, mock.Anything, tc.arg, int64(1)).Return(storage.ErrUserNotFound)

			require.ErrorIs(t, svc.DeleteUser(context.Background(), tc.identifier, 1), ErrUserNotFound)
		})
	}

	t.Run("no identifier", func(t *testing.T) {
		svc, _, _, _, _ := newTestAuth()
		require.ErrorIs(t, svc.DeleteUser(context.Background(), models.UserIdentifier{}, 1), ErrInvalidIdentifier)
	})
}

// ------------------------------------------------------------ Application ---

func TestRegisterApp(t *testing.T) {
	t.Run("returns a usable secret and stores an encrypted one", func(t *testing.T) {
		withMasterKey(t)
		svc, storageMock, _, _, _ := newTestAuth()

		var storedSecret string
		storageMock.On("RegisterApp", mock.Anything, "auralift", mock.AnythingOfType("string"), "https://example.test").
			Run(func(args mock.Arguments) { storedSecret = args.String(2) }).Return(int64(3), nil)

		id, secret, err := svc.RegisterApp(context.Background(), "auralift", "https://example.test")

		require.NoError(t, err)
		require.Equal(t, int64(3), id)
		require.Len(t, secret, 32, "16 random bytes hex-encoded")
		// What goes to the database must not be the plaintext secret.
		require.NotEqual(t, secret, storedSecret)
		require.NotEmpty(t, storedSecret)
	})

	t.Run("two registrations produce different secrets", func(t *testing.T) {
		withMasterKey(t)
		svc, storageMock, _, _, _ := newTestAuth()
		storageMock.On("RegisterApp", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(1), nil)

		_, first, err := svc.RegisterApp(context.Background(), "a", "https://a.test")
		require.NoError(t, err)
		_, second, err := svc.RegisterApp(context.Background(), "b", "https://b.test")
		require.NoError(t, err)

		require.NotEqual(t, first, second)
	})

	t.Run("duplicate application", func(t *testing.T) {
		withMasterKey(t)
		svc, storageMock, _, _, _ := newTestAuth()
		storageMock.On("RegisterApp", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
			Return(int64(0), storage.ErrAppExists)

		_, _, err := svc.RegisterApp(context.Background(), "auralift", "https://example.test")

		require.ErrorIs(t, err, ErrAppExists)
	})

	t.Run("invalid master key is refused", func(t *testing.T) {
		// AES needs 16, 24 or 32 bytes. A wrong-length key must fail loudly
		// rather than register an application whose secret cannot be read back.
		t.Setenv("MASTER_KEY", "too-short")
		svc, storageMock, _, _, _ := newTestAuth()

		_, _, err := svc.RegisterApp(context.Background(), "auralift", "https://example.test")

		require.Error(t, err)
		storageMock.AssertNotCalled(t, "RegisterApp", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestDeleteApp(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, storageMock, _, _, _ := newTestAuth()
		storageMock.On("DeleteApp", mock.Anything, int64(3)).Return(nil)

		require.NoError(t, svc.DeleteApp(context.Background(), 3))
	})

	t.Run("unknown application", func(t *testing.T) {
		svc, storageMock, _, _, _ := newTestAuth()
		storageMock.On("DeleteApp", mock.Anything, int64(3)).Return(storage.ErrAppNotFound)

		require.ErrorIs(t, svc.DeleteApp(context.Background(), 3), storage.ErrAppNotFound)
	})

	// The cache must not keep serving a secret for an application that is gone.
	t.Run("drops the cached secret", func(t *testing.T) {
		withMasterKey(t)
		svc, storageMock, _, _, _ := newTestAuth()
		storageMock.On("RegisterApp", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(int64(3), nil)
		storageMock.On("DeleteApp", mock.Anything, int64(3)).Return(nil)

		_, _, err := svc.RegisterApp(context.Background(), "auralift", "https://example.test")
		require.NoError(t, err)
		_, cached := svc.appSecrets.Load(int64(3))
		require.True(t, cached)

		require.NoError(t, svc.DeleteApp(context.Background(), 3))
		_, cached = svc.appSecrets.Load(int64(3))
		require.False(t, cached, "secret must be evicted when the application is deleted")
	})
}

// ---------------------------------------------------------------- Tokens ----

func TestRefreshToken(t *testing.T) {
	fields := &models.RefreshTokenFields{UserID: 42, AppId: 7}

	t.Run("issues a new access token", func(t *testing.T) {
		svc, storageMock, jwtMock, _, _ := newTestAuth()
		jwtMock.On("GetRefreshTokenFields", mock.Anything, "refresh").Return(fields, nil)
		storageMock.On("App", mock.Anything, int64(7)).Return(models.App{ID: 7, Secret: "s"}, nil)

		token, err := svc.RefreshToken(context.Background(), "refresh")

		require.NoError(t, err)
		require.NotEmpty(t, token)
	})

	t.Run("caches the application secret after the first load", func(t *testing.T) {
		svc, storageMock, jwtMock, _, _ := newTestAuth()
		jwtMock.On("GetRefreshTokenFields", mock.Anything, "refresh").Return(fields, nil)
		storageMock.On("App", mock.Anything, int64(7)).Return(models.App{ID: 7, Secret: "s"}, nil).Once()

		_, err := svc.RefreshToken(context.Background(), "refresh")
		require.NoError(t, err)
		_, err = svc.RefreshToken(context.Background(), "refresh")
		require.NoError(t, err)

		storageMock.AssertNumberOfCalls(t, "App", 1)
	})

	t.Run("unknown token", func(t *testing.T) {
		svc, _, jwtMock, _, _ := newTestAuth()
		jwtMock.On("GetRefreshTokenFields", mock.Anything, "gone").Return(nil, storage.ErrTokenNotFound)

		_, err := svc.RefreshToken(context.Background(), "gone")

		require.ErrorIs(t, err, storage.ErrTokenNotFound)
	})

	t.Run("application lookup failure", func(t *testing.T) {
		svc, storageMock, jwtMock, _, _ := newTestAuth()
		jwtMock.On("GetRefreshTokenFields", mock.Anything, "refresh").Return(fields, nil)
		storageMock.On("App", mock.Anything, int64(7)).Return(models.App{}, storage.ErrAppNotFound)

		_, err := svc.RefreshToken(context.Background(), "refresh")

		require.ErrorIs(t, err, storage.ErrAppNotFound)
	})
}

func TestUpdateRefreshToken(t *testing.T) {
	fields := &models.RefreshTokenFields{UserID: 42, AppId: 7}

	t.Run("rotates and persists", func(t *testing.T) {
		svc, storageMock, jwtMock, _, _ := newTestAuth()
		jwtMock.On("GetRefreshTokenFields", mock.Anything, "old").Return(fields, nil)
		storageMock.On("App", mock.Anything, int64(7)).Return(models.App{ID: 7, Secret: "s"}, nil)
		jwtMock.On("SetNewRefreshToken", mock.Anything, "old", mock.AnythingOfType("string"), testRefreshTTL).Return(nil)

		token, err := svc.UpdateRefreshToken(context.Background(), "old")

		require.NoError(t, err)
		require.NotEmpty(t, token)
		require.NotEqual(t, "old", token)
		jwtMock.AssertExpectations(t)
	})

	t.Run("unknown token", func(t *testing.T) {
		svc, _, jwtMock, _, _ := newTestAuth()
		jwtMock.On("GetRefreshTokenFields", mock.Anything, "gone").Return(nil, storage.ErrTokenNotFound)

		_, err := svc.UpdateRefreshToken(context.Background(), "gone")

		require.ErrorIs(t, err, storage.ErrTokenNotFound)
	})

	// If the store rejects the rotation the caller must get an error rather
	// than a token the store does not know about.
	t.Run("store rejects the rotation", func(t *testing.T) {
		svc, storageMock, jwtMock, _, _ := newTestAuth()
		jwtMock.On("GetRefreshTokenFields", mock.Anything, "old").Return(fields, nil)
		storageMock.On("App", mock.Anything, int64(7)).Return(models.App{ID: 7, Secret: "s"}, nil)
		jwtMock.On("SetNewRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errRedisDown)

		token, err := svc.UpdateRefreshToken(context.Background(), "old")

		require.ErrorIs(t, err, errRedisDown)
		require.Empty(t, token)
	})
}
