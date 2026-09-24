package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/synnfluxx/TrustMeBroID/internal/lib/encryptor"
	discardHandler "github.com/synnfluxx/TrustMeBroID/internal/lib/logger/handlers/discardHandler"
	strg "github.com/synnfluxx/TrustMeBroID/internal/storage"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

const (
	appName     = "test-app"
	appSecret   = "very-security-secret"
	redirectURI = "https://example.com/callback"
	email       = "email@example.com"
	username    = "testuser"
	passHash    = "very-security-password"
)

// requireDocker skips instead of failing when no container runtime is
// reachable. These are integration tests: on a machine without Docker they
// have nothing to say, and failing there hides real regressions in the rest of
// the suite behind a wall of infrastructure errors.
//
// Set SSO_REQUIRE_DOCKER=1 in CI so a missing runtime is treated as a failure
// and the integration tests cannot be skipped by accident.
func requireDocker(t *testing.T) {
	t.Helper()

	if _, err := testcontainers.ProviderDocker.GetProvider(); err != nil {
		if os.Getenv("SSO_REQUIRE_DOCKER") != "" {
			t.Fatalf("SSO_REQUIRE_DOCKER is set but no container runtime is reachable: %v", err)
		}
		t.Skipf("skipping: no container runtime reachable (%v)", err)
	}
}

func createPostgresDB(t *testing.T) *sql.DB {
	t.Helper()

	requireDocker(t)

	ctx := context.Background()
	migrationsPath := "file://" + migrationsDir(t)

	pgContainer, err := postgres.Run(ctx,
		"postgres:alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("user"),
		postgres.WithPassword("pass"),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	})

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	runMigrations(t, connStr, migrationsPath)

	db, err := sql.Open("postgres", connStr)
	require.NoError(t, err)

	require.NoError(t, db.Ping())
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})

	return db
}

func migrationsDir(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)

	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "..", "migrations"))
}

func runMigrations(t *testing.T, connectionString, migrationsPath string) {
	t.Helper()

	m, err := migrate.New(migrationsPath, connectionString)
	require.NoError(t, err)

	t.Cleanup(func() {
		sourceErr, dbErr := m.Close()
		require.NoError(t, sourceErr)
		require.NoError(t, dbErr)
	})

	require.NoError(t, m.Up())
}

func newTestStorage(t *testing.T) (*Storage, context.Context) {
	t.Helper()

	// masterKey and log are set the way New would set them: App() decrypts the
	// application secret with the key, and the query tracer logs through it.
	return &Storage{
		db:        createPostgresDB(t),
		log:       discardHandler.NewDiscardLogger(),
		masterKey: []byte("12345678901234567890123456789012"),
	}, context.Background()
}

func createTestApp(t *testing.T, storage *Storage, ctx context.Context) int64 {
	t.Helper()

	appID, err := storage.RegisterApp(ctx, appName, appSecret, redirectURI)
	require.NoError(t, err)

	return appID
}

func createTestUser(t *testing.T, storage *Storage, ctx context.Context, appID int64) int64 {
	t.Helper()

	userID, err := storage.SaveUser(ctx, email, username, []byte(passHash), appID, "test-verification-code")
	require.NoError(t, err)

	return userID
}

func TestStorage_RegisterApp(t *testing.T) {
	storage, ctx := newTestStorage(t)

	t.Run("success", func(t *testing.T) {
		appID, err := storage.RegisterApp(ctx, appName, appSecret, redirectURI)
		require.NoError(t, err)
		assert.NotZero(t, appID)
	})

	t.Run("duplicate", func(t *testing.T) {
		_, err := storage.RegisterApp(ctx, appName, appSecret, redirectURI)
		require.NoError(t, err)

		_, err = storage.RegisterApp(ctx, appName, appSecret, redirectURI)
		require.Error(t, err)
		require.ErrorIs(t, err, strg.ErrAppExists)
	})
}

func TestStorage_SaveUser(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		storage, ctx := newTestStorage(t)
		appID := createTestApp(t, storage, ctx)

		userID, err := storage.SaveUser(ctx, email, username, []byte(passHash), appID, "test-verification-code")
		require.NoError(t, err)
		assert.NotZero(t, userID)
	})

	t.Run("duplicate", func(t *testing.T) {
		storage, ctx := newTestStorage(t)
		appID := createTestApp(t, storage, ctx)

		_, err := storage.SaveUser(ctx, email, username, []byte(passHash), appID, "test-verification-code")
		require.NoError(t, err)

		_, err = storage.SaveUser(ctx, email, username, []byte(passHash), appID, "test-verification-code")
		require.Error(t, err)
		require.ErrorIs(t, err, strg.ErrUserExists)
	})

	t.Run("non-existing app", func(t *testing.T) {
		storage, ctx := newTestStorage(t)

		_, err := storage.SaveUser(ctx, email, username, []byte(passHash), 1337, "test-verification-code")
		require.Error(t, err)
		require.ErrorIs(t, err, strg.ErrAppNotFound)
	})
}

func TestStorage_UserLookup(t *testing.T) {
	storage, ctx := newTestStorage(t)
	appID := createTestApp(t, storage, ctx)
	userID := createTestUser(t, storage, ctx, appID)

	t.Run("find by id", func(t *testing.T) {
		user, err := storage.User(ctx, userID, appID)
		require.NoError(t, err)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, email, user.Email)
		assert.Equal(t, username, user.Username)
	})

	t.Run("find by username", func(t *testing.T) {
		user, err := storage.UserByUsername(ctx, username, appID)
		require.NoError(t, err)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, email, user.Email)
	})

	t.Run("find by email", func(t *testing.T) {
		user, err := storage.UserByEmail(ctx, email, appID)
		require.NoError(t, err)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, username, user.Username)
	})

	t.Run("user not found", func(t *testing.T) {
		_, err := storage.UserByEmail(ctx, "missing@example.com", appID)
		require.Error(t, err)
		require.ErrorIs(t, err, strg.ErrUserNotFound)
	})
}

func TestStorage_DeleteUser(t *testing.T) {
	t.Run("delete by email", func(t *testing.T) {
		storage, ctx := newTestStorage(t)
		appID := createTestApp(t, storage, ctx)
		createTestUser(t, storage, ctx, appID)

		err := storage.DeleteUserByEmail(ctx, email, appID)
		require.NoError(t, err)

		_, err = storage.UserByEmail(ctx, email, appID)
		require.Error(t, err)
		require.ErrorIs(t, err, strg.ErrUserDeleted)
	})

	t.Run("delete by username", func(t *testing.T) {
		storage, ctx := newTestStorage(t)
		appID := createTestApp(t, storage, ctx)
		createTestUser(t, storage, ctx, appID)

		err := storage.DeleteUserByUsername(ctx, username, appID)
		require.NoError(t, err)

		_, err = storage.UserByUsername(ctx, username, appID)
		require.Error(t, err)
		require.ErrorIs(t, err, strg.ErrUserDeleted)
	})

	t.Run("delete by user id", func(t *testing.T) {
		storage, ctx := newTestStorage(t)
		appID := createTestApp(t, storage, ctx)
		userID := createTestUser(t, storage, ctx, appID)

		err := storage.DeleteUserByUserID(ctx, userID, appID)
		require.NoError(t, err)

		_, err = storage.User(ctx, userID, appID)
		require.Error(t, err)
		require.ErrorIs(t, err, strg.ErrUserDeleted)
	})

	t.Run("delete missing user", func(t *testing.T) {
		storage, ctx := newTestStorage(t)
		appID := createTestApp(t, storage, ctx)

		err := storage.DeleteUserByEmail(ctx, "missing@example.com", appID)
		require.Error(t, err)
		require.ErrorIs(t, err, strg.ErrUserNotFound)
	})
}

func TestStorage_DeleteApp(t *testing.T) {
	storage, ctx := newTestStorage(t)

	t.Run("success", func(t *testing.T) {
		appID := createTestApp(t, storage, ctx)

		err := storage.DeleteApp(ctx, appID)
		require.NoError(t, err)

		_, err = storage.App(ctx, appID)
		require.Error(t, err)
		require.ErrorIs(t, err, strg.ErrAppNotFound)
	})

	t.Run("missing app", func(t *testing.T) {
		err := storage.DeleteApp(ctx, 1337)
		require.Error(t, err)
		require.ErrorIs(t, err, strg.ErrAppNotFound)
	})
}

func TestStorage_FindOrCreateOAuthUser(t *testing.T) {
	t.Run("creates new user", func(t *testing.T) {
		storage, ctx := newTestStorage(t)
		appID := createTestApp(t, storage, ctx)

		user, err := storage.FindOrCreateOAuthUser(ctx, email, username, appID)
		require.NoError(t, err)
		assert.NotZero(t, user.ID)
		assert.Equal(t, email, user.Email)
		assert.Equal(t, username, user.Username)
	})

	t.Run("returns existing user", func(t *testing.T) {
		storage, ctx := newTestStorage(t)
		appID := createTestApp(t, storage, ctx)
		userID := createTestUser(t, storage, ctx, appID)

		user, err := storage.FindOrCreateOAuthUser(ctx, email, username, appID)
		require.NoError(t, err)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, email, user.Email)
	})
}

func TestStorage_SaveAndFind(t *testing.T) {
	storage, ctx := newTestStorage(t)

	t.Run("save user in non-existing app", func(t *testing.T) {
		_, err := storage.SaveUser(ctx, email, username, []byte(passHash), 1337, "test-verification-code")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, strg.ErrAppNotFound))
	})

	appID := createTestApp(t, storage, ctx)

	t.Run("duplicate app registration", func(t *testing.T) {
		_, err := storage.RegisterApp(ctx, appName, appSecret, redirectURI)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, strg.ErrAppExists))
	})

	userID := createTestUser(t, storage, ctx, appID)

	t.Run("duplicate save user", func(t *testing.T) {
		_, err := storage.SaveUser(ctx, email, username, []byte(passHash), appID, "test-verification-code")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, strg.ErrUserExists))
	})

	t.Run("find user by username", func(t *testing.T) {
		user, err := storage.UserByUsername(ctx, username, appID)
		assert.NoError(t, err)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, email, user.Email)
	})

	t.Run("find user by email", func(t *testing.T) {
		user, err := storage.UserByEmail(ctx, email, appID)
		assert.NoError(t, err)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, username, user.Username)
	})
}

// --- additional coverage ---------------------------------------------------

func TestStorage_AppDecryptsTheStoredSecret(t *testing.T) {
	store, ctx := newTestStorage(t)

	plain := "the-application-secret"
	encrypted, err := encryptor.EncryptString(store.masterKey, []byte(plain))
	require.NoError(t, err)

	appID, err := store.RegisterApp(ctx, "decrypting-app", encrypted, "https://app.test")
	require.NoError(t, err)

	app, err := store.App(ctx, appID)
	require.NoError(t, err)
	require.Equal(t, plain, app.Secret, "App must hand back the decrypted secret")
	require.Equal(t, "https://app.test", app.RedirectURI)
}

func TestStorage_AppFailsWithTheWrongMasterKey(t *testing.T) {
	store, ctx := newTestStorage(t)

	encrypted, err := encryptor.EncryptString(store.masterKey, []byte("secret"))
	require.NoError(t, err)
	appID, err := store.RegisterApp(ctx, "rotating-app", encrypted, "https://app.test")
	require.NoError(t, err)

	// Simulates MASTER_KEY changing between deploys.
	store.masterKey = []byte("22345678901234567890123456789012")

	_, err = store.App(ctx, appID)
	require.Error(t, err)
}

func TestStorage_AppNotFound(t *testing.T) {
	store, ctx := newTestStorage(t)

	_, err := store.App(ctx, 999999)

	require.ErrorIs(t, err, strg.ErrAppNotFound)
}

func TestStorage_VerifyUser(t *testing.T) {
	store, ctx := newTestStorage(t)
	appID := createTestApp(t, store, ctx)
	createTestUser(t, store, ctx, appID)

	before, err := store.UserByEmail(ctx, email, appID)
	require.NoError(t, err)
	require.False(t, before.IsVerified)

	require.NoError(t, store.VerifyUser(ctx, email, appID))

	after, err := store.UserByEmail(ctx, email, appID)
	require.NoError(t, err)
	require.True(t, after.IsVerified)
}

// The UPDATE is guarded by is_verified = FALSE, so a second call matches no
// rows and reports not-found rather than silently succeeding.
func TestStorage_VerifyUser_SecondCallReportsNoRows(t *testing.T) {
	store, ctx := newTestStorage(t)
	appID := createTestApp(t, store, ctx)
	createTestUser(t, store, ctx, appID)

	require.NoError(t, store.VerifyUser(ctx, email, appID))
	require.ErrorIs(t, store.VerifyUser(ctx, email, appID), strg.ErrUserNotFound)
}

func TestStorage_VerifyUser_UnknownAddress(t *testing.T) {
	store, ctx := newTestStorage(t)
	appID := createTestApp(t, store, ctx)

	require.ErrorIs(t, store.VerifyUser(ctx, "absent@example.test", appID), strg.ErrUserNotFound)
}

func TestStorage_UpdateVerificationToken_RefreshesTheIssueTime(t *testing.T) {
	store, ctx := newTestStorage(t)
	appID := createTestApp(t, store, ctx)
	createTestUser(t, store, ctx, appID)

	before, err := store.UserByEmail(ctx, email, appID)
	require.NoError(t, err)
	require.True(t, before.LastTokenGeneratedTime.Valid)

	require.NoError(t, store.UpdateVerificationToken(ctx, email, appID, "rotated-code"))

	after, err := store.UserByEmail(ctx, email, appID)
	require.NoError(t, err)
	require.Equal(t, "rotated-code", after.VerificationCode)
	// Without this the expiry window keeps counting from registration, so a
	// resent code is born expired once the original window has passed.
	require.False(t, after.LastTokenGeneratedTime.Time.Before(before.LastTokenGeneratedTime.Time),
		"rotating the code must also refresh its issue time")
}

func TestStorage_UpdateVerificationToken_UnknownAddress(t *testing.T) {
	store, ctx := newTestStorage(t)
	appID := createTestApp(t, store, ctx)

	require.ErrorIs(t,
		store.UpdateVerificationToken(ctx, "absent@example.test", appID, "code"),
		strg.ErrUserNotFound)
}

func TestStorage_AdminLifecycle(t *testing.T) {
	store, ctx := newTestStorage(t)
	appID := createTestApp(t, store, ctx)
	userID := createTestUser(t, store, ctx, appID)

	isAdmin, err := store.IsAdmin(ctx, userID, appID)
	require.NoError(t, err)
	require.False(t, isAdmin)

	_, err = store.MakeAdmin(ctx, userID, appID)
	require.NoError(t, err)

	isAdmin, err = store.IsAdmin(ctx, userID, appID)
	require.NoError(t, err)
	require.True(t, isAdmin)

	require.NoError(t, store.DeleteAdminByUserID(ctx, userID, appID))

	isAdmin, err = store.IsAdmin(ctx, userID, appID)
	require.NoError(t, err)
	require.False(t, isAdmin)
}

func TestStorage_DeleteAdminByUsernameAndEmail(t *testing.T) {
	for _, tc := range []struct {
		name   string
		delete func(s *Storage, ctx context.Context, appID int64) error
	}{
		{"by username", func(s *Storage, ctx context.Context, appID int64) error {
			return s.DeleteAdminByUsername(ctx, username, appID)
		}},
		{"by email", func(s *Storage, ctx context.Context, appID int64) error {
			return s.DeleteAdminByEmail(ctx, email, appID)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, ctx := newTestStorage(t)
			appID := createTestApp(t, store, ctx)
			userID := createTestUser(t, store, ctx, appID)
			_, err := store.MakeAdmin(ctx, userID, appID)
			require.NoError(t, err)

			require.NoError(t, tc.delete(store, ctx, appID))

			isAdmin, err := store.IsAdmin(ctx, userID, appID)
			require.NoError(t, err)
			require.False(t, isAdmin)
		})
	}
}

func TestStorage_DeleteAdmin_NotFound(t *testing.T) {
	store, ctx := newTestStorage(t)
	appID := createTestApp(t, store, ctx)

	require.ErrorIs(t, store.DeleteAdminByUserID(ctx, 999999, appID), strg.ErrUserNotFound)
}

// MakeAdmin uses INSERT ... SELECT, which inserts nothing when the user does
// not exist and returns sql.ErrNoRows rather than a mapped storage error. The
// service checks for strg.ErrUserNotFound, so that branch never matches.
func TestStorage_MakeAdmin_UnknownUserIsNotMapped(t *testing.T) {
	store, ctx := newTestStorage(t)
	appID := createTestApp(t, store, ctx)

	_, err := store.MakeAdmin(ctx, 999999, appID)

	require.Error(t, err)
	require.NotErrorIs(t, err, strg.ErrUserNotFound,
		"documents that the not-found mapping is missing at this layer")
}

func TestStorage_SoftDeleteHidesTheUser(t *testing.T) {
	store, ctx := newTestStorage(t)
	appID := createTestApp(t, store, ctx)
	createTestUser(t, store, ctx, appID)

	require.NoError(t, store.DeleteUserByEmail(ctx, email, appID))

	_, err := store.UserByEmail(ctx, email, appID)
	require.ErrorIs(t, err, strg.ErrUserDeleted)
}

func TestStorage_DeleteUser_TwiceReportsNotFound(t *testing.T) {
	store, ctx := newTestStorage(t)
	appID := createTestApp(t, store, ctx)
	createTestUser(t, store, ctx, appID)

	require.NoError(t, store.DeleteUserByEmail(ctx, email, appID))
	require.ErrorIs(t, store.DeleteUserByEmail(ctx, email, appID), strg.ErrUserNotFound)
}

func TestStorage_Reaper(t *testing.T) {
	store, ctx := newTestStorage(t)
	appID := createTestApp(t, store, ctx)
	userID := createTestUser(t, store, ctx, appID)

	// Freshly deleted rows are inside the grace period and must survive.
	require.NoError(t, store.DeleteUserByEmail(ctx, email, appID))

	reaped, err := store.Reaper(ctx)
	require.NoError(t, err)
	require.NotContains(t, reaped, userID)

	// Age the row past the 72-hour window the reaper statement uses.
	_, err = store.db.ExecContext(ctx,
		"UPDATE users SET deleted_at = NOW() - INTERVAL '100 hours' WHERE id = $1", userID)
	require.NoError(t, err)

	reaped, err = store.Reaper(ctx)
	require.NoError(t, err)
	require.Contains(t, reaped, userID)
}

func TestStorage_Reaper_LeavesLiveUsersAlone(t *testing.T) {
	store, ctx := newTestStorage(t)
	appID := createTestApp(t, store, ctx)
	userID := createTestUser(t, store, ctx, appID)

	reaped, err := store.Reaper(ctx)
	require.NoError(t, err)
	require.NotContains(t, reaped, userID)

	_, err = store.UserByEmail(ctx, email, appID)
	require.NoError(t, err)
}

func TestStorage_EmailsAndUsernames(t *testing.T) {
	store, ctx := newTestStorage(t)
	appID := createTestApp(t, store, ctx)
	createTestUser(t, store, ctx, appID)

	emails, err := store.Emails(ctx)
	require.NoError(t, err)
	require.Contains(t, emails, email)

	usernames, err := store.Usernames(ctx)
	require.NoError(t, err)
	require.Contains(t, usernames, username)
}

func TestStorage_SaveUser_DuplicateIsReported(t *testing.T) {
	store, ctx := newTestStorage(t)
	appID := createTestApp(t, store, ctx)
	createTestUser(t, store, ctx, appID)

	_, err := store.SaveUser(ctx, email, username, []byte(passHash), appID, "another-code")

	require.ErrorIs(t, err, strg.ErrUserExists)
}

func TestStorage_SaveUser_UnknownApplication(t *testing.T) {
	store, ctx := newTestStorage(t)

	_, err := store.SaveUser(ctx, email, username, []byte(passHash), 999999, "code")

	require.ErrorIs(t, err, strg.ErrAppNotFound)
}

func TestStorage_Close(t *testing.T) {
	store, _ := newTestStorage(t)
	require.NoError(t, store.Close())
}
