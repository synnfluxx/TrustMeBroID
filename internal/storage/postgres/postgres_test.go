package postgres

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	strg "github.com/synnfluxx/TrustMeBroID/internal/storage"
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

func createPostgresDB(t *testing.T) *sql.DB {
	t.Helper()

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

	return &Storage{db: createPostgresDB(t)}, context.Background()
}

func createTestApp(t *testing.T, storage *Storage, ctx context.Context) int64 {
	t.Helper()

	appID, err := storage.RegisterApp(ctx, appName, appSecret, redirectURI)
	require.NoError(t, err)

	return appID
}

func createTestUser(t *testing.T, storage *Storage, ctx context.Context, appID int64) int64 {
	t.Helper()

	userID, err := storage.SaveUser(ctx, email, username, []byte(passHash), appID)
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

		userID, err := storage.SaveUser(ctx, email, username, []byte(passHash), appID)
		require.NoError(t, err)
		assert.NotZero(t, userID)
	})

	t.Run("duplicate", func(t *testing.T) {
		storage, ctx := newTestStorage(t)
		appID := createTestApp(t, storage, ctx)

		_, err := storage.SaveUser(ctx, email, username, []byte(passHash), appID)
		require.NoError(t, err)

		_, err = storage.SaveUser(ctx, email, username, []byte(passHash), appID)
		require.Error(t, err)
		require.ErrorIs(t, err, strg.ErrUserExists)
	})

	t.Run("non-existing app", func(t *testing.T) {
		storage, ctx := newTestStorage(t)

		_, err := storage.SaveUser(ctx, email, username, []byte(passHash), 1337)
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
		_, err := storage.SaveUser(ctx, email, username, []byte(passHash), 1337)
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
		_, err := storage.SaveUser(ctx, email, username, []byte(passHash), appID)
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
