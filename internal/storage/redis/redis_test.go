package redisStorage

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
)

const testTTL = time.Hour

func newTestStorage(t *testing.T) (*Storage, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)

	strg, err := NewRedis(server.Addr(), time.Second, 1, "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = strg.Close() })

	return strg, server
}

func TestNewRedis_FailsFastWhenUnreachable(t *testing.T) {
	// The constructor pings, so an unreachable Redis must fail at startup
	// rather than at the first login.
	_, err := NewRedis("127.0.0.1:1", 200*time.Millisecond, 0, "")
	require.Error(t, err)
}

func TestNewRedis_AcceptsConnectionString(t *testing.T) {
	server := miniredis.RunT(t)

	strg, err := NewRedis("", time.Second, 1, "redis://"+server.Addr()+"/0")
	require.NoError(t, err)
	require.NotNil(t, strg)
	require.NoError(t, strg.Close())
}

func TestNewRedis_RejectsMalformedConnectionString(t *testing.T) {
	_, err := NewRedis("", time.Second, 1, "://not a url")
	require.Error(t, err)
}

func TestSaveAndGetRefreshToken(t *testing.T) {
	strg, _ := newTestStorage(t)
	ctx := context.Background()

	require.NoError(t, strg.SaveRefreshToken(ctx, "token-a", 42, 7, testTTL))

	fields, err := strg.GetRefreshTokenFields(ctx, "token-a")
	require.NoError(t, err)
	require.Equal(t, int64(42), fields.UserID)
	require.Equal(t, int64(7), fields.AppId)
}

// EXPIRE takes whole seconds. Passing a float worked only because every
// configured TTL happens to be round.
func TestSaveRefreshToken_SetsExpiry(t *testing.T) {
	strg, server := newTestStorage(t)

	require.NoError(t, strg.SaveRefreshToken(context.Background(), "token-a", 42, 7, 90*time.Minute))

	ttl := server.TTL("token-a")
	require.Greater(t, ttl, time.Duration(0), "the entry must expire")
	require.InDelta(t, (90 * time.Minute).Seconds(), ttl.Seconds(), 2)
}

func TestSaveRefreshToken_FractionalTTLIsAccepted(t *testing.T) {
	strg, server := newTestStorage(t)

	require.NoError(t, strg.SaveRefreshToken(context.Background(), "token-a", 42, 7, 1500*time.Millisecond))
	require.Greater(t, server.TTL("token-a"), time.Duration(0))
}

func TestGetRefreshTokenFields_UnknownToken(t *testing.T) {
	strg, _ := newTestStorage(t)

	_, err := strg.GetRefreshTokenFields(context.Background(), "never-issued")

	require.ErrorIs(t, err, storage.ErrTokenNotFound)
}

func TestGetRefreshTokenFields_ExpiredToken(t *testing.T) {
	strg, server := newTestStorage(t)
	ctx := context.Background()

	require.NoError(t, strg.SaveRefreshToken(ctx, "token-a", 42, 7, time.Minute))
	server.FastForward(2 * time.Minute)

	_, err := strg.GetRefreshTokenFields(ctx, "token-a")
	require.ErrorIs(t, err, storage.ErrTokenNotFound)
}

func TestSetNewRefreshToken_RotatesPreservingFields(t *testing.T) {
	strg, _ := newTestStorage(t)
	ctx := context.Background()

	require.NoError(t, strg.SaveRefreshToken(ctx, "old", 42, 7, testTTL))
	require.NoError(t, strg.SetNewRefreshToken(ctx, "old", "new", testTTL))

	// The old token must stop working the moment it is rotated.
	_, err := strg.GetRefreshTokenFields(ctx, "old")
	require.ErrorIs(t, err, storage.ErrTokenNotFound)

	fields, err := strg.GetRefreshTokenFields(ctx, "new")
	require.NoError(t, err)
	require.Equal(t, int64(42), fields.UserID)
	require.Equal(t, int64(7), fields.AppId)
}

func TestSetNewRefreshToken_UnknownTokenIsReported(t *testing.T) {
	strg, _ := newTestStorage(t)

	err := strg.SetNewRefreshToken(context.Background(), "never-issued", "new", testTTL)

	require.ErrorIs(t, err, storage.ErrTokenNotFound)
}

func TestSetNewRefreshToken_RefreshesTheExpiry(t *testing.T) {
	strg, server := newTestStorage(t)
	ctx := context.Background()

	require.NoError(t, strg.SaveRefreshToken(ctx, "old", 42, 7, time.Minute))
	require.NoError(t, strg.SetNewRefreshToken(ctx, "old", "new", 2*time.Hour))

	require.InDelta(t, (2 * time.Hour).Seconds(), server.TTL("new").Seconds(), 2)
}

func TestLogout_RevokesTheToken(t *testing.T) {
	strg, _ := newTestStorage(t)
	ctx := context.Background()

	require.NoError(t, strg.SaveRefreshToken(ctx, "token-a", 42, 7, testTTL))
	require.NoError(t, strg.Logout(ctx, "token-a"))

	_, err := strg.GetRefreshTokenFields(ctx, "token-a")
	require.ErrorIs(t, err, storage.ErrTokenNotFound)
}

// Deleting a key that is not there returns zero rather than an error, so a
// logout with a bogus token used to report success.
func TestLogout_UnknownTokenIsReported(t *testing.T) {
	strg, _ := newTestStorage(t)

	err := strg.Logout(context.Background(), "never-issued")

	require.ErrorIs(t, err, storage.ErrTokenNotFound)
}

func TestLogout_IsNotIdempotent(t *testing.T) {
	strg, _ := newTestStorage(t)
	ctx := context.Background()

	require.NoError(t, strg.SaveRefreshToken(ctx, "token-a", 42, 7, testTTL))
	require.NoError(t, strg.Logout(ctx, "token-a"))
	require.ErrorIs(t, strg.Logout(ctx, "token-a"), storage.ErrTokenNotFound)
}

// Two sessions for one user must be independent: revoking one must not revoke
// the other.
func TestSessionsAreIndependent(t *testing.T) {
	strg, _ := newTestStorage(t)
	ctx := context.Background()

	require.NoError(t, strg.SaveRefreshToken(ctx, "phone", 42, 7, testTTL))
	require.NoError(t, strg.SaveRefreshToken(ctx, "laptop", 42, 7, testTTL))

	require.NoError(t, strg.Logout(ctx, "phone"))

	_, err := strg.GetRefreshTokenFields(ctx, "laptop")
	require.NoError(t, err)
}

func TestClose(t *testing.T) {
	server := miniredis.RunT(t)
	strg, err := NewRedis(server.Addr(), time.Second, 1, "")
	require.NoError(t, err)

	require.NoError(t, strg.Close())
}
