package jwt

import (
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const (
	testSecret = "test-app-secret"
	testUserID = int64(42)
	testAppID  = int64(7)
)

func parse(t *testing.T, token, secret string) *jwtlib.RegisteredClaims {
	t.Helper()
	claims := &jwtlib.RegisteredClaims{}
	parsed, err := jwtlib.ParseWithClaims(token, claims, func(*jwtlib.Token) (any, error) {
		return []byte(secret), nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	return claims
}

func TestNewAccessToken_ClaimsAndExpiry(t *testing.T) {
	token, err := NewAccessToken(testUserID, testAppID, 5*time.Minute, testSecret)
	require.NoError(t, err)

	claims := parse(t, token, testSecret)
	require.Equal(t, "42", claims.Subject)
	require.Equal(t, "7", claims.Issuer)
	require.WithinDuration(t, time.Now().Add(5*time.Minute), claims.ExpiresAt.Time, 5*time.Second)
	require.WithinDuration(t, time.Now(), claims.IssuedAt.Time, 5*time.Second)
}

func TestNewRefreshToken_ClaimsAndExpiry(t *testing.T) {
	token, err := NewRefreshToken(testUserID, testAppID, 168*time.Hour, testSecret)
	require.NoError(t, err)

	claims := parse(t, token, testSecret)
	require.Equal(t, "42", claims.Subject)
	require.WithinDuration(t, time.Now().Add(168*time.Hour), claims.ExpiresAt.Time, 5*time.Second)
}

func TestTokensAreSignedWithHS256(t *testing.T) {
	token, err := NewAccessToken(testUserID, testAppID, time.Minute, testSecret)
	require.NoError(t, err)

	parsed, _, err := jwtlib.NewParser().ParseUnverified(token, &jwtlib.RegisteredClaims{})
	require.NoError(t, err)
	require.Equal(t, "HS256", parsed.Method.Alg())
}

func TestTokenDoesNotValidateUnderAnotherSecret(t *testing.T) {
	token, err := NewAccessToken(testUserID, testAppID, time.Minute, testSecret)
	require.NoError(t, err)

	claims := &jwtlib.RegisteredClaims{}
	_, err = jwtlib.ParseWithClaims(token, claims, func(*jwtlib.Token) (any, error) {
		return []byte("a-different-secret"), nil
	})

	require.ErrorIs(t, err, jwtlib.ErrTokenSignatureInvalid)
}

func TestExpiredTokenIsRejected(t *testing.T) {
	token, err := NewAccessToken(testUserID, testAppID, -time.Minute, testSecret)
	require.NoError(t, err)

	claims := &jwtlib.RegisteredClaims{}
	_, err = jwtlib.ParseWithClaims(token, claims, func(*jwtlib.Token) (any, error) {
		return []byte(testSecret), nil
	})

	require.ErrorIs(t, err, jwtlib.ErrTokenExpired)
}

func TestNewTokens_ReturnsBothWithDifferentLifetimes(t *testing.T) {
	access, refresh, err := NewTokens(testUserID, testAppID, testSecret, 168*time.Hour, 5*time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, access)
	require.NotEmpty(t, refresh)

	accessClaims := parse(t, access, testSecret)
	refreshClaims := parse(t, refresh, testSecret)
	require.True(t, refreshClaims.ExpiresAt.After(accessClaims.ExpiresAt.Time),
		"the refresh token must outlive the access token")
}

// Access and refresh tokens carry identical registered claims and are signed
// with the same key, so nothing in the token itself says which is which. Any
// verifier that only checks the signature will accept a refresh token where an
// access token is expected. This test states the current behaviour; adding a
// "typ" claim would be the fix.
func TestAccessAndRefreshAreStructurallyIndistinguishable(t *testing.T) {
	access, refresh, err := NewTokens(testUserID, testAppID, testSecret, time.Hour, time.Hour)
	require.NoError(t, err)

	accessClaims := parse(t, access, testSecret)
	refreshClaims := parse(t, refresh, testSecret)

	require.Equal(t, accessClaims.Subject, refreshClaims.Subject)
	require.Equal(t, accessClaims.Issuer, refreshClaims.Issuer)
	require.Equal(t, access, refresh,
		"with equal TTLs the two tokens are byte-identical: there is no type claim to tell them apart")
}

// Registered claims contain no nonce, so two tokens minted for the same user in
// the same second are identical. Refresh tokens are used as Redis keys, so two
// concurrent logins collide on one entry.
func TestTokensMintedInTheSameSecondCollide(t *testing.T) {
	first, err := NewRefreshToken(testUserID, testAppID, time.Hour, testSecret)
	require.NoError(t, err)
	second, err := NewRefreshToken(testUserID, testAppID, time.Hour, testSecret)
	require.NoError(t, err)

	require.Equal(t, first, second,
		"no jti claim: same user, same app, same second produces the same token")
}

func TestNewOAuthAccessToken_CarriesAvatar(t *testing.T) {
	token, err := NewOAuthAccessToken(testUserID, testAppID, time.Minute, testSecret, "https://avatars.test/a.png")
	require.NoError(t, err)

	claims := &OAuthCustomClaims{}
	parsed, err := jwtlib.ParseWithClaims(token, claims, func(*jwtlib.Token) (any, error) {
		return []byte(testSecret), nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	require.Equal(t, "https://avatars.test/a.png", claims.AvatarPath)
	require.Equal(t, "42", claims.Subject)
}

func TestNewOAuthTokens(t *testing.T) {
	access, refresh, err := NewOAuthTokens(testUserID, testAppID, testSecret, "https://avatars.test/a.png", time.Hour, time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, access)
	require.NotEmpty(t, refresh)

	claims := &OAuthCustomClaims{}
	_, err = jwtlib.ParseWithClaims(access, claims, func(*jwtlib.Token) (any, error) {
		return []byte(testSecret), nil
	})
	require.NoError(t, err)
	require.Equal(t, "https://avatars.test/a.png", claims.AvatarPath)
}

func TestEmptySecretStillProducesAToken(t *testing.T) {
	// Documents that nothing here rejects an empty signing key: the guard has
	// to live at the call site.
	token, err := NewAccessToken(testUserID, testAppID, time.Minute, "")
	require.NoError(t, err)
	require.NotEmpty(t, token)
}
