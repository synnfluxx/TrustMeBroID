package oauth

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	discardHandler "github.com/synnfluxx/TrustMeBroID/internal/lib/logger/handlers/discardHandler"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
)

type stubStorage struct {
	app    models.App
	appErr error

	user     models.User
	userErr  error
	gotEmail string
	gotName  string
}

func (s *stubStorage) FindOrCreateOAuthUser(_ context.Context, email, username string, _ int64) (models.User, error) {
	s.gotEmail, s.gotName = email, username
	return s.user, s.userErr
}
func (s *stubStorage) App(context.Context, int64) (models.App, error) { return s.app, s.appErr }
func (s *stubStorage) UserByEmail(context.Context, string, int64) (models.User, error) {
	return s.user, s.userErr
}

type stubTokens struct {
	err       error
	savedFor  int64
	savedApp  int64
	savedTTL  time.Duration
	callCount int
}

func (s *stubTokens) SaveRefreshToken(_ context.Context, _ string, userID, appID int64, ttl time.Duration) error {
	s.callCount++
	s.savedFor, s.savedApp, s.savedTTL = userID, appID, ttl
	return s.err
}

type stubConfig struct {
	url      string
	details  *OAuthUserDetails
	err      error
	gotCode  string
	gotState string
}

func (s *stubConfig) URL(state string) string { s.gotState = state; return s.url + "?state=" + state }
func (s *stubConfig) Callback(_ context.Context, code string) (*OAuthUserDetails, error) {
	s.gotCode = code
	return s.details, s.err
}

func newService(st *stubStorage, tk *stubTokens, cfg *stubConfig) *OAuthService {
	return New(cfg, st, tk, discardHandler.NewDiscardLogger())
}

// ------------------------------------------------------------------ Login --

func TestLogin_StateCarriesAppIDAndRandomNonce(t *testing.T) {
	st := &stubStorage{app: models.App{ID: 7}}
	cfg := &stubConfig{url: "https://github.test/authorize"}

	state, url, err := newService(st, &stubTokens{}, cfg).Login(context.Background(), 7)

	require.NoError(t, err)
	require.Contains(t, url, "https://github.test/authorize")

	parts := strings.Split(state, ":")
	require.Len(t, parts, 2)
	require.Len(t, parts[0], 32, "16 random bytes hex-encoded")
	appID, err := strconv.Atoi(parts[1])
	require.NoError(t, err)
	require.Equal(t, 7, appID)
}

// The nonce is the CSRF token; two authorizations must never share one.
func TestLogin_StateIsUniquePerCall(t *testing.T) {
	st := &stubStorage{app: models.App{ID: 7}}
	svc := newService(st, &stubTokens{}, &stubConfig{url: "https://github.test/authorize"})

	seen := make(map[string]struct{}, 200)
	for range 200 {
		state, _, err := svc.Login(context.Background(), 7)
		require.NoError(t, err)
		_, dup := seen[state]
		require.False(t, dup, "state repeated")
		seen[state] = struct{}{}
	}
}

func TestLogin_UnknownApplication(t *testing.T) {
	st := &stubStorage{appErr: storage.ErrAppNotFound}

	_, _, err := newService(st, &stubTokens{}, &stubConfig{}).Login(context.Background(), 7)

	require.ErrorIs(t, err, storage.ErrAppNotFound)
}

// --------------------------------------------------------------- Callback --

func TestCallback_IssuesTokensAndPersistsRefresh(t *testing.T) {
	st := &stubStorage{
		app:  models.App{ID: 7, Secret: "app-secret", RedirectURI: "https://app.test/done"},
		user: models.User{ID: 42, Email: "a@b.c"},
	}
	tk := &stubTokens{}
	cfg := &stubConfig{details: &OAuthUserDetails{Email: "a@b.c", Username: "octocat", Avatar: "https://avatars.test/a.png"}}

	access, refresh, redirect, err := newService(st, tk, cfg).
		Callback(context.Background(), "auth-code", 7, 5*time.Minute, 168*time.Hour)

	require.NoError(t, err)
	require.NotEmpty(t, access)
	require.NotEmpty(t, refresh)
	require.Equal(t, "https://app.test/done", redirect)
	require.Equal(t, "auth-code", cfg.gotCode)
	require.Equal(t, "a@b.c", st.gotEmail)
	require.Equal(t, "octocat", st.gotName)

	require.Equal(t, 1, tk.callCount)
	require.Equal(t, int64(42), tk.savedFor)
	require.Equal(t, int64(7), tk.savedApp)
	require.Equal(t, 168*time.Hour, tk.savedTTL)
}

func TestCallback_Failures(t *testing.T) {
	provider := errors.New("github rejected the code")
	cases := []struct {
		name  string
		build func() (*stubStorage, *stubTokens, *stubConfig)
		want  error
	}{
		{
			name: "code exchange fails",
			build: func() (*stubStorage, *stubTokens, *stubConfig) {
				return &stubStorage{}, &stubTokens{}, &stubConfig{err: provider}
			},
			want: provider,
		},
		{
			name: "account resolution fails",
			build: func() (*stubStorage, *stubTokens, *stubConfig) {
				return &stubStorage{userErr: errors.New("db down")},
					&stubTokens{},
					&stubConfig{details: &OAuthUserDetails{Email: "a@b.c"}}
			},
		},
		{
			name: "application lookup fails",
			build: func() (*stubStorage, *stubTokens, *stubConfig) {
				return &stubStorage{appErr: storage.ErrAppNotFound, user: models.User{ID: 1}},
					&stubTokens{},
					&stubConfig{details: &OAuthUserDetails{Email: "a@b.c"}}
			},
			want: storage.ErrAppNotFound,
		},
		{
			name: "refresh token not persisted",
			build: func() (*stubStorage, *stubTokens, *stubConfig) {
				return &stubStorage{app: models.App{ID: 7, Secret: "s"}, user: models.User{ID: 1}},
					&stubTokens{err: errors.New("redis down")},
					&stubConfig{details: &OAuthUserDetails{Email: "a@b.c"}}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, tk, cfg := tc.build()

			access, refresh, redirect, err := newService(st, tk, cfg).
				Callback(context.Background(), "auth-code", 7, time.Minute, time.Hour)

			require.Error(t, err)
			require.Empty(t, access)
			require.Empty(t, refresh)
			require.Empty(t, redirect)
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
			}
		})
	}
}

// Password login refuses an unverified account; this path does not check
// IsVerified at all. The test states the current behaviour so a future change
// is deliberate rather than accidental.
func TestCallback_DoesNotEnforceEmailVerification(t *testing.T) {
	st := &stubStorage{
		app:  models.App{ID: 7, Secret: "s", RedirectURI: "https://app.test/done"},
		user: models.User{ID: 42, Email: "a@b.c", IsVerified: false},
	}
	cfg := &stubConfig{details: &OAuthUserDetails{Email: "a@b.c", Username: "octocat"}}

	access, _, _, err := newService(st, &stubTokens{}, cfg).
		Callback(context.Background(), "auth-code", 7, time.Minute, time.Hour)

	require.NoError(t, err)
	require.NotEmpty(t, access, "an unverified account still receives a session over oauth")
}
