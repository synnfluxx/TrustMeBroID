package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// newStubGithub wires a GithubOAuth against a local server so the whole
// exchange-then-fetch-profile flow runs without touching api.github.com.
func newStubGithub(t *testing.T, handler http.Handler) (*GithubOAuth, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return &GithubOAuth{
		config: &oauth2.Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			RedirectURL:  "https://sso.test/auth/github/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  server.URL + "/login/oauth/authorize",
				TokenURL: server.URL + "/login/oauth/access_token",
			},
			Scopes: []string{"user:email", "read:user"},
		},
		userAPIURL:   server.URL + "/user",
		emailsAPIURL: server.URL + "/user/emails",
	}, server
}

func tokenAndUser(userBody, emailsBody string, emailsStatus int) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gh-token","token_type":"bearer"}`))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(userBody))
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(emailsStatus)
		_, _ = w.Write([]byte(emailsBody))
	})
	return mux
}

func TestNewGithubConfig_ReadsEnvironment(t *testing.T) {
	t.Setenv("GITHUB_CLIENT_ID", "id-from-env")
	t.Setenv("GITHUB_CLIENT_SECRET", "secret-from-env")
	t.Setenv("BASE_URL", "https://sso.test")

	cfg := NewGithubConfig()

	require.Equal(t, "id-from-env", cfg.config.ClientID)
	require.Equal(t, "secret-from-env", cfg.config.ClientSecret)
	require.Equal(t, "https://sso.test/auth/github/callback", cfg.config.RedirectURL)
	require.Contains(t, cfg.config.Scopes, "user:email")
}

func TestURL_CarriesStateAndClientID(t *testing.T) {
	g, _ := newStubGithub(t, http.NotFoundHandler())

	raw := g.URL("nonce:7")

	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	require.Equal(t, "nonce:7", parsed.Query().Get("state"))
	require.Equal(t, "client-id", parsed.Query().Get("client_id"))
}

func TestCallback_UsesProfileEmailWhenPresent(t *testing.T) {
	g, _ := newStubGithub(t, tokenAndUser(
		`{"email":"public@example.test","login":"octocat","avatar_url":"https://avatars.test/a.png"}`,
		`[]`, http.StatusOK))

	details, err := g.Callback(context.Background(), "auth-code")

	require.NoError(t, err)
	require.Equal(t, "public@example.test", details.Email)
	require.Equal(t, "octocat", details.Username)
	require.Equal(t, "https://avatars.test/a.png", details.Avatar)
}

func TestCallback_FallsBackToThePrimaryVerifiedAddress(t *testing.T) {
	g, _ := newStubGithub(t, tokenAndUser(
		`{"email":"","login":"octocat"}`,
		`[{"email":"secondary@example.test","primary":false,"verified":true},
		  {"email":"primary@example.test","primary":true,"verified":true}]`,
		http.StatusOK))

	details, err := g.Callback(context.Background(), "auth-code")

	require.NoError(t, err)
	require.Equal(t, "primary@example.test", details.Email)
}

// Documents a real hazard: when no address is both primary and verified, the
// first entry is used regardless of its verified flag. An attacker who adds an
// unverified address to their GitHub account can therefore present it as their
// identity here.
func TestCallback_FallsBackToAnUnverifiedAddress(t *testing.T) {
	g, _ := newStubGithub(t, tokenAndUser(
		`{"email":"","login":"octocat"}`,
		`[{"email":"unverified@example.test","primary":false,"verified":false}]`,
		http.StatusOK))

	details, err := g.Callback(context.Background(), "auth-code")

	require.NoError(t, err)
	require.Equal(t, "unverified@example.test", details.Email,
		"the first address is accepted even when it is not verified")
}

func TestCallback_NoAddressAvailable(t *testing.T) {
	g, _ := newStubGithub(t, tokenAndUser(`{"email":"","login":"octocat"}`, `[]`, http.StatusOK))

	_, err := g.Callback(context.Background(), "auth-code")

	require.Error(t, err)
}

func TestCallback_EmailsEndpointError(t *testing.T) {
	g, _ := newStubGithub(t, tokenAndUser(`{"email":"","login":"octocat"}`, `{}`, http.StatusForbidden))

	_, err := g.Callback(context.Background(), "auth-code")

	require.Error(t, err)
	require.Contains(t, err.Error(), "403")
}

func TestCallback_TokenExchangeFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	g, _ := newStubGithub(t, mux)

	_, err := g.Callback(context.Background(), "bad-code")

	require.Error(t, err)
}

func TestCallback_MalformedProfileJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gh-token","token_type":"bearer"}`))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	})
	g, _ := newStubGithub(t, mux)

	_, err := g.Callback(context.Background(), "auth-code")

	require.Error(t, err)
}
