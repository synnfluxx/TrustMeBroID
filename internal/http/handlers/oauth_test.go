package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	discardHandler "github.com/synnfluxx/TrustMeBroID/internal/lib/logger/handlers/discardHandler"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
)

type stubOAuth struct {
	loginState string
	loginURL   string
	loginErr   error

	access      string
	refresh     string
	redirectURI string
	callbackErr error

	callbackCode  string
	callbackAppID int64
	callbackCalls int
}

func (s *stubOAuth) Login(context.Context, int64) (string, string, error) {
	return s.loginState, s.loginURL, s.loginErr
}

func (s *stubOAuth) Callback(_ context.Context, code string, appID int64, _, _ time.Duration) (string, string, string, error) {
	s.callbackCalls++
	s.callbackCode = code
	s.callbackAppID = appID
	return s.access, s.refresh, s.redirectURI, s.callbackErr
}

func newServer(stub *stubOAuth) *Server {
	return NewHTTPOAuthServer(stub, discardHandler.NewDiscardLogger(), 5*time.Minute, 168*time.Hour)
}

func callbackRequest(state, cookie string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=auth-code&state="+url.QueryEscape(state), nil)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: "oauth_state", Value: cookie})
	}
	return r
}

// ------------------------------------------------------------ Login ---------

func TestLoginHandler_SetsStateCookieAndRedirects(t *testing.T) {
	stub := &stubOAuth{loginState: "nonce:7", loginURL: "https://github.test/authorize?state=nonce%3A7"}
	rec := httptest.NewRecorder()

	newServer(stub).LoginHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/github/login?app_id=7", nil))

	require.Equal(t, http.StatusTemporaryRedirect, rec.Code)
	require.Equal(t, stub.loginURL, rec.Header().Get("Location"))

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	got := cookies[0]
	require.Equal(t, "oauth_state", got.Name)
	require.Equal(t, "nonce:7", got.Value)
	require.True(t, got.HttpOnly, "the state cookie must not be readable from JavaScript")
	require.True(t, got.Secure)
	require.Equal(t, http.SameSiteLaxMode, got.SameSite)
	require.Equal(t, 600, got.MaxAge)
}

func TestLoginHandler_BadAppID(t *testing.T) {
	for _, tc := range []struct{ name, query string }{
		{"missing", "/auth/github/login"},
		{"empty", "/auth/github/login?app_id="},
		{"not a number", "/auth/github/login?app_id=abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			newServer(&stubOAuth{}).LoginHandler()(rec, httptest.NewRequest(http.MethodGet, tc.query, nil))

			require.Equal(t, http.StatusBadRequest, rec.Code)
			require.Empty(t, rec.Result().Cookies())
		})
	}
}

func TestLoginHandler_UnknownApplication(t *testing.T) {
	stub := &stubOAuth{loginErr: storage.ErrAppNotFound}
	rec := httptest.NewRecorder()

	newServer(stub).LoginHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/github/login?app_id=7", nil))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Empty(t, rec.Header().Get("Location"))
}

// Any other Login error used to fall through the error block and redirect the
// browser to an empty Location.
func TestLoginHandler_UnexpectedErrorDoesNotRedirect(t *testing.T) {
	stub := &stubOAuth{loginErr: errors.New("database down")}
	rec := httptest.NewRecorder()

	newServer(stub).LoginHandler()(rec, httptest.NewRequest(http.MethodGet, "/auth/github/login?app_id=7", nil))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Empty(t, rec.Header().Get("Location"))
}

// --------------------------------------------------------- Callback --------

func TestCallbackHandler_Success(t *testing.T) {
	stub := &stubOAuth{access: "access-token", refresh: "refresh-token", redirectURI: "https://app.test/done"}
	rec := httptest.NewRecorder()

	newServer(stub).CallbackHandler()(rec, callbackRequest("nonce:7", "nonce:7"))

	require.Equal(t, http.StatusPermanentRedirect, rec.Code)
	require.Equal(t, 1, stub.callbackCalls)
	require.Equal(t, "auth-code", stub.callbackCode)
	require.Equal(t, int64(7), stub.callbackAppID)
	require.True(t, strings.HasPrefix(rec.Header().Get("Location"), "https://app.test/done?token="))

	var refreshCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "refreshToken" {
			refreshCookie = c
		}
	}
	require.NotNil(t, refreshCookie)
	require.Equal(t, "refresh-token", refreshCookie.Value)
	require.True(t, refreshCookie.HttpOnly)
	require.True(t, refreshCookie.Secure)
}

// The core CSRF guard. Each of these must stop the exchange before the service
// is called at all.
func TestCallbackHandler_StateValidation(t *testing.T) {
	cases := []struct {
		name   string
		state  string
		cookie string
	}{
		{"state does not match the cookie", "nonce:7", "a-different-nonce:7"},
		{"no cookie at all", "nonce:7", ""},
		{"empty state", "", "nonce:7"},
		{"state without an app id", "nonce", "nonce"},
		{"state with an empty app id", "nonce:", "nonce:"},
		{"non-numeric app id", "nonce:abc", "nonce:abc"},
		{"attacker supplies only the query", "attacker-nonce:7", "victim-nonce:7"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubOAuth{access: "a", refresh: "r", redirectURI: "https://app.test/done"}
			rec := httptest.NewRecorder()

			newServer(stub).CallbackHandler()(rec, callbackRequest(tc.state, tc.cookie))

			require.Equal(t, http.StatusBadRequest, rec.Code)
			require.Zero(t, stub.callbackCalls, "the authorization code must not be exchanged")
			require.Empty(t, rec.Header().Get("Location"))

			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, "bad request", body["error"])
		})
	}
}

func TestCallbackHandler_ServiceFailure(t *testing.T) {
	stub := &stubOAuth{callbackErr: errors.New("github rejected the code")}
	rec := httptest.NewRecorder()

	newServer(stub).CallbackHandler()(rec, callbackRequest("nonce:7", "nonce:7"))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Empty(t, rec.Header().Get("Location"))
}

// The error body must not echo the provider's message back to the browser.
func TestCallbackHandler_ErrorBodyIsGeneric(t *testing.T) {
	stub := &stubOAuth{callbackErr: errors.New("client_secret 90f3ab is invalid")}
	rec := httptest.NewRecorder()

	newServer(stub).CallbackHandler()(rec, callbackRequest("nonce:7", "nonce:7"))

	require.NotContains(t, rec.Body.String(), "90f3ab")
	require.Contains(t, rec.Body.String(), "internal server error")
}

func TestRedirectHost(t *testing.T) {
	require.Equal(t, "app.test", redirectHost("https://app.test/done?token=secret"))
	require.Equal(t, "[unparsable]", redirectHost(""))
	require.Equal(t, "[unparsable]", redirectHost("::not a url::"))
}

func TestRespondError_ShapeAndContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	newServer(&stubOAuth{}).respondError(rec, http.StatusTeapot, "nope")

	require.Equal(t, http.StatusTeapot, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "nope", body["error"])
}
