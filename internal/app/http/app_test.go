package httpApp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger"
	discardHandler "github.com/synnfluxx/TrustMeBroID/internal/lib/logger/handlers/discardHandler"
)

func newTestApp(rps, burst int) *App {
	return &App{
		log:      discardHandler.NewDiscardLogger(),
		visitors: make(map[string]*Visitor),
		rps:      rps,
		burst:    burst,
	}
}

// ----------------------------------------------------------- redactQuery ----

// The OAuth callback carries the authorization code and the CSRF state in the
// query string. Logging the raw URI wrote live credentials into the log.
func TestRedactQuery_RemovesCredentialsKeepsShape(t *testing.T) {
	u, err := url.Parse("/auth/github/callback?code=live-auth-code&state=nonce%3A7&app_id=7")
	require.NoError(t, err)

	got := redactQuery(u)

	require.NotContains(t, got, "live-auth-code")
	require.NotContains(t, got, "nonce:7")
	require.Contains(t, got, "code=%5BREDACTED%5D")
	require.Contains(t, got, "state=%5BREDACTED%5D")
	// Non-sensitive parameters survive, so the shape of the request is still
	// readable in the log.
	require.Contains(t, got, "app_id=7")
}

func TestRedactQuery_AllSensitiveParams(t *testing.T) {
	for _, key := range []string{"code", "state", "token", "access_token", "refresh_token", "verification_token", "email", "password"} {
		t.Run(key, func(t *testing.T) {
			u, err := url.Parse("/x?" + key + "=super-secret")
			require.NoError(t, err)

			require.NotContains(t, redactQuery(u), "super-secret")
		})
	}
}

func TestRedactQuery_EdgeCases(t *testing.T) {
	empty, _ := url.Parse("/x")
	require.Empty(t, redactQuery(empty))

	plain, _ := url.Parse("/x?page=2&sort=asc")
	got := redactQuery(plain)
	require.Contains(t, got, "page=2")
	require.Contains(t, got, "sort=asc")

	broken := &url.URL{RawQuery: "%zz"}
	require.Equal(t, "[unparsable]", redactQuery(broken))
}

// -------------------------------------------------------- responseWriter ----

func TestResponseWriter_RecordsStatusAndSize(t *testing.T) {
	rec := httptest.NewRecorder()
	w := newResponseWriter(rec)

	w.WriteHeader(http.StatusCreated)
	n, err := w.Write([]byte("hello"))

	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.Equal(t, http.StatusCreated, w.code)
	require.Equal(t, 5, w.bytes)
}

func TestResponseWriter_ImplicitTwoHundred(t *testing.T) {
	w := newResponseWriter(httptest.NewRecorder())

	_, err := w.Write([]byte("body without an explicit WriteHeader"))

	require.NoError(t, err)
	require.Equal(t, http.StatusOK, w.code)
	require.True(t, w.wroteHeader)
}

// net/http panics on a second WriteHeader; the wrapper must swallow it the way
// the standard library's own does.
func TestResponseWriter_IgnoresSecondWriteHeader(t *testing.T) {
	w := newResponseWriter(httptest.NewRecorder())

	w.WriteHeader(http.StatusTeapot)
	w.WriteHeader(http.StatusInternalServerError)

	require.Equal(t, http.StatusTeapot, w.code)
}

func TestResponseWriter_AccumulatesMultipleWrites(t *testing.T) {
	w := newResponseWriter(httptest.NewRecorder())

	_, _ = w.Write([]byte("abc"))
	_, _ = w.Write([]byte("de"))

	require.Equal(t, 5, w.bytes)
}

// ----------------------------------------------------------- rate limit ----

func TestLimit_ShedsOverBudgetAndIsolatesClients(t *testing.T) {
	app := newTestApp(1, 1)
	handler := app.limit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	request := func(ip string) int {
		r := httptest.NewRequest(http.MethodGet, "/auth/github/login", nil)
		r.RemoteAddr = ip + ":1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		return rec.Code
	}

	require.Equal(t, http.StatusOK, request("10.0.0.1"))
	require.Equal(t, http.StatusTooManyRequests, request("10.0.0.1"))
	// A different client has its own bucket.
	require.Equal(t, http.StatusOK, request("10.0.0.2"))
}

// The bucket key comes from X-Forwarded-For when present, so a caller can mint
// a fresh budget per request by rotating the header. This also means the map
// grows without bound under a spoofing client.
func TestLimit_BucketKeyFollowsForwardedHeader(t *testing.T) {
	app := newTestApp(1, 1)
	handler := app.limit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i, forwarded := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		r := httptest.NewRequest(http.MethodGet, "/auth/github/login", nil)
		r.RemoteAddr = "10.0.0.9:1234"
		r.Header.Set("X-Forwarded-For", forwarded)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		require.Equal(t, http.StatusOK, rec.Code, "request %d was throttled", i)
	}

	app.mu.RLock()
	tracked := len(app.visitors)
	app.mu.RUnlock()
	require.Equal(t, 3, tracked, "one bucket per spoofed address")
}

func TestGetVisitor_ReusesTheSameBucket(t *testing.T) {
	app := newTestApp(5, 5)

	first := app.getVisitor("10.0.0.1")
	second := app.getVisitor("10.0.0.1")

	require.Same(t, first, second)
}

func TestGetVisitor_IsSafeUnderConcurrency(t *testing.T) {
	app := newTestApp(100, 100)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			app.getVisitor("10.0.0.1")
		}()
	}
	wg.Wait()

	app.mu.RLock()
	defer app.mu.RUnlock()
	require.Len(t, app.visitors, 1, "concurrent first-use must not create duplicate buckets")
}

// ------------------------------------------------------------- recovery ----

func TestRecoverPanic_ReturnsJSONAndKeepsServing(t *testing.T) {
	app := newTestApp(10, 10)
	handler := app.recoverPanic(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("handler exploded")
	}))

	rec := httptest.NewRecorder()
	require.NotPanics(t, func() {
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/github/callback", nil))
	})

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.Contains(t, rec.Body.String(), "internal server error")
	// The panic value must not be echoed to the caller.
	require.NotContains(t, rec.Body.String(), "handler exploded")
}

func TestRecoverPanic_LeavesNormalResponsesAlone(t *testing.T) {
	app := newTestApp(10, 10)
	handler := app.recoverPanic(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	require.Equal(t, http.StatusNoContent, rec.Code)
}

// ------------------------------------------------------------ request id ----

func TestSetRequestID_AdoptsUpstreamHeader(t *testing.T) {
	app := newTestApp(10, 10)

	var seen string
	handler := app.setRequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = logger.RequestID(r.Context())
	}))

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("X-Request-ID", "from-caddy")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)

	require.Equal(t, "from-caddy", seen)
	require.Equal(t, "from-caddy", rec.Header().Get("X-Request-ID"))
}

func TestSetRequestID_MintsAndEchoesWhenAbsent(t *testing.T) {
	app := newTestApp(10, 10)

	var seen string
	handler := app.setRequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = logger.RequestID(r.Context())
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	require.NotEmpty(t, seen)
	require.Equal(t, seen, rec.Header().Get("X-Request-ID"))
}

// -------------------------------------------------------------- logging ----

func TestLogRequest_DoesNotAlterTheResponse(t *testing.T) {
	app := newTestApp(10, 10)
	handler := app.logRequest(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("payload"))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x?code=secret", nil))

	require.Equal(t, http.StatusAccepted, rec.Code)
	require.Equal(t, "payload", rec.Body.String())
}

// ------------------------------------------------------------- cleaner -----

func TestVisitorsCleaner_EvictsIdleBucketsAndStops(t *testing.T) {
	app := newTestApp(10, 10)

	fresh := app.getVisitor("fresh")
	fresh.lastSeen.Store(time.Now().Unix())
	idle := app.getVisitor("idle")
	idle.lastSeen.Store(time.Now().Add(-visitorTTL - time.Minute).Unix())

	cancel := app.VisitorsCleaner(t.Context(), 10*time.Millisecond)
	defer cancel()

	require.Eventually(t, func() bool {
		app.mu.RLock()
		defer app.mu.RUnlock()
		_, idleStillThere := app.visitors["idle"]
		_, freshStillThere := app.visitors["fresh"]
		return !idleStillThere && freshStillThere
	}, 2*time.Second, 10*time.Millisecond)
}

// ---------------------------------------------------------------- server ----

func TestRun_RefusesToStartWithoutBindAddr(t *testing.T) {
	app := newTestApp(10, 10)
	app.bindAddr = ""

	err := app.Run()

	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "HTTP_BIND_ADDR"))
}

func TestStop_DrainsAndStopsTheCleaner(t *testing.T) {
	app := newTestApp(10, 10)
	app.srv = &http.Server{}
	app.cleanerCancel = func() {}

	require.NoError(t, app.Stop())
}

func TestMustRun_ReturnsQuietlyOnServerClosed(t *testing.T) {
	// A graceful shutdown surfaces as http.ErrServerClosed and must not be
	// treated as a crash.
	app := newTestApp(10, 10)
	app.bindAddr = "127.0.0.1:0"
	app.srv = &http.Server{Addr: "127.0.0.1:0"}
	require.NoError(t, app.srv.Close())

	require.NotPanics(t, app.MustRun)
}

func TestClientIP_PrefersForwardedThenRemoteAddr(t *testing.T) {
	forwarded := httptest.NewRequest(http.MethodGet, "/x", nil)
	forwarded.RemoteAddr = "10.0.0.9:1234"
	forwarded.Header.Set("X-Forwarded-For", "1.1.1.1")
	require.Equal(t, "1.1.1.1", clientIP(forwarded))

	direct := httptest.NewRequest(http.MethodGet, "/x", nil)
	direct.RemoteAddr = "10.0.0.9:1234"
	require.Equal(t, "10.0.0.9", clientIP(direct))

	noPort := httptest.NewRequest(http.MethodGet, "/x", nil)
	noPort.RemoteAddr = "10.0.0.9"
	require.Equal(t, "10.0.0.9", clientIP(noPort))

	unknown := httptest.NewRequest(http.MethodGet, "/x", nil)
	unknown.RemoteAddr = ""
	require.Equal(t, "unknown", clientIP(unknown))
}
