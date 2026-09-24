package httpApp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/mo7zayed/reqip"
	"github.com/synnfluxx/TrustMeBroID/internal/http/handlers"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	"github.com/synnfluxx/TrustMeBroID/internal/services/oauth"
	"golang.org/x/time/rate"
)

// visitorTTL is how long an idle client keeps its rate-limit bucket.
const visitorTTL = 3 * time.Hour

// sensitiveParams never appear in an access log. The OAuth callback carries the
// authorization code and the CSRF state in the query string, and the previous
// implementation logged r.RequestURI verbatim — which wrote live authorization
// codes into the log stream on every callback.
var sensitiveParams = map[string]struct{}{
	"code":               {},
	"state":              {},
	"token":              {},
	"access_token":       {},
	"refresh_token":      {},
	"verification_token": {},
	"email":              {},
	"password":           {},
}

type App struct {
	router        *mux.Router
	log           *slog.Logger
	bindAddr      string
	srv           *http.Server
	oAuthServer   GitHubOAuthServer
	visitors      map[string]*Visitor
	mu            sync.RWMutex
	rps           int
	burst         int
	cleanerCancel context.CancelFunc
}

type Visitor struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64
}

type GitHubOAuthServer interface {
	CallbackHandler() http.HandlerFunc
	LoginHandler() http.HandlerFunc
}

func NewHTTPApp(storage oauth.Storage, log *slog.Logger, db oauth.TokenProvider, accessTTL, refreshTTL, cleanerDelay time.Duration, rps, burst int) *App {
	bindAddr := os.Getenv("HTTP_BIND_ADDR")

	oauthService := oauth.New(oauth.NewGithubConfig(), storage, db, log)

	app := &App{
		router:      mux.NewRouter(),
		log:         log,
		bindAddr:    bindAddr,
		oAuthServer: handlers.NewHTTPOAuthServer(oauthService, log, accessTTL, refreshTTL),
		visitors:    make(map[string]*Visitor),
		rps:         rps,
		burst:       burst,
	}

	app.configureRouter()
	app.srv = &http.Server{
		Addr:    bindAddr,
		Handler: app,
		// Route net/http's own errors (bad TLS handshakes, malformed requests)
		// into the structured stream instead of the default stderr logger,
		// which bypassed slog entirely and produced unparseable lines.
		ErrorLog: slog.NewLogLogger(log.With(slog.String("component", "net/http")).Handler(), slog.LevelWarn),
	}
	app.cleanerCancel = app.VisitorsCleaner(context.Background(), cleanerDelay)
	return app
}

func (a *App) configureRouter() {
	a.router.Use(a.recoverPanic)
	a.router.Use(a.setRequestID)
	a.router.Use(a.logRequest)
	a.router.Use(a.limit)
	a.router.HandleFunc("/auth/github/login", a.oAuthServer.LoginHandler())
	a.router.HandleFunc("/auth/github/callback", a.oAuthServer.CallbackHandler())
}

// recoverPanic keeps one bad request from taking down the listener and records
// the stack with the request already correlated. net/http's built-in recovery
// drops the connection and logs to its own writer, which never reached slog.
func (a *App) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if errors.Is(r.Context().Err(), context.Canceled) {
					return
				}
				logger.From(r.Context(), a.log).Error("panic in http handler",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Any("panic", rec),
					slog.String("stack", string(debug.Stack())),
					slog.String(logger.KeyOutcome, logger.OutcomeFailed),
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"internal server error"}`))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// setRequestID adopts an upstream correlation id when the proxy supplies one,
// so a request can be followed from Caddy through SSO without a second lookup.
func (a *App) setRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)

		ctx, _ := logger.WithRequestID(r.Context(), a.log, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// logRequest writes one access record per request.
//
// The level is chosen from the status: client mistakes stay at info, 4xx that
// indicate a broken flow are warnings, and only 5xx are errors. That keeps an
// error-level alert meaningful.
func (a *App) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log := logger.From(r.Context(), a.log)

		rw := newResponseWriter(w)
		next.ServeHTTP(rw, r)

		attrs := []any{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("query", redactQuery(r.URL)),
			slog.Int("status", rw.code),
			slog.Int("bytes", rw.bytes),
			slog.String("client_ip", clientIP(r)),
			slog.String("remote_addr", r.RemoteAddr),
			slog.String("user_agent", r.UserAgent()),
			slog.String("referer", r.Referer()),
			sl.Since(start),
		}

		switch {
		case rw.code >= 500:
			attrs = append(attrs, slog.String(logger.KeyOutcome, logger.OutcomeFailed))
			log.Error("http request failed", attrs...)
		case rw.code >= 400:
			attrs = append(attrs, slog.String(logger.KeyOutcome, logger.OutcomeRejected))
			log.Warn("http request rejected", attrs...)
		default:
			attrs = append(attrs, slog.String(logger.KeyOutcome, logger.OutcomeSuccess))
			log.Info("http request completed", attrs...)
		}
	})
}

// redactQuery keeps the shape of the query string — which parameters were
// present — while removing the values that must not be retained.
func redactQuery(u *url.URL) string {
	if u.RawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "[unparsable]"
	}
	for key := range values {
		if _, secret := sensitiveParams[key]; secret {
			values.Set(key, "[REDACTED]")
		}
	}
	return values.Encode()
}

func (a *App) VisitorsCleaner(pctx context.Context, cleanerDelay time.Duration) context.CancelFunc {
	ctx, cancel := context.WithCancel(pctx)

	go func(ctx context.Context) {
		log := a.log.With(slog.String(logger.KeyOp, "http.visitorsCleaner"))
		log.Info("starting rate-limit bucket cleaner",
			slog.Duration("interval", cleanerDelay),
			slog.Duration("visitor_ttl", visitorTTL))

		ticker := time.NewTicker(cleanerDelay)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Info("rate-limit bucket cleaner stopped")
				return
			case <-ticker.C:
				start := time.Now()
				a.mu.Lock()
				before := len(a.visitors)
				for k, v := range a.visitors {
					if time.Since(time.Unix(v.lastSeen.Load(), 0)) >= visitorTTL {
						delete(a.visitors, k)
					}
				}
				after := len(a.visitors)
				a.mu.Unlock()

				// Tracked at info because this map is keyed by a client-supplied
				// address: unbounded growth here is a memory-exhaustion vector,
				// and the only warning is this number trending upwards.
				log.Info("rate-limit buckets swept",
					slog.Int("before", before),
					slog.Int("after", after),
					slog.Int("evicted", before-after),
					sl.Since(start))
			}
		}
	}(ctx)

	return cancel
}

func (a *App) getVisitor(ip string) *Visitor {
	a.mu.RLock()
	visitor, ok := a.visitors[ip]
	a.mu.RUnlock()
	if ok {
		return visitor
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if visitor, ok := a.visitors[ip]; ok {
		return visitor
	}
	visitor = &Visitor{limiter: rate.NewLimiter(rate.Limit(a.rps), a.burst)}
	visitor.lastSeen.Store(time.Now().Unix())
	a.visitors[ip] = visitor
	return visitor
}

// clientIP identifies the caller for rate limiting.
//
// reqip only reads forwarding headers; it returns "" when a client connects
// directly, which is reachable here because the HTTP port is published on all
// interfaces. Without the fallback every direct client shares a single bucket
// keyed by the empty string, so one of them can throttle all the others.
func clientIP(r *http.Request) string {
	if ip := reqip.GetClientIP(r); ip != "" {
		return ip
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

func (a *App) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)

		visitor := a.getVisitor(ip)
		visitor.lastSeen.Store(time.Now().Unix())

		if !visitor.limiter.Allow() {
			a.mu.RLock()
			tracked := len(a.visitors)
			a.mu.RUnlock()

			logger.From(r.Context(), a.log).Warn("http request shed by rate limiter",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("client_ip", ip),
				slog.String("remote_addr", r.RemoteAddr),
				// The bucket key comes from X-Forwarded-For when present, so it
				// is only as trustworthy as the proxy in front. Recording both
				// makes a spoofing attempt visible: the same remote_addr
				// arriving under many client_ip values.
				slog.String("ip_source", "x-forwarded-for or remote addr"),
				slog.Float64("limit_rps", float64(a.rps)),
				slog.Int("burst", a.burst),
				slog.Int("tracked_visitors", tracked),
				slog.String(logger.KeyOutcome, logger.OutcomeRejected),
			)
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return
		}
		a.log.Error("http server terminated",
			slog.String("bind_addr", a.bindAddr),
			slog.String(logger.KeyOutcome, logger.OutcomeFailed),
			sl.Err(err))
		os.Exit(1)
	}
}

func (a *App) Run() error {
	const op = "httpapp.Run"
	log := a.log.With(slog.String(logger.KeyOp, op))

	if a.bindAddr == "" {
		err := fmt.Errorf("HTTP_BIND_ADDR is empty")
		log.Error("cannot start http server", sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("http server listening",
		slog.String("bind_addr", a.bindAddr),
		slog.Int("rate_limit_rps", a.rps),
		slog.Int("rate_limit_burst", a.burst),
		slog.String("routes", "/auth/github/login, /auth/github/callback"))

	return a.srv.ListenAndServe()
}

func (a *App) Stop() error {
	const op = "httpapp.Stop"
	log := a.log.With(slog.String(logger.KeyOp, op))

	start := time.Now()
	log.Info("draining http server", slog.String("bind_addr", a.bindAddr))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	a.cleanerCancel()

	if err := a.srv.Shutdown(ctx); err != nil {
		log.Error("http server did not drain within the grace period",
			slog.Duration("grace", 15*time.Second),
			sl.Err(err), sl.Since(start))
		return err
	}

	log.Info("http server stopped", sl.Since(start))
	return nil
}
