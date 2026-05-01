package httpApp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/mo7zayed/reqip"
	"github.com/synnfluxx/TrustMeBroID/internal/http/handlers"
	"github.com/synnfluxx/TrustMeBroID/internal/services/oauth"
	"golang.org/x/time/rate"
)

type App struct {
	router        *mux.Router
	log           *slog.Logger
	bindAddr      string
	srv           *http.Server
	oAuthServer   OAuthServer
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

type ctxKey int8

const (
	ctxKeyUser ctxKey = iota
	ctxKeyRequestID
)

type OAuthServer interface {
	GitHubOAuthCallbackHandler() http.HandlerFunc
	GitHubLoginHandler() http.HandlerFunc
}

func NewHTTPApp(storage handlers.Storage, log *slog.Logger, db oauth.TokenProvider, accessTTL, refreshTTL, cleanerDelay time.Duration, rps, burst int) *App {
	bindAddr := os.Getenv("HTTP_BIND_ADDR")

	app := &App{
		router:      mux.NewRouter(),
		log:         log,
		bindAddr:    bindAddr,
		oAuthServer: handlers.NewHTTPHandlerServer(storage, db, log, accessTTL, refreshTTL),
		visitors:    make(map[string]*Visitor),
		rps:         rps,
		burst:       burst,
	}

	app.configureRouter()
	app.srv = &http.Server{Addr: bindAddr, Handler: app}
	app.cleanerCancel = app.VisitorsCleaner(context.Background(), cleanerDelay)
	return app
}

func (a *App) configureRouter() {
	a.router.Use(a.setRequestID)
	a.router.Use(a.logRequest)
	a.router.Use(a.limit)
	a.router.HandleFunc("/auth/github/login", a.oAuthServer.GitHubLoginHandler())
	a.router.HandleFunc("/auth/github/callback", a.oAuthServer.GitHubOAuthCallbackHandler())
}

func (a *App) VisitorsCleaner(pctx context.Context, cleanerDelay time.Duration) context.CancelFunc {
	ctx, cancel := context.WithCancel(pctx)

	go func(ctx context.Context) {
		ticker := time.NewTicker(cleanerDelay)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.mu.Lock()
				for k, v := range a.visitors {
					if time.Since(time.Unix(v.lastSeen.Load(), 0)) >= 3*time.Hour {
						delete(a.visitors, k)
					}
				}
				a.mu.Unlock()
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
	if visitor, ok := a.visitors[ip]; !ok {
		visitor = &Visitor{
			limiter: rate.NewLimiter(rate.Limit(a.rps), a.burst),
		}
		visitor.lastSeen.Store(time.Now().Unix())
		a.visitors[ip] = visitor
		return visitor
	} else {
		return visitor
	}
}

func (a *App) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ip := reqip.GetClientIP(r)

			visitor := a.getVisitor(ip)
			visitor.lastSeen.Store(time.Now().Unix())
			if !visitor.limiter.Allow() {
				http.Error(w, http.StatusText(429), http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
}

func (a *App) setRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			id := uuid.New().String()
			w.Header().Set("X-Request-ID", id)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyRequestID, id)))
		})
}

func (a *App) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			log := a.log.With("http request", "remote_addr", r.RemoteAddr, "request_id", r.Context().Value(ctxKeyRequestID))
			log.Info("started", "method", r.Method, "URI", r.RequestURI)
			start := time.Now()
			rw := &responseWriter{http.StatusOK, w}
			next.ServeHTTP(rw, r)

			switch {
			case rw.code >= 500:
				log.Error("request completed", "code", rw.code, "status", http.StatusText(rw.code), "duration", time.Since(start).Milliseconds())
			case rw.code >= 400:
				log.Warn("request completed", "code", rw.code, "status", http.StatusText(rw.code), "duration", time.Since(start).Milliseconds())
			default:
				log.Info("request completed", "code", rw.code, "status", http.StatusText(rw.code), "duration", time.Since(start).Milliseconds())
			}

		},
	)
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return
		}
		panic(err)
	}
}

func (a *App) Run() error {
	const op = "httpapp.Run"
	log := a.log.With(slog.String("op", op), slog.String("port", a.bindAddr))
	log.Info("Starting HTTP server", slog.String("port", a.bindAddr))
	return a.srv.ListenAndServe()
}

func (a *App) Stop() error {
	const op = "httpapp.Stop"
	log := a.log.With(slog.String("op", op))
	log.Info("Stopping HTTP server", slog.String("port", a.bindAddr))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	a.cleanerCancel()
	err := a.srv.Shutdown(ctx)
	if err != nil {
		return err
	}

	log.Info("HTTP server succesfully stopped!")
	return nil
}
