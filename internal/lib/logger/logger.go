// Package logger builds the process-wide structured logger and carries a request-scoped logger through context.
package logger

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/dusted-go/logging/v2/handlers/prettylog"
)

const (
	EnvLocal = "local"
	EnvDev   = "dev"
	EnvProd  = "prod"
)

// RequestIDHeader is the HTTP header and the gRPC metadata key that carries the correlation id between AuraLift and SSO.
const RequestIDHeader = "x-request-id"

// Keys used on every record so queries stay uniform across both services.
const (
	KeyService   = "service"
	KeyEnv       = "env"
	KeyOp        = "op"
	KeyRequestID = "request_id"
	KeyError     = "error"
	KeyErrorType = "error_type"
	KeyDuration  = "duration_ms"
	KeyUserID    = "user_id"
	KeyAppID     = "app_id"
	KeyOutcome   = "outcome"
)

// Outcome values.
const (
	OutcomeSuccess  = "success"
	OutcomeRejected = "rejected" // caller's fault: bad input, wrong credentials
	OutcomeFailed   = "failed"   // our fault: dependency error, bug
)

// redactedKeys never reach the output, whatever a call site passes.
var redactedKeys = map[string]struct{}{
	"password":           {},
	"pass":               {},
	"passhash":           {},
	"pass_hash":          {},
	"secret":             {},
	"app_secret":         {},
	"client_secret":      {},
	"master_key":         {},
	"admin_token":        {},
	"refresh_key":        {},
	"token":              {},
	"access_token":       {},
	"refresh_token":      {},
	"authorization":      {},
	"code":               {},
	"credentials":        {},
	"verification_code":  {},
	"verification_token": {},
}

const redactedValue = "[REDACTED]"

// levelVar lets SetLevel change verbosity for the whole process at runtime.
var levelVar = new(slog.LevelVar)

// Setup returns the root logger for the process.
func Setup(env, service string) *slog.Logger {
	level, levelUnknown := parseLevel(os.Getenv("LOG_LEVEL"), env)
	levelVar.Set(level)

	opts := &slog.HandlerOptions{
		Level:       levelVar,
		ReplaceAttr: replaceAttr,
		// Source costs a caller lookup per record.
		AddSource: true,
	}

	var handler slog.Handler
	envUnknown := false
	switch env {
	case EnvLocal, EnvDev:
		handler = prettylog.NewHandler(opts)
	case EnvProd:
		handler = slog.NewJSONHandler(os.Stdout, opts)
	default:
		// Never leave the handler nil: slog.New(nil) panics on first use.
		envUnknown = true
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	log := slog.New(handler).With(
		slog.String(KeyService, service),
		slog.String(KeyEnv, env),
	)

	if envUnknown {
		log.Warn("unknown environment, falling back to json handler at info level",
			slog.String("expected", strings.Join([]string{EnvLocal, EnvDev, EnvProd}, ", ")))
	}
	if levelUnknown {
		log.Warn("unknown LOG_LEVEL, using the default for this environment",
			slog.String("value", os.Getenv("LOG_LEVEL")))
	}

	return log
}

// SetLevel changes verbosity for every logger derived from Setup.
func SetLevel(l slog.Level) { levelVar.Set(l) }

// Level reports the current threshold.
func Level() slog.Level { return levelVar.Level() }

func parseLevel(raw, env string) (slog.Level, bool) {
	if raw == "" {
		if env == EnvProd {
			return slog.LevelInfo, false
		}
		return slog.LevelDebug, false
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug, false
	case "info":
		return slog.LevelInfo, false
	case "warn", "warning":
		return slog.LevelWarn, false
	case "error":
		return slog.LevelError, false
	default:
		if env == EnvProd {
			return slog.LevelInfo, true
		}
		return slog.LevelDebug, true
	}
}

func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if _, secret := redactedKeys[strings.ToLower(a.Key)]; secret {
		if a.Value.Kind() == slog.KindString && a.Value.String() == "" {
			return slog.String(a.Key, "")
		}
		return slog.String(a.Key, redactedValue)
	}

	if a.Key == slog.SourceKey {
		if src, ok := a.Value.Any().(*slog.Source); ok && src != nil {
			src.File = trimSourcePath(src.File)
		}
	}

	return a
}

func trimSourcePath(file string) string {
	parts := strings.Split(file, "/")
	if len(parts) <= 3 {
		return file
	}
	return strings.Join(parts[len(parts)-3:], "/")
}

type loggerCtxKey struct{}

type requestIDCtxKey struct{}

// Into stores a request-scoped logger so downstream layers inherit the correlation id without threading a logger through every signature.
func Into(ctx context.Context, log *slog.Logger) context.Context {
	if log == nil {
		return ctx
	}
	return context.WithValue(ctx, loggerCtxKey{}, log)
}

// From returns the request-scoped logger, or fallback when the context carries none (background jobs, tests, direct service calls).
func From(ctx context.Context, fallback *slog.Logger) *slog.Logger {
	if ctx != nil {
		if log, ok := ctx.Value(loggerCtxKey{}).(*slog.Logger); ok && log != nil {
			return log
		}
	}
	if fallback != nil {
		return fallback
	}
	return slog.Default()
}

// Op returns the request-scoped logger tagged with the operation name.
func Op(ctx context.Context, fallback *slog.Logger, op string) *slog.Logger {
	return From(ctx, fallback).With(slog.String(KeyOp, op))
}

// WithRequestID stores the correlation id and tags the context logger with it.
func WithRequestID(ctx context.Context, log *slog.Logger, id string) (context.Context, *slog.Logger) {
	if id == "" {
		return ctx, log
	}
	ctx = context.WithValue(ctx, requestIDCtxKey{}, id)
	log = log.With(slog.String(KeyRequestID, id))
	return Into(ctx, log), log
}

// RequestID returns the correlation id carried by ctx, or "".
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(requestIDCtxKey{}).(string)
	return id
}
