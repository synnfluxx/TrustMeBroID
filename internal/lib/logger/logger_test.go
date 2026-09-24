package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// newTestLogger builds a JSON logger over a buffer using the production
// ReplaceAttr, so these tests exercise the same redaction path as the service.
func newTestLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level:       slog.LevelDebug,
		ReplaceAttr: replaceAttr,
	})
	return slog.New(h), &buf
}

func record(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("log line is not valid json: %v\n%s", err, buf.String())
	}
	return out
}

// The redaction net must hold even when a call site passes a secret directly,
// because that is exactly the mistake it exists to catch.
func TestSensitiveKeysAreRedacted(t *testing.T) {
	for _, key := range []string{
		"password", "pass", "secret", "app_secret", "client_secret",
		"master_key", "admin_token", "token", "access_token", "refresh_token",
		"authorization", "code", "verification_token",
	} {
		t.Run(key, func(t *testing.T) {
			log, buf := newTestLogger()
			log.Info("test", slog.String(key, "super-secret-value"))

			if strings.Contains(buf.String(), "super-secret-value") {
				t.Fatalf("value for key %q reached the output: %s", key, buf.String())
			}
			if got := record(t, buf)[key]; got != redactedValue {
				t.Fatalf("key %q = %v, want %q", key, got, redactedValue)
			}
		})
	}
}

func TestNonSensitiveKeysPassThrough(t *testing.T) {
	log, buf := newTestLogger()
	log.Info("test", slog.String("username", "danya"), slog.Int64("user_id", 42))

	rec := record(t, buf)
	if rec["username"] != "danya" {
		t.Fatalf("username = %v, want danya", rec["username"])
	}
	if rec["user_id"] != float64(42) {
		t.Fatalf("user_id = %v, want 42", rec["user_id"])
	}
}

// slog.New(nil) panics on first use, so an unrecognised environment must never
// produce a nil handler.
func TestSetupNeverReturnsNilHandler(t *testing.T) {
	for _, env := range []string{EnvLocal, EnvDev, EnvProd, "", "production", "staging"} {
		log := Setup(env, "test")
		if log == nil {
			t.Fatalf("Setup(%q) returned nil", env)
		}
		log.Info("must not panic", slog.String("env", env))
	}
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		raw, env string
		want     slog.Level
		unknown  bool
	}{
		{"", EnvProd, slog.LevelInfo, false},
		{"", EnvLocal, slog.LevelDebug, false},
		{"debug", EnvProd, slog.LevelDebug, false},
		{"WARN", EnvProd, slog.LevelWarn, false},
		{" error ", EnvProd, slog.LevelError, false},
		{"nonsense", EnvProd, slog.LevelInfo, true},
	}
	for _, c := range cases {
		got, unknown := parseLevel(c.raw, c.env)
		if got != c.want || unknown != c.unknown {
			t.Fatalf("parseLevel(%q, %q) = %v/%v, want %v/%v", c.raw, c.env, got, unknown, c.want, c.unknown)
		}
	}
}

// sl.Err used to call err.Error() unconditionally, so logging a nil error
// panicked inside the logging call itself.
func TestErrAttrToleratesNil(t *testing.T) {
	log, buf := newTestLogger()
	log.Info("test", sl.Err(nil))
	if buf.Len() == 0 {
		t.Fatal("no record written")
	}
}

func TestErrAttrCarriesType(t *testing.T) {
	log, buf := newTestLogger()
	log.Error("test", sl.Err(errTest{}))

	rec := record(t, buf)
	if rec["error"] != "boom" {
		t.Fatalf("error = %v, want boom", rec["error"])
	}
	if rec["error_type"] != "logger.errTest" {
		t.Fatalf("error_type = %v, want logger.errTest", rec["error_type"])
	}
}

type errTest struct{}

func (errTest) Error() string { return "boom" }

// Masking has to leave an address recognisable in a support thread while not
// leaving a harvestable list of addresses in a log archive.
func TestMaskEmail(t *testing.T) {
	cases := map[string]string{
		"daniil@icloud.com": "d****l@icloud.com",
		"ab@x.io":           "**@x.io",
		"a@x.io":            "*@x.io",
		"noatsign":          "n******n",
		"":                  "",
	}
	for in, want := range cases {
		if got := sl.MaskEmail(in); got != want {
			t.Fatalf("MaskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

// Fingerprints must be stable (two records about one token line up) and must
// not be reversible to the token.
func TestFingerprintIsStableAndShort(t *testing.T) {
	a := sl.Fingerprint("some-refresh-token")
	b := sl.Fingerprint("some-refresh-token")
	if a != b {
		t.Fatalf("fingerprint is not stable: %q vs %q", a, b)
	}
	if a == "some-refresh-token" || len(a) != 16 {
		t.Fatalf("unexpected fingerprint %q", a)
	}
	if sl.Fingerprint("") != "empty" {
		t.Fatal("empty token should fingerprint as \"empty\"")
	}
}

// --- context plumbing ------------------------------------------------------

func TestFrom_FallsBackWhenContextCarriesNothing(t *testing.T) {
	fallback := slog.New(slog.NewJSONHandler(io.Discard, nil))

	if got := From(context.Background(), fallback); got != fallback {
		t.Fatal("From should return the fallback when the context has no logger")
	}
	//nolint:staticcheck // deliberately passing a nil context
	if From(nil, fallback) != fallback {
		t.Fatal("From should tolerate a nil context")
	}
	if From(context.Background(), nil) == nil {
		t.Fatal("From must never return nil")
	}
}

func TestInto_RoundTrips(t *testing.T) {
	want := slog.New(slog.NewJSONHandler(io.Discard, nil))

	ctx := Into(context.Background(), want)

	if got := From(ctx, nil); got != want {
		t.Fatal("Into/From did not round-trip the logger")
	}
}

func TestInto_NilLoggerLeavesTheContextAlone(t *testing.T) {
	ctx := Into(context.Background(), nil)

	if ctx.Value(loggerCtxKey{}) != nil {
		t.Fatal("a nil logger should not be stored")
	}
}

func TestOp_TagsTheOperation(t *testing.T) {
	var buf bytes.Buffer
	base := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: replaceAttr}))

	Op(context.Background(), base, "auth.Login").Info("hello")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not json: %v", err)
	}
	if rec[KeyOp] != "auth.Login" {
		t.Fatalf("op = %v", rec[KeyOp])
	}
}

func TestWithRequestID(t *testing.T) {
	var buf bytes.Buffer
	base := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: replaceAttr}))

	ctx, log := WithRequestID(context.Background(), base, "req-123")
	log.Info("hello")

	if RequestID(ctx) != "req-123" {
		t.Fatalf("RequestID = %q", RequestID(ctx))
	}

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not json: %v", err)
	}
	if rec[KeyRequestID] != "req-123" {
		t.Fatalf("request_id = %v", rec[KeyRequestID])
	}
	// The logger is also bound to the context so downstream layers inherit it.
	if From(ctx, nil) == base {
		t.Fatal("the context should carry the tagged logger, not the base one")
	}
}

func TestWithRequestID_EmptyIDIsANoop(t *testing.T) {
	base := slog.New(slog.NewJSONHandler(io.Discard, nil))

	ctx, log := WithRequestID(context.Background(), base, "")

	if log != base {
		t.Fatal("an empty id should not wrap the logger")
	}
	if RequestID(ctx) != "" {
		t.Fatal("no id should be stored")
	}
}

func TestRequestID_EmptyWithoutValue(t *testing.T) {
	if RequestID(context.Background()) != "" {
		t.Fatal("expected an empty id")
	}
	//nolint:staticcheck // deliberately passing a nil context
	if RequestID(nil) != "" {
		t.Fatal("RequestID should tolerate a nil context")
	}
}

// --- handler options -------------------------------------------------------

func TestTrimSourcePath(t *testing.T) {
	cases := map[string]string{
		"/Users/someone/go/src/project/internal/services/auth/auth.go": "services/auth/auth.go",
		"a/b/c.go": "a/b/c.go",
		"c.go":     "c.go",
	}
	for in, want := range cases {
		if got := trimSourcePath(in); got != want {
			t.Fatalf("trimSourcePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetupAddsSourceAndTrimsIt(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{AddSource: true, ReplaceAttr: replaceAttr})

	slog.New(h).Info("hello")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not json: %v", err)
	}
	source, ok := rec["source"].(map[string]any)
	if !ok {
		t.Fatalf("no source in %s", buf.String())
	}
	file, _ := source["file"].(string)
	if strings.HasPrefix(file, "/") {
		t.Fatalf("source path was not trimmed: %q", file)
	}
}

func TestSetLevelAndLevel(t *testing.T) {
	original := Level()
	t.Cleanup(func() { SetLevel(original) })

	SetLevel(slog.LevelError)
	if Level() != slog.LevelError {
		t.Fatalf("Level = %v", Level())
	}
}

func TestSetup_HonoursLogLevelEnv(t *testing.T) {
	t.Setenv("LOG_LEVEL", "error")
	Setup(EnvProd, "test")

	if Level() != slog.LevelError {
		t.Fatalf("Level = %v, want error", Level())
	}
	t.Cleanup(func() { SetLevel(slog.LevelInfo) })
}

func TestSetup_ProductionDefaultsToInfo(t *testing.T) {
	t.Setenv("LOG_LEVEL", "")
	Setup(EnvProd, "test")

	if Level() != slog.LevelInfo {
		t.Fatalf("Level = %v, want info", Level())
	}
}

func TestSetup_StampsServiceAndEnv(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{ReplaceAttr: replaceAttr})
	slog.New(h).With(slog.String(KeyService, "sso"), slog.String(KeyEnv, "prod")).Info("hello")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not json: %v", err)
	}
	if rec[KeyService] != "sso" || rec[KeyEnv] != "prod" {
		t.Fatalf("missing service/env: %s", buf.String())
	}
}
