package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const validYAML = `
env: 'local'
access_token_ttl: 5m
refresh_token_ttl: 168h
grpc:
  port: 1337
  timeout: 10s
  rps: 3
  burst: 6
postgres:
  port: 5432
  host: 'postgres'
  reaper_delay: 3h
  sslmode: 'disable'
redis:
  port: 6379
  host: 'redis-sso'
  timeout: 15s
  retires: 3
http:
  rps: 3
  burst: 6
  visitor_cleaner_delay: 3h
smtp:
  host: 'smtp.test'
  port: 587
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SMTP_USERNAME", "noreply@auralift.test")
	t.Setenv("SMTP_PASSWORD", "smtp-password")
	t.Setenv("DB_CONNECTION_STRING", "postgres://user:pw@postgres:5432/auralift?sslmode=disable")
	t.Setenv("REDIS_CONNECTION_STRING", "redis://redis-sso:6379/0")
}

func TestMustLoadByPath_ParsesEveryField(t *testing.T) {
	setRequiredEnv(t)

	cfg := MustLoadByPath(writeConfig(t, validYAML))

	require.Equal(t, "local", cfg.Env)
	require.Equal(t, 5*time.Minute, cfg.AccessTokenTTL)
	require.Equal(t, 168*time.Hour, cfg.RefreshTokenTTL)
	require.Equal(t, 1337, cfg.GRPC.Port)
	require.Equal(t, 3, cfg.GRPC.Rps)
	require.Equal(t, 6, cfg.GRPC.Burst)
	require.Equal(t, "postgres", cfg.DB.Host)
	require.Equal(t, "disable", cfg.DB.SSLMode)
	require.Equal(t, 3*time.Hour, cfg.DB.ReaperDelay)
	require.Equal(t, "redis-sso", cfg.Redis.Host)
	require.Equal(t, 15*time.Second, cfg.Redis.Timeout)
	require.Equal(t, "smtp.test", cfg.SMTP.Host)
	require.Equal(t, 587, cfg.SMTP.Port)
	require.Equal(t, "noreply@auralift.test", cfg.SMTP.Username)
	require.Equal(t, "smtp-password", cfg.SMTP.Password)
}

// ENV is exported to the process so that code reached later (redirect URI
// validation, the gRPC client) can branch on it.
func TestMustLoadByPath_ExportsENV(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("ENV", "")

	MustLoadByPath(writeConfig(t, validYAML))

	require.Equal(t, "local", os.Getenv("ENV"))
}

func TestMustLoadByPath_SMTPCredentialsAreRequired(t *testing.T) {
	// The deployment compose file passes neither variable, which is why the
	// container refuses to start rather than silently sending nothing.
	t.Setenv("DB_CONNECTION_STRING", "postgres://user:pw@postgres:5432/db")
	t.Setenv("SMTP_USERNAME", "placeholder")
	t.Setenv("SMTP_PASSWORD", "placeholder")
	require.NoError(t, os.Unsetenv("SMTP_USERNAME"))
	require.NoError(t, os.Unsetenv("SMTP_PASSWORD"))

	path := writeConfig(t, validYAML)
	require.Panics(t, func() { MustLoadByPath(path) })
}

// env-required only checks that the variable exists. An empty value passes
// validation and fails later, at the first send, with a connection error that
// does not mention credentials.
func TestMustLoadByPath_EmptySMTPCredentialsPassValidation(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SMTP_USERNAME", "")
	t.Setenv("SMTP_PASSWORD", "")

	cfg := MustLoadByPath(writeConfig(t, validYAML))

	require.Empty(t, cfg.SMTP.Username)
	require.Empty(t, cfg.SMTP.Password)
}

func TestMustLoadByPath_MissingFile(t *testing.T) {
	require.Panics(t, func() { MustLoadByPath(filepath.Join(t.TempDir(), "absent.yaml")) })
}

func TestMustLoadByPath_MalformedYAML(t *testing.T) {
	setRequiredEnv(t)
	path := writeConfig(t, "env: [unclosed")
	require.Panics(t, func() { MustLoadByPath(path) })
}

func TestConnectionString_PrefersTheExplicitDSN(t *testing.T) {
	cfg := PostgresConfig{Host: "ignored", Port: 1, SSLMode: "disable"}
	t.Setenv("DB_CONNECTION_STRING", "postgres://explicit/dsn")

	cfg.mustSetConnectionString()

	require.Equal(t, "postgres://explicit/dsn", cfg.ConnectionString)
}

func TestConnectionString_BuiltFromParts(t *testing.T) {
	cfg := PostgresConfig{Host: "postgres", Port: 5432, SSLMode: "require"}
	t.Setenv("DB_CONNECTION_STRING", "")
	t.Setenv("DB_USER", "sso")
	t.Setenv("DB_PASSWORD", "pw")
	t.Setenv("DB_NAME", "auralift")

	cfg.mustSetConnectionString()

	require.Equal(t, "postgres://sso:pw@postgres:5432/auralift?sslmode=require", cfg.ConnectionString)
}

func TestConnectionString_PanicsOnIncompleteParts(t *testing.T) {
	for _, missing := range []string{"DB_USER", "DB_PASSWORD", "DB_NAME"} {
		t.Run("without "+missing, func(t *testing.T) {
			t.Setenv("DB_CONNECTION_STRING", "")
			t.Setenv("DB_USER", "sso")
			t.Setenv("DB_PASSWORD", "pw")
			t.Setenv("DB_NAME", "auralift")
			t.Setenv(missing, "")

			cfg := PostgresConfig{Host: "postgres", Port: 5432}
			require.Panics(t, cfg.mustSetConnectionString)
		})
	}
}

// The yaml tag is spelled "retires"; the deployment file spells it the same way
// to compensate. This pins the current contract so the two cannot drift apart
// silently.
func TestRedisRetriesTagIsMisspelled(t *testing.T) {
	setRequiredEnv(t)

	cfg := MustLoadByPath(writeConfig(t, validYAML))

	require.Equal(t, 3, cfg.Redis.Retries, `the yaml key is "retires", not "retries"`)
}

func TestFetchConfigPath_FallsBackToTheEnvironment(t *testing.T) {
	// The flag is only parsed from the real command line, so the env fallback
	// is the path the container actually uses (CONFIG_PATH in compose).
	t.Setenv("CONFIG_PATH", "/app/config/prod.yaml")

	require.Equal(t, "/app/config/prod.yaml", fetchConfigPath())
}

func TestMustLoad_PanicsWithoutAPath(t *testing.T) {
	t.Setenv("CONFIG_PATH", "")

	require.Panics(t, func() { MustLoad() })
}

func TestMustLoad_ReadsThePathFromTheEnvironment(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("CONFIG_PATH", writeConfig(t, validYAML))

	cfg := MustLoad()

	require.Equal(t, "local", cfg.Env)
	require.Equal(t, 1337, cfg.GRPC.Port)
}
