package main

import (
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/pressly/goose/v3"
	"github.com/synnfluxx/TrustMeBroID/internal/app"
	"github.com/synnfluxx/TrustMeBroID/internal/config"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	"github.com/synnfluxx/TrustMeBroID/migrations"
)

const serviceName = "sso"

func init() {
	godotenv.Load()
}

func main() {
	cfg := config.MustLoad()

	log := logger.Setup(cfg.Env, serviceName)

	log.Info("starting service",
		slog.String("version", buildVersion()),
		slog.String("go_version", runtime.Version()),
		slog.Int("pid", os.Getpid()),
		slog.String("log_level", logger.Level().String()),
		// Everything below decides behaviour in production and is the first
		// thing to check when the service misbehaves after a deploy.
		slog.Int("grpc_port", cfg.GRPC.Port),
		slog.String("http_bind_addr", os.Getenv("HTTP_BIND_ADDR")),
		slog.Duration("access_token_ttl", cfg.AccessTokenTTL),
		slog.Duration("refresh_token_ttl", cfg.RefreshTokenTTL),
		slog.Int("grpc_rps", cfg.GRPC.Rps),
		slog.Int("grpc_burst", cfg.GRPC.Burst),
		slog.Int("http_rps", cfg.HTTP.Rps),
		slog.Int("http_burst", cfg.HTTP.Burst),
		slog.String("postgres_host", cfg.DB.Host),
		slog.String("postgres_sslmode", cfg.DB.SSLMode),
		slog.String("redis_host", cfg.Redis.Host),
		slog.String("smtp_host", cfg.SMTP.Host),
		slog.Int("smtp_port", cfg.SMTP.Port),
	)

	warnOnRiskyConfig(log, cfg)

	if err := runMigrations(log, cfg.DB.ConnectionString); err != nil {
		log.Error("migrations failed, refusing to start", sl.Err(err))
		os.Exit(1)
	}

	application := app.New(log, cfg)

	go application.GRPCSrv.MustRun()
	go application.HTTPSrv.MustRun()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	sig := <-stop
	shutdownStart := time.Now()
	log.Info("shutdown signal received, draining", slog.String("signal", sig.String()))

	application.GRPCSrv.Stop()

	if err := application.HTTPSrv.Stop(); err != nil {
		log.Error("http server did not shut down cleanly", sl.Err(err))
	}

	log.Info("service stopped", sl.Since(shutdownStart))
}

// warnOnRiskyConfig states, once and at startup, the settings that will
// silently degrade the service later. Each of these has cost an incident
// somewhere; finding them in the first ten log lines is cheaper than inferring
// them from symptoms.
func warnOnRiskyConfig(log *slog.Logger, cfg *config.Config) {
	if cfg.Env == logger.EnvProd && cfg.DB.SSLMode == "disable" {
		log.Warn("postgres TLS is disabled in production",
			slog.String("sslmode", cfg.DB.SSLMode),
			slog.String("impact", "database traffic, including password hashes, is unencrypted in transit"))
	}
	if cfg.GRPC.Rps > 0 && cfg.GRPC.Rps < 50 {
		log.Warn("grpc rate limit is process-wide, not per-client",
			slog.Int("rps", cfg.GRPC.Rps),
			slog.Int("burst", cfg.GRPC.Burst),
			slog.String("impact", "all callers share this budget; one client can starve the rest"))
	}
	if cfg.SMTP.Host == "" || cfg.SMTP.Port == 0 {
		log.Warn("smtp is not configured, verification email will fail",
			slog.String("smtp_host", cfg.SMTP.Host),
			slog.Int("smtp_port", cfg.SMTP.Port))
	}
	if cfg.SMTP.Port == 465 {
		log.Warn("smtp port 465 expects implicit TLS, which net/smtp does not speak",
			slog.String("impact", "use 587 with STARTTLS or the send will fail"))
	}
	if os.Getenv("MASTER_KEY") == "" {
		log.Error("MASTER_KEY is empty: application secrets cannot be decrypted")
	}
	if os.Getenv("ADMIN_TOKEN") == "" {
		log.Error("ADMIN_TOKEN is empty: every admin gRPC method will reject all callers")
	}
}

func runMigrations(log *slog.Logger, dsn string) error {
	start := time.Now()
	log.Info("applying database migrations")

	goose.SetLogger(goose.NopLogger())
	goose.SetBaseFS(migrations.MigrationsFS)

	db, err := goose.OpenDBWithDriver("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	before, _ := goose.GetDBVersion(db)

	if err := goose.Up(db, "."); err != nil {
		// "already applied" is the steady state on every restart after the
		// first, not a failure. The previous code logged that and panicked
		// anyway, which made the log line unreachable in practice.
		if errors.Is(err, goose.ErrAlreadyApplied) || errors.Is(err, goose.ErrNoNextVersion) {
			log.Info("migrations already up to date",
				slog.Int64("version", before),
				sl.Since(start))
			return nil
		}
		return err
	}

	after, _ := goose.GetDBVersion(db)
	log.Info("migrations applied",
		slog.Int64("version_before", before),
		slog.Int64("version_after", after),
		sl.Since(start))
	return nil
}

func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	var revision, modified string
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value
		}
	}
	if revision == "" {
		return "unknown"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified == "true" {
		return revision + "-dirty"
	}
	return revision
}
