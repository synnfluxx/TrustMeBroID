package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/lib/pq"
	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/encryptor"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
)

// Connection pool limits. database/sql defaults to unlimited open connections,
// while the deployed Postgres runs with max_connections=30 shared with the
// AuraLift service. Without a ceiling here a traffic spike exhausts the server
// and every query starts failing with "too many clients".
const (
	maxOpenConns    = 10
	maxIdleConns    = 5
	connMaxLifetime = 30 * time.Minute
	connMaxIdleTime = 5 * time.Minute
)

// slowQueryThreshold is the point at which a query is reported on its own.
// Below it, timings are only visible at debug level.
const slowQueryThreshold = 200 * time.Millisecond

type Storage struct {
	db         *sql.DB
	log        *slog.Logger
	masterKey  []byte
	reaperStmt *sql.Stmt
}

func New(url string, log *slog.Logger) (*Storage, error) {
	const op = "postgres.New"

	log = log.With(slog.String("component", "postgres"))

	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	db.SetConnMaxIdleTime(connMaxIdleTime)

	// sql.Open is lazy: without this ping the first failure would surface
	// inside an unrelated request instead of at startup.
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return nil, fmt.Errorf("%s: ping: %w", op, err)
	}

	strg := &Storage{db: db, log: log}

	strg.masterKey = []byte(os.Getenv("MASTER_KEY"))
	if len(strg.masterKey) == 0 {
		log.Error("MASTER_KEY is empty: application secrets cannot be decrypted",
			slog.String("impact", "every login will fail when reading the app secret"))
	} else if l := len(strg.masterKey); l != 16 && l != 24 && l != 32 {
		log.Error("MASTER_KEY has an invalid length for AES",
			slog.Int("length", l),
			slog.String("expected", "16, 24 or 32 bytes"))
	}

	stmt, err := db.Prepare("DELETE FROM users WHERE deleted_at IS NOT NULL AND NOW()-INTERVAL '72 hours' >= deleted_at RETURNING id")
	if err != nil {
		return nil, fmt.Errorf("%s: prepare reaper: %w", op, err)
	}

	strg.reaperStmt = stmt

	log.Info("postgres pool configured",
		slog.Int("max_open_conns", maxOpenConns),
		slog.Int("max_idle_conns", maxIdleConns),
		slog.Duration("conn_max_lifetime", connMaxLifetime),
		slog.Duration("slow_query_threshold", slowQueryThreshold))

	return strg, nil
}

// trace records the outcome of a single statement. Successful fast queries stay
// at debug so production stays readable; anything slow or failing is promoted,
// because those are the records someone is actually looking for.
//
// Query text is logged, arguments are not: the arguments are emails, password
// hashes and verification codes.
func (s *Storage) trace(ctx context.Context, op string, start time.Time, err error) {
	elapsed := time.Since(start)
	log := logger.From(ctx, s.log).With(
		slog.String(logger.KeyOp, op),
		sl.Dur(elapsed),
	)

	switch {
	case err != nil && errors.Is(err, sql.ErrNoRows):
		log.Debug("query returned no rows")
	case err != nil:
		var pqErr *pq.Error
		if errors.As(err, &pqErr) {
			log.Error("query failed",
				slog.String("pg_code", string(pqErr.Code)),
				slog.String("pg_constraint", pqErr.Constraint),
				slog.String("pg_table", pqErr.Table),
				slog.String("pg_detail", pqErr.Detail),
				sl.Err(err))
			return
		}
		log.Error("query failed", sl.Err(err))
	case elapsed >= slowQueryThreshold:
		log.Warn("slow query",
			slog.Duration("threshold", slowQueryThreshold),
			slog.Int("pool_in_use", s.db.Stats().InUse),
			slog.Int("pool_open", s.db.Stats().OpenConnections))
	default:
		log.Debug("query ok")
	}
}

// Stats exposes pool saturation for periodic reporting.
func (s *Storage) Stats() sql.DBStats { return s.db.Stats() }

// Close releases the prepared statement and the pool.
func (s *Storage) Close() error {
	if s.reaperStmt != nil {
		_ = s.reaperStmt.Close()
	}
	return s.db.Close()
}

func (s *Storage) Reaper(ctx context.Context) ([]int64, error) {
	const op = "storage.postgres.reaper"

	deletedUsers := make([]int64, 0)

	start := time.Now()
	rows, err := s.reaperStmt.QueryContext(ctx)
	s.trace(ctx, op, start, err)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	for rows.Next() {
		var uid int64
		if err := rows.Scan(&uid); err != nil {
			// Skipping silently would understate how many accounts were removed.
			logger.From(ctx, s.log).Error("cannot scan reaped user id",
				slog.String(logger.KeyOp, op), sl.Err(err))
			continue
		}
		deletedUsers = append(deletedUsers, uid)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return deletedUsers, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, username string, passHash []byte, appID int64, verificationCode string) (int64, error) {
	const op = "storage.postgres.SaveUser"

	var id int64

	query := `
		WITH cleanup AS (
			DELETE FROM users
			WHERE (email = $1 OR username = $2)
			  AND app_id = $4
			  AND deleted_at IS NOT NULL
		)
		INSERT INTO users(email, username, pass_hash, app_id, verification_code, last_token_generated_time) 
		VALUES($1, $2, $3, $4, $5, NOW()) 
		RETURNING id
	`

	start := time.Now()
	err := s.db.QueryRowContext(ctx, query, email, username, passHash, appID, verificationCode).Scan(&id)
	s.trace(ctx, op, start, err)
	if err != nil {
		var pqErr *pq.Error

		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			// Which column collided decides what the user is told, so record
			// the constraint name rather than a generic "already exists".
			logger.From(ctx, s.log).Warn("registration rejected: unique constraint violated",
				slog.String(logger.KeyOp, op),
				slog.String("constraint", pqErr.Constraint),
				slog.Int64(logger.KeyAppID, appID),
				sl.Email(email))
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}

		if errors.As(err, &pqErr) && pqErr.Code == "23503" {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (s *Storage) getUser(ctx context.Context, query string, args ...any) (models.User, error) {
	const op = "storage.postgres.getUser"

	start := time.Now()
	row := s.db.QueryRowContext(ctx, query, args...)

	var user models.User
	err := row.Scan(&user.ID, &user.Email, &user.Username, &user.PassHash, &user.DeletedAt, &user.IsVerified, &user.VerificationCode, &user.LastTokenGeneratedTime)
	s.trace(ctx, op, start, err)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	if user.DeletedAt.Valid {
		// A soft-deleted account still answers lookups, so say why the caller
		// is refused: otherwise this is indistinguishable from a typo.
		logger.From(ctx, s.log).Info("user lookup hit a soft-deleted account",
			slog.String(logger.KeyOp, op),
			slog.Int64(logger.KeyUserID, user.ID),
			slog.Time("deleted_at", user.DeletedAt.Time))
		return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserDeleted)
	}

	return user, nil
}

func (s *Storage) User(ctx context.Context, userID int64, appID int64) (models.User, error) {
	return s.getUser(ctx,
		"SELECT id, email, username, pass_hash, deleted_at, is_verified, verification_code, last_token_generated_time FROM users WHERE id = $1 AND app_id = $2 ORDER BY deleted_at IS NULL DESC, id DESC LIMIT 1",
		userID,
		appID,
	)
}

func (s *Storage) UserByEmail(ctx context.Context, email string, appID int64) (models.User, error) {
	return s.getUser(ctx,
		"SELECT id, email, username, pass_hash, deleted_at, is_verified, verification_code, last_token_generated_time FROM users WHERE email = $1 AND app_id = $2 ORDER BY deleted_at IS NULL DESC, id DESC LIMIT 1",
		email,
		appID,
	)
}

func (s *Storage) UserByUsername(ctx context.Context, username string, appID int64) (models.User, error) {
	return s.getUser(ctx,
		"SELECT id, email, username, pass_hash, deleted_at, is_verified, verification_code, last_token_generated_time	 FROM users WHERE app_id = $1 AND username = $2 ORDER BY deleted_at IS NULL DESC, id DESC LIMIT 1",
		appID,
		username,
	)
}

func (s *Storage) deleteUser(ctx context.Context, query string, args ...any) error {
	const op = "storage.postgres.deleteUser"

	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if affected == 0 {
		return storage.ErrUserNotFound
	}

	return nil
}

func (s *Storage) DeleteUserByEmail(ctx context.Context, email string, appID int64) error {
	return s.deleteUser(ctx,
		"UPDATE users SET deleted_at = $1 WHERE app_id = $2 AND email = $3 AND deleted_at IS NULL",
		time.Now().UTC(),
		appID,
		email,
	)
}

func (s *Storage) DeleteUserByUsername(ctx context.Context, username string, appID int64) error {
	return s.deleteUser(ctx,
		"UPDATE users SET deleted_at = $1 WHERE app_id = $2 AND username = $3 AND deleted_at IS NULL",
		time.Now().UTC(),
		appID,
		username,
	)
}

func (s *Storage) DeleteUserByUserID(ctx context.Context, userID, appID int64) error {
	return s.deleteUser(ctx,
		"UPDATE users SET deleted_at = $1 WHERE app_id = $2 AND id = $3 AND deleted_at IS NULL",
		time.Now().UTC(),
		appID,
		userID,
	)
}

func (s *Storage) MakeAdmin(ctx context.Context, userID, appID int64) (int64, error) {
	const op = "storage.postgres.MakeAdmin"

	var aid int64
	err := s.db.QueryRowContext(ctx,
		"INSERT INTO admins (user_id, app_id) SELECT id, app_id FROM users WHERE id = $1 AND app_id = $2 RETURNING id",
		userID, appID,
	).Scan(&aid)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return aid, nil
}

func (s *Storage) IsAdmin(ctx context.Context, id int64, appID int64) (bool, error) {
	const op = "storage.postgres.IsAdmin"

	var isAdmin bool
	row := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM admins WHERE user_id = $1 AND app_id = $2)", id, appID)

	if err := row.Scan(&isAdmin); err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}

func (s *Storage) deleteAdmin(ctx context.Context, query string, args ...any) error {
	const op = "storage.postgres.deleteAdmin"

	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if affected == 0 {
		return storage.ErrUserNotFound
	}

	return nil
}

func (s *Storage) DeleteAdminByUserID(ctx context.Context, userID, appID int64) error {
	return s.deleteAdmin(ctx, "DELETE FROM admins WHERE app_id = $1 AND user_id = $2", appID, userID)
}

func (s *Storage) DeleteAdminByUsername(ctx context.Context, username string, appID int64) error {
	return s.deleteAdmin(ctx, `
		DELETE FROM admins
		USING users
		WHERE admins.user_id = users.id
		  AND admins.app_id = $1
		  AND users.username = $2
	`, appID, username)
}

func (s *Storage) DeleteAdminByEmail(ctx context.Context, email string, appID int64) error {
	return s.deleteAdmin(ctx, `
		DELETE FROM admins
		USING users
		WHERE admins.user_id = users.id
		  AND admins.app_id = $1
		  AND users.email = $2
	`, appID, email)
}

func (s *Storage) App(ctx context.Context, appID int64) (models.App, error) {
	const op = "storage.postgres.App"

	start := time.Now()
	row := s.db.QueryRowContext(ctx, "SELECT id, name, secret, redirect_uri FROM apps WHERE id = $1", appID)
	var app models.App
	err := row.Scan(&app.ID, &app.Name, &app.Secret, &app.RedirectURI)
	s.trace(ctx, op, start, err)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.From(ctx, s.log).Warn("application not found",
				slog.String(logger.KeyOp, op),
				slog.Int64(logger.KeyAppID, appID),
				slog.String("impact", "login and registration for this app_id cannot proceed"))
			return models.App{}, storage.ErrAppNotFound
		}

		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	decrypted, err := encryptor.DecryptString(s.masterKey, app.Secret)
	if err != nil {
		// Almost always a MASTER_KEY mismatch after a redeploy. Without this
		// record the symptom is every login failing with a generic 500.
		logger.From(ctx, s.log).Error("cannot decrypt application secret",
			slog.String(logger.KeyOp, op),
			slog.Int64(logger.KeyAppID, appID),
			slog.String("app_name", app.Name),
			slog.Int("master_key_len", len(s.masterKey)),
			slog.String("likely_cause", "MASTER_KEY differs from the one used at app registration"),
			sl.Err(err))
		return models.App{}, err
	}
	app.Secret = decrypted

	return app, nil
}

func (s *Storage) RegisterApp(ctx context.Context, appName, appSecret, redirectURI string) (appID int64, err error) {
	const op = "storage.postgres.RegisterApp"

	var id int64
	err = s.db.QueryRowContext(ctx, "INSERT INTO apps(name, secret, redirect_uri) VALUES($1, $2, $3) RETURNING id", appName, appSecret, redirectURI).Scan(&id)
	if err != nil {
		var pqErr *pq.Error

		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrAppExists)
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (s *Storage) DeleteApp(ctx context.Context, appID int64) error {
	const op = "storage.postgres.DeleteApp"

	res, err := s.db.ExecContext(ctx, "DELETE FROM apps WHERE id = $1", appID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if affected == 0 {
		return storage.ErrAppNotFound
	}

	return nil
}

func (s *Storage) FindOrCreateOAuthUser(ctx context.Context, email, username string, appID int64) (usr models.User, err error) {
	const op = "storage.postgres.SaveOAuthUser"

	var uid int64
	err = s.db.QueryRowContext(ctx, "INSERT INTO users(email, username, app_id) VALUES($1, $2, $3) RETURNING id", email, username, appID).Scan(&uid)
	if err != nil {
		var pqErr *pq.Error

		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			usr, err := s.UserByEmail(ctx, email, appID)
			if err != nil {
				return models.User{}, fmt.Errorf("%s: %w", op, err)
			}

			return usr, nil
		}

		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return models.User{
		ID:       uid,
		Email:    email,
		Username: username,
	}, nil
}

func (s *Storage) Emails(ctx context.Context) ([]string, error) {
	emails := make([]string, 0)
	rows, err := s.db.QueryContext(ctx, "SELECT email FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			continue
		}
		emails = append(emails, email)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return emails, nil
}

func (s *Storage) Usernames(ctx context.Context) ([]string, error) {
	usernames := make([]string, 0)
	rows, err := s.db.QueryContext(ctx, "SELECT username FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			continue
		}
		usernames = append(usernames, username)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return usernames, nil
}

func (s *Storage) VerifyUser(ctx context.Context, email string, appID int64) error { //TODO: test this function
	const op = "storage.postgres.VerifyUser"

	start := time.Now()
	res, err := s.db.ExecContext(ctx, "UPDATE users SET is_verified = TRUE, last_token_generated_time = NOW() WHERE email = $1 AND app_id = $2 AND is_verified = FALSE", email, appID)
	s.trace(ctx, op, start, err)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if affected == 0 {
		return storage.ErrUserNotFound
	}

	return nil
}

func (s *Storage) UpdateVerificationToken(ctx context.Context, email string, appID int64, newToken string) error { //TODO: test this function
	const op = "storage.postgres.UpdateVerificationToken"

	res, err := s.db.ExecContext(ctx, "UPDATE users SET verification_code = $1, last_token_generated_time = NOW() WHERE email = $2 AND app_id = $3", newToken, email, appID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if affected == 0 {
		return storage.ErrUserNotFound
	}

	return nil
}
