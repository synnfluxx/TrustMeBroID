package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/lib/pq"
	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/encryptor"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
)

type Storage struct {
	db         *sql.DB
	masterKey  []byte
	reaperStmt *sql.Stmt
}

func New(url string) (*Storage, error) {
	const op = "postgres.New"

	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	strg := &Storage{
		db: db,
	}

	strg.masterKey = []byte(os.Getenv("MASTER_KEY"))

	stmt, err := db.Prepare("DELETE FROM users WHERE deleted_at IS NOT NULL AND NOW()-INTERVAL '72 hours' >= deleted_at RETURNING id")
	if err != nil {
		return nil, err
	}

	strg.reaperStmt = stmt

	return strg, nil
}

func (s *Storage) Reaper(ctx context.Context) ([]int64, error) {
	const op = "storage.postgres.reaper"

	deletedUsers := make([]int64, 0)

	rows, err := s.reaperStmt.QueryContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer rows.Close()

	for rows.Next() {
		var uid int64
		if err := rows.Scan(&uid); err != nil {
			continue
		}
		deletedUsers = append(deletedUsers, uid)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return deletedUsers, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, username string, passHash []byte, appID int64) (int64, error) {
	const op = "storage.postgres.SaveUser"

	var id int64
	err := s.db.QueryRowContext(ctx, "INSERT INTO users(email, username, pass_hash, app_id) VALUES($1, $2, $3, $4) RETURNING id", email, username, passHash, appID).Scan(&id)
	if err != nil {
		var pqErr *pq.Error

		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
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

	row := s.db.QueryRowContext(ctx, query, args...)

	var user models.User
	err := row.Scan(&user.ID, &user.Email, &user.Username, &user.PassHash, &user.DeletedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	if user.DeletedAt.Valid {
		return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserDeleted)
	}

	return user, nil
}

func (s *Storage) User(ctx context.Context, userID int64, appID int64) (models.User, error) {
	return s.getUser(ctx,
		"SELECT id, email, username, pass_hash, deleted_at FROM users WHERE id = $1 AND app_id = $2",
		userID,
		appID,
	)
}

func (s *Storage) UserByEmail(ctx context.Context, email string, appID int64) (models.User, error) {
	return s.getUser(ctx,
		"SELECT id, email, username, pass_hash, deleted_at FROM users WHERE email = $1 AND app_id = $2",
		email,
		appID,
	)
}

func (s *Storage) UserByUsername(ctx context.Context, username string, appID int64) (models.User, error) {
	return s.getUser(ctx,
		"SELECT id, email, username, pass_hash, deleted_at FROM users WHERE app_id = $1 AND username = $2",
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
	err := s.db.QueryRowContext(ctx, "INSERT INTO admins (id, email, username, app_id) SELECT id, email, username, app_id FROM users WHERE id = $1 AND app_id = $2 RETURNING id", userID, appID).Scan(&aid)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return aid, nil
}

func (s *Storage) IsAdmin(ctx context.Context, id int64, appID int64) (bool, error) {
	const op = "storage.postgres.IsAdmin"

	var isAdmin bool
	row := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM admins WHERE id = $1 AND app_id = $2)", id, appID)

	err := row.Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

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

func (s *Storage) DeleteAdminByEmail(ctx context.Context, email string, appID int64) error {
	return s.deleteAdmin(ctx, "DELETE FROM admins WHERE app_id = $1 AND email = $2", appID, email)
}

func (s *Storage) DeleteAdminByUsername(ctx context.Context, username string, appID int64) error {
	return s.deleteAdmin(ctx, "DELETE FROM admins WHERE app_id = $1 AND username = $2", appID, username)
}
func (s *Storage) DeleteAdminByUserID(ctx context.Context, userID, appID int64) error {
	return s.deleteAdmin(ctx, "DELETE FROM admins WHERE app_id = $1 AND id = $2", appID, userID)
}

func (s *Storage) App(ctx context.Context, appID int64) (models.App, error) {
	const op = "storage.postgres.App"

	row := s.db.QueryRowContext(ctx, "SELECT id, name, secret, redirect_uri FROM apps WHERE id = $1", appID)
	var app models.App
	err := row.Scan(&app.ID, &app.Name, &app.Secret, &app.RedirectURI)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, storage.ErrAppNotFound
		}

		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	decrypted, err := encryptor.DecryptString(s.masterKey, app.Secret)
	if err != nil {
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
