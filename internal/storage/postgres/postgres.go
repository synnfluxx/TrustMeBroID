package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/lib/pq"
	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/encryptor"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
)

type Storage struct {
	db *sql.DB
	mu sync.Mutex
}

func New(url string) (*Storage, error) {
	const op = "postgres.New"

	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{
		db: db,
	}, nil
}

func (s *Storage) Reaper(ctx context.Context) ([]int64, error) {
		const op = "storage.postgres.reaper"

		s.mu.Lock()
		defer s.mu.Unlock()

		deletedUsers := make([]int64, 0)
		logStmt, err := s.db.Prepare("SELECT id FROM users WHERE deleted_at IS NOT NULL AND NOW()-INTERVAL '72 hours' >= deleted_at")
		if err != nil {
			return nil, err
		}
		defer logStmt.Close()

		rows, err := logStmt.QueryContext(ctx)
		if err != nil {
			return nil, err
		}

		for rows.Next() {
			var uid int64
			if err := rows.Scan(&uid); err != nil {
				continue
			}
			deletedUsers = append(deletedUsers, uid)
		}

		if err := rows.Err(); err != nil {
			return nil, err
		}

		delStmt, err := s.db.Prepare("DELETE FROM users WHERE deleted_at IS NOT NULL AND NOW()-INTERVAL '72 hours' >= deleted_at")
		if err != nil {
			return nil, err
		}
		defer delStmt.Close()

		res, err := delStmt.ExecContext(ctx)
		if err != nil {
			return nil, err
		}

		if n, _ := res.RowsAffected(); n != int64(len(deletedUsers)) {
			return nil, fmt.Errorf("%s: %s", op, "not all users have been deleted") // TODO: const error
		}

		return deletedUsers, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, username string, passHash []byte, appID int64) (int64, error) {
	const op = "storage.postgres.SaveUser"

	stmt, err := s.db.Prepare("INSERT INTO users(email, username, pass_hash, app_id) VALUES($1, $2, $3, $4) RETURNING id")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var id int64
	err = stmt.QueryRowContext(ctx, email, username, passHash, appID).Scan(&id)
	if err != nil {
		var pqErr *pq.Error

		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (s *Storage) User(ctx context.Context, userID int64, appID int64) (models.User, error) {
	const op = "storage.postgres.User"

	stmt, err := s.db.Prepare("SELECT id, email, pass_hash, deleted_at FROM users WHERE id = $1 AND app_id = $2")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, userID, appID)

	var user models.User
	err = row.Scan(&user.ID, &user.Email, &user.PassHash, &user.DeletedAt)
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

func (s *Storage) UserByEmail(ctx context.Context, email string, appID int64) (models.User, error) {
	const op = "storage.postgres.UserByEmail"

	stmt, err := s.db.Prepare("SELECT id, email, pass_hash, deleted_at FROM users WHERE email = $1 AND app_id = $2")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, email, appID)

	var user models.User
	err = row.Scan(&user.ID, &user.Email, &user.PassHash, &user.DeletedAt)
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
func (s *Storage) UserByUsername(ctx context.Context, username string, appID int64) (models.User, error) {
	const op = "storage.postgres.UserByUsername"

	stmt, err := s.db.Prepare("SELECT id, email, pass_hash, deleted_at FROM users WHERE app_id = $1 AND username = $2")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, appID, username)

	var user models.User
	err = row.Scan(&user.ID, &user.Email, &user.PassHash, &user.DeletedAt)
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

func (s *Storage) DeleteUserByEmail(ctx context.Context, email string, appID int64) error {
	const op = "storage.postgres.DeleteUserByEmail"

	stmt, err := s.db.Prepare("UPDATE users SET deleted_at = $1 WHERE app_id = $2 AND email = $3")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.ExecContext(ctx, time.Now(), appID, email)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if affected == 0 {
		return storage.ErrUserNotFound
	} else {
		return nil
	}
}

func (s *Storage) DeleteUserByUsername(ctx context.Context, username string, appID int64) error {
	const op = "storage.postgres.DeleteUserByUsername"

	stmt, err := s.db.Prepare("UPDATE users SET deleted_at = $1 WHERE app_id = $2 AND username = $3")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.ExecContext(ctx, time.Now(), appID, username)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if affected == 0 {
		return storage.ErrUserNotFound
	} else {
		return nil
	}
}
func (s *Storage) DeleteUserByUserID(ctx context.Context, userID, appID int64) error {
	const op = "storage.postgres.DeleteUserByUserID"

	stmt, err := s.db.Prepare("UPDATE users SET deleted_at = $1 WHERE app_id = $2 AND id = $3")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.ExecContext(ctx, time.Now(), appID, userID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if affected == 0 {
		return storage.ErrUserNotFound
	} else {
		return nil
	}
}

func (s *Storage) MakeAdmin(ctx context.Context, email string, appID int64) error {
	const op = "storage.postgres.MakeAdmin"

	stmt, err := s.db.Prepare("INSERT INTO admins (id, email) SELECT id, email FROM users WHERE email = $1 AND app_id = $2 ")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.ExecContext(ctx, email, appID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	count, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if count == 0 {
		return fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
	}

	return nil
}

func (s *Storage) IsAdmin(ctx context.Context, id int64, appID int64) (bool, error) {
	const op = "storage.postgres.IsAdmin"

	stmt, err := s.db.Prepare("SELECT EXISTS(SELECT 1 FROM admins WHERE id = $1 AND app_id = $2)")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var isAdmin bool
	row := stmt.QueryRowContext(ctx, id, appID)

	err = row.Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}

func (s *Storage) DeleteAdminByEmail(ctx context.Context, email string, appID int64) error {
	const op = "storage.postgres.DeleteAdminByEmail"

	stmt, err := s.db.Prepare("DELETE FROM admins WHERE app_id = $1 AND email = $2")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.ExecContext(ctx, appID, email)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if affected == 0 {
		return storage.ErrUserNotFound
	} else {
		return nil
	}
}

func (s *Storage) DeleteAdminByUsername(ctx context.Context, username string, appID int64) error {
	const op = "storage.postgres.DeleteAdminByUsername"

	stmt, err := s.db.Prepare("DELETE FROM admins WHERE app_id = $1 AND username = $2")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.ExecContext(ctx, appID, username)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if affected == 0 {
		return storage.ErrUserNotFound
	} else {
		return nil
	}
}
func (s *Storage) DeleteAdminByUserID(ctx context.Context, userID, appID int64) error {
	const op = "storage.postgres.DeleteAdminByUserID"

	stmt, err := s.db.Prepare("DELETE FROM admins WHERE app_id = $1 AND id = $2")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.ExecContext(ctx, appID, userID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if affected == 0 {
		return storage.ErrUserNotFound
	} else {
		return nil
	}
}

func (s *Storage) App(ctx context.Context, appID int64) (models.App, error) {
	const op = "storage.postgres.App"

	stmt, err := s.db.Prepare("SELECT id, name, secret FROM apps WHERE id = $1")
	if err != nil {
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	row := stmt.QueryRowContext(ctx, appID)
	var app models.App
	err = row.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, storage.ErrAppNotFound
		}

		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	decrypted, err := encryptor.DecryptString([]byte(os.Getenv("MASTER_KEY")), app.Secret)
	if err != nil {
		return models.App{}, err
	}
	app.Secret = decrypted

	return app, nil
}

func (s *Storage) RegisterApp(ctx context.Context, appName, appSecret string) (appID int64, err error) {
	const op = "storage.postgres.RegisterApp"

	stmt, err := s.db.Prepare("INSERT INTO apps(name, secret) VALUES($1, $2) RETURNING id")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var id int64
	err = stmt.QueryRowContext(ctx, appName, appSecret).Scan()
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

	stmt, err := s.db.Prepare("DELETE FROM apps WHERE id = $1")
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.ExecContext(ctx, appID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if affected == 0 {
		return storage.ErrAppNotFound
	} else {
		return nil
	}
}

func (s *Storage) SaveOAuthUser(ctx context.Context, email, username string, appID int64) (usr models.User, err error) {
	const op = "storage.postgres.SaveOAuthUser"

	stmt, err := s.db.Prepare("INSERT INTO users(email, username, app_id) VALUES($1, $2, $3) RETURNING id")
	if err != nil {
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	var uid int64
	err = stmt.QueryRowContext(ctx, email, username, appID).Scan(&uid)
	if err != nil {
		var pqErr *pq.Error

		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return models.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserExists)
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
