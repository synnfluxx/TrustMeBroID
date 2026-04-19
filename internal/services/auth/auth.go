package auth
//TODO: delete ok from Delete methods

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/encryptor"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/jwt"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAppID       = errors.New("invalid app id")
	ErrUserExists         = errors.New("user already exists")
	ErrAppExists          = errors.New("app already exists")
	ErrUserNotFound       = errors.New("user not found")
)

type Auth struct {
	log *slog.Logger

	usrSaver       UserSaver
	usrProvider    UserProvider
	appProvider    AppProvider
	adminProvider  AdminProvider
	filterProvider filterProvider
	tokenTTL       time.Duration
	filters        *filters
}

type filters struct {
	emails    *bloom.BloomFilter
	usernames *bloom.BloomFilter
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, username string, passHash []byte, appID int64) (uid int64, err error)
	SaveOAuthUser(ctx context.Context, email, username string, appID int64) (usr models.User, err error)
}

type UserProvider interface {
	User(ctx context.Context, userID int64, appID int64) (models.User, error)
	IsAdmin(ctx context.Context, userID int64, appID int64) (bool, error)
	UserByUsername(ctx context.Context, username string, appID int64) (models.User, error)
	UserByEmail(ctx context.Context, email string, appID int64) (models.User, error)
	DeleteUserByUserID(ctx context.Context, userID int64, appID int64) error
	DeleteUserByUsername(ctx context.Context, username string, appID int64) error
	DeleteUserByEmail(ctx context.Context, email string, appID int64) error
}

type AdminProvider interface {
	//MakeAdmin(ctx context.Context, appID int64) (models.User, error) // TODO
	DeleteAdminByUserID(ctx context.Context, userID int64, appID int64) error
	DeleteAdminByUsername(ctx context.Context, username string, appID int64) error
	DeleteAdminByEmail(ctx context.Context, email string, appID int64) error
}

type AppProvider interface {
	App(ctx context.Context, appID int64) (models.App, error)
	RegisterApp(ctx context.Context, appName string, appSecret string) (appID int64, err error)
	DeleteApp(ctx context.Context, appID int64) error
}

type filterProvider interface {
	Emails(ctx context.Context) ([]string, error)
	Usernames(ctx context.Context) ([]string, error)
}

func New(log *slog.Logger, userSaver UserSaver, userProvider UserProvider, appProvider AppProvider, adminProvider AdminProvider, filterProvider filterProvider, tokenTTL time.Duration) *Auth {
	auth := &Auth{
		log:            log,
		usrSaver:       userSaver,
		usrProvider:    userProvider,
		appProvider:    appProvider,
		adminProvider:  adminProvider,
		filterProvider: filterProvider,
		tokenTTL:       tokenTTL,
		filters: &filters{
			emails:    bloom.New(1000*1000*20, 5),
			usernames: bloom.New(1000*1000*20, 5),
		},
	}
	auth.MustHydrate(context.Background())
	return auth
}

func (a *Auth) MustHydrate(ctx context.Context) {
	const op = "auth.Hydrate"
	log := a.log.With("op", op)
	log.Info("Hydrating start")
	t := time.Now()
	count := 0

	emails, err := a.filterProvider.Emails(ctx)
	if err != nil {
		panic(err)
	}

	for _, v := range emails {
		a.filters.emails.Add([]byte(v))
		count++
	}

	usernames, err := a.filterProvider.Usernames(ctx)
	if err != nil {
		panic(err)
	}

	for _, v := range usernames {
		a.filters.usernames.Add([]byte(v))
		count++
	}

	log.Info("filter hydrated successfully", slog.Any("rows", count), slog.Any("elapsed", time.Since(t).Milliseconds()))
}

func (a *Auth) LoginByEmail(ctx context.Context, email, password string, appID int64) (string, error) {
	const op = "auth.Login (ByEmail)"
	log := a.log.With("op", op)
	log.Info("attempting to login user")

	user, err := a.usrProvider.UserByEmail(ctx, email, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) || errors.Is(err, storage.ErrUserDeleted) {
			log.Warn("user not found", sl.Err(err))

			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		log.Error("failed to get user", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}


	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Info("invalid credentials", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		log.Error("failed to generate token", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (a *Auth) LoginByUsername(ctx context.Context, username string, password string, appID int64) (string, error) {
	const op = "auth.Login (ByUsername)"
	log := a.log.With("op", op)
	log.Info("attempting to login user")

	user, err := a.usrProvider.UserByUsername(ctx, username, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) || errors.Is(err, storage.ErrUserDeleted) {
			log.Warn("user not found", sl.Err(err))

			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		log.Error("failed to get user", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Info("invalid credentials", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		log.Error("failed to generate token", sl.Err(err))

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

func (a *Auth) RegisterNewUser(ctx context.Context, email, username, pass string, appID int64) (int64, error) {
	const op = "auth.RegisterNewUser"

	log := a.log.With(slog.String("op", op))

	log.Info("registering user")

	if a.filters.emails.Test([]byte(email)) || a.filters.usernames.Test([]byte(username)) {
		log.Warn("user already exists")

		return 0, ErrUserExists
	}

	_, err := a.appProvider.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("app not found", sl.Err(err))

			return 0, storage.ErrAppNotFound
		}

		log.Error("failed to get app", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.usrSaver.SaveUser(ctx, email, username, passHash, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists", sl.Err(err))

			return 0, ErrUserExists
		}
		log.Error("failed to save user", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered")

	return id, nil
}

func (a *Auth) DeleteUserByUserID(ctx context.Context, userID int64, appID int64) error {
	const op = "auth.DeleteUserByUserID"
	log := a.log.With(slog.String("op", op))
	log.Info("deleting user")

	err := a.usrProvider.DeleteUserByUserID(ctx, userID, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return storage.ErrUserNotFound
		}

		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *Auth) DeleteUserByUsername(ctx context.Context, username string, appID int64) error {
	const op = "auth.DeleteUserByUsername"
	log := a.log.With(slog.String("op", op))
	log.Info("deleting user")

	err := a.usrProvider.DeleteUserByUsername(ctx, username, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return storage.ErrUserNotFound
		}

		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *Auth) DeleteUserByEmail(ctx context.Context, email string, appID int64) error {
	const op = "auth.DeleteUserByEmail"
	log := a.log.With(slog.String("op", op))
	log.Info("deleting user")

	err := a.usrProvider.DeleteUserByEmail(ctx, email, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
			return ErrInvalidCredentials
		}

		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *Auth) IsAdmin(ctx context.Context, UserID int64, appID int64) (bool, error) {
	const op = "auth.IsAdmin"

	log := a.log.With(slog.String("op", op)) //, slog.String("email", email))

	isAdmin, err := a.usrProvider.IsAdmin(ctx, UserID, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("admin not found", sl.Err(err))

			return false, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}

		return false, fmt.Errorf("%s: %w", op, ErrInvalidAppID)
	}

	return isAdmin, nil
}

func (a *Auth) DeleteAdminByUserID(ctx context.Context, UserID int64, appID int64) error {
	const op = "auth.DeleteAdminByUserID"
	log := a.log.With(slog.String("op", op))

	isAdmin, err := a.usrProvider.IsAdmin(ctx, UserID, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
		}

		return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	if isAdmin {
		err := a.adminProvider.DeleteAdminByUserID(ctx, UserID, appID)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				log.Warn("user not found", sl.Err(err))
			}

			return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}

		return nil
	} else {
		return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}
}

func (a *Auth) RegisterApp(ctx context.Context, appName string) (appID int64, secret string, err error) {
	const op = "auth.RegisterApp"

	log := a.log.With(slog.String("op", op))

	log.Info("registering app")

	secretKey := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, secretKey)
	if err != nil {
		return 0, "", err
	}

	encrypted, err := encryptor.EncryptString([]byte(os.Getenv("MASTER_KEY")), secretKey)

	id, err := a.appProvider.RegisterApp(ctx, appName, encrypted)
	if err != nil {
		if errors.Is(err, storage.ErrAppExists) {
			log.Warn("app already exists", sl.Err(err))
			return 0, "", ErrAppExists
		}
	}

	return id, string(secretKey), nil
}

func (a *Auth) DeleteApp(ctx context.Context, appID int64) error {
	const op = "auth.DeleteApp"
	log := a.log.With(slog.String("op", op))
	log.Info("deleting app")

	err := a.appProvider.DeleteApp(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("app not found", sl.Err(err))
			return storage.ErrAppNotFound
		}

		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *Auth) DeleteAdminByEmail(ctx context.Context, appID int64, email string) error {
	const op = "auth.DeleteAdminByEmail"
	log := a.log.With(slog.String("op", op))

	if err := a.adminProvider.DeleteAdminByEmail(ctx, email, appID); err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
		}

		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *Auth) DeleteAdminByUsername(ctx context.Context, appID int64, username string) error {
	const op = "auth.DeleteAdminByEmail"
	log := a.log.With(slog.String("op", op))

	if err := a.adminProvider.DeleteAdminByUsername(ctx, username, appID); err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found", sl.Err(err))
		}

		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
