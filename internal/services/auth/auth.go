package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/encryptor"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/jwt"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	//ErrInvalidAppID       = errors.New("invalid app id")
	ErrUserExists        = errors.New("user already exists")
	ErrAppExists         = errors.New("app already exists")
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidIdentifier = errors.New("invalid identifier")
)

type Auth struct {
	log *slog.Logger

	jwtProvider     JWTProvider
	usrSaver        UserSaver
	usrProvider     UserProvider
	appProvider     AppProvider
	adminProvider   AdminProvider
	pwVerifier      PasswordVerifier
	RefreshTokenTTL time.Duration
	AccessTokenTTL  time.Duration
	appSecrets      sync.Map
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, username string, passHash []byte, appID int64) (uid int64, err error)
	//SaveOAuthUser(ctx context.Context, email, username string, appID int64) (usr models.User, err error)
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
	MakeAdmin(ctx context.Context, userID, appID int64) (uid int64, err error)
	DeleteAdminByUserID(ctx context.Context, userID int64, appID int64) error
	DeleteAdminByUsername(ctx context.Context, username string, appID int64) error
	DeleteAdminByEmail(ctx context.Context, email string, appID int64) error
}

type AppProvider interface {
	App(ctx context.Context, appID int64) (models.App, error)
	RegisterApp(ctx context.Context, appName string, appSecret, redirectURI string) (appID int64, err error)
	DeleteApp(ctx context.Context, appID int64) error
}

type JWTProvider interface {
	SaveRefreshToken(ctx context.Context, token string, userID int64, appID int64, ttl time.Duration) error
	SetNewRefreshToken(ctx context.Context, oldToken string, newToken string, ttl time.Duration) error
	GetRefreshTokenFields(ctx context.Context, token string) (*models.RefreshTokenFields, error)
	Logout(ctx context.Context, token string) error
}

type PasswordVerifier interface {
	Compare(hash []byte, pw []byte) error // For tests	// maybe boilerplate a little bit
}

func New(log *slog.Logger, userSaver UserSaver, userProvider UserProvider, appProvider AppProvider, adminProvider AdminProvider, jwtProvider JWTProvider, passwordVerifier PasswordVerifier, accessTokenTTL, refreshTokenTTL time.Duration) *Auth {
	return &Auth{
		log:             log,
		jwtProvider:     jwtProvider,
		usrSaver:        userSaver,
		usrProvider:     userProvider,
		appProvider:     appProvider,
		adminProvider:   adminProvider,
		pwVerifier:      passwordVerifier,
		AccessTokenTTL:  accessTokenTTL,
		RefreshTokenTTL: refreshTokenTTL,
		appSecrets:      sync.Map{},
	}
}

func (a *Auth) MakeAdmin(ctx context.Context, userID, appID int64) (uid int64, err error) {
	const op = "auth.MakeAdmin"
	log := a.log.With("op", op)
	log.Info("attempting to make user admin")
	
	uid, err = a.adminProvider.MakeAdmin(ctx, userID, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return 0, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	
	return uid, err
}

func (a *Auth) Login(ctx context.Context, identifier models.UserIdentifier, password string, appID int64) (string, string, error) {
	const op = "auth.Login"
	log := a.log.With("op", op)
	log.Info("attempting to login user")

	var user models.User
	var err error
	switch {
	case identifier.Username != nil:
		user, err = a.usrProvider.UserByUsername(ctx, *identifier.Username, appID)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) || errors.Is(err, storage.ErrUserDeleted) {
				log.Warn("user not found", sl.Err(err))

				return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
			}

			log.Error("failed to get user", sl.Err(err))

			return "", "", fmt.Errorf("%s: %w", op, err)
		}
	case identifier.Email != nil:
		user, err = a.usrProvider.UserByEmail(ctx, *identifier.Email, appID)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) || errors.Is(err, storage.ErrUserDeleted) {
				log.Warn("user not found", sl.Err(err))

				return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
			}

			log.Error("failed to get user", sl.Err(err))

			return "", "", fmt.Errorf("%s: %w", op, err)
		}
	case identifier.ID != nil:
		user, err = a.usrProvider.User(ctx, *identifier.ID, appID)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) || errors.Is(err, storage.ErrUserDeleted) {
				log.Warn("user not found", sl.Err(err))

				return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
			}

			log.Error("failed to get user", sl.Err(err))

			return "", "", fmt.Errorf("%s: %w", op, err)
		}
	default:
		return "", "", fmt.Errorf("%s: %w", op, ErrInvalidIdentifier)
	}

	if err := a.pwVerifier.Compare(user.PassHash, []byte(password)); err != nil {
		log.Info("invalid credentials", sl.Err(err))

		return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	accessToken, refreshToken, err := jwt.NewTokens(user.ID, app.ID, app.Secret, a.RefreshTokenTTL, a.AccessTokenTTL)
	if err != nil {
		log.Error("failed to generate token", sl.Err(err))

		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	if err := a.jwtProvider.SaveRefreshToken(ctx, refreshToken, user.ID, app.ID, a.RefreshTokenTTL); err != nil {
		log.Error("failed to save refresh token", sl.Err(err))

		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	return accessToken, refreshToken, nil
}

func (a *Auth) Logout(ctx context.Context, token string) error {
	const op = "auth.Logout"
	log := a.log.With("op", op)
	log.Info("attempting to logout user")

	
	if err := a.jwtProvider.Logout(ctx, token); err != nil {
		log.Warn("error logout user", sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *Auth) RegisterNewUser(ctx context.Context, email, username, pass string, appID int64) (int64, error) {
	const op = "auth.RegisterNewUser"
	log := a.log.With(slog.String("op", op))
	log.Info("registering user")

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

func (a *Auth) DeleteUser(ctx context.Context, identifier models.UserIdentifier, appID int64) error {
	const op = "auth.DeleteUser"
	log := a.log.With(slog.String("op", op))
	log.Info("deleting user")

	switch {
	case identifier.ID != nil:
		err := a.usrProvider.DeleteUserByUserID(ctx, *identifier.ID, appID)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				log.Warn("user not found", sl.Err(err))
				return ErrUserNotFound
			}

			return fmt.Errorf("%s: %w", op, err)
		}
	case identifier.Username != nil:
		err := a.usrProvider.DeleteUserByUsername(ctx, *identifier.Username, appID)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				log.Warn("user not found", sl.Err(err))
				return ErrUserNotFound
			}

			return fmt.Errorf("%s: %w", op, err)
		}
	case identifier.Email != nil:
		err := a.usrProvider.DeleteUserByEmail(ctx, *identifier.Email, appID)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				log.Warn("user not found", sl.Err(err))
				return ErrUserNotFound
			}

			return fmt.Errorf("%s: %w", op, err)
		}
	default:
		return fmt.Errorf("%s: %w", op, ErrInvalidIdentifier)
	}

	return nil
}

func (a *Auth) RefreshToken(ctx context.Context, token string) (string, error) {
	const op = "auth.RefreshToken"
	log := a.log.With(slog.String("op", op))
	log.Info("trying to refresh. token", "refreshToken", fmt.Sprintf("***%s", tokenFingerprint(token)))

	data, err := a.jwtProvider.GetRefreshTokenFields(ctx, token)
	if err != nil {
		if errors.Is(err, storage.ErrTokenNotFound) {
			return "", storage.ErrTokenNotFound
		}

		return "", err
	}

	secret, ok := a.appSecrets.Load(data.AppId)
	if !ok {
		log.Info("App secret Is not cached")

		app, err := a.appProvider.App(ctx, data.AppId)
		if err != nil {
			return "", err
		}

		secret = app.Secret
		a.appSecrets.Store(app.ID, app.Secret)
	}

	newToken, err := jwt.NewAccessToken(data.UserID, data.AppId, a.AccessTokenTTL, secret.(string))
	if err != nil {
		return "", err
	}

	return newToken, nil
}

func (a *Auth) IsAdmin(ctx context.Context, UserID int64, appID int64) (bool, error) {
	const op = "auth.IsAdmin"

	log := a.log.With(slog.String("op", op))

	isAdmin, err := a.usrProvider.IsAdmin(ctx, UserID, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("admin not found", sl.Err(err))

			return false, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}

		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("invalid appID", sl.Err(err))

			return false, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}

		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}

func (a *Auth) DeleteAdmin(ctx context.Context, identifier models.UserIdentifier, appID int64) error {
	const op = "auth.DeleteAdmin"
	log := a.log.With(slog.String("op", op))
	log.Info("deleting admin")

	switch {
	case identifier.ID != nil:
		err := a.adminProvider.DeleteAdminByUserID(ctx, *identifier.ID, appID)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				log.Warn("user not found", sl.Err(err))
			}

			return fmt.Errorf("%s: %w", op, err)
		}
	case identifier.Username != nil:
		err := a.adminProvider.DeleteAdminByUsername(ctx, *identifier.Username, appID)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				log.Warn("user not found", sl.Err(err))
			}

			return fmt.Errorf("%s: %w", op, err)
		}
	case identifier.Email != nil:
		err := a.adminProvider.DeleteAdminByEmail(ctx, *identifier.Email, appID)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				log.Warn("user not found", sl.Err(err))
			}

			return fmt.Errorf("%s: %w", op, err)
		}
	default:
		return fmt.Errorf("%s: %w", op, ErrInvalidIdentifier)
	}

	return nil
}

func (a *Auth) RegisterApp(ctx context.Context, appName, redirectURI string) (appID int64, secret string, err error) {
	const op = "auth.RegisterApp"
	log := a.log.With(slog.String("op", op))
	log.Info("registering app")

	secretKey := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, secretKey)
	if err != nil {
		return 0, "", err
	}

	encrypted, err := encryptor.EncryptString([]byte(os.Getenv("MASTER_KEY")), []byte(hex.EncodeToString(secretKey)))
	if err != nil {
		log.Warn("encrypting error", sl.Err(err))
		return 0, "", err
	}

	id, err := a.appProvider.RegisterApp(ctx, appName, encrypted, redirectURI)
	if err != nil {
		if errors.Is(err, storage.ErrAppExists) {
			log.Warn("app already exists", sl.Err(err))
			return 0, "", ErrAppExists
		}

		log.Warn("register app error", sl.Err(err))
		return 0, "", ErrInvalidCredentials
	}

	a.appSecrets.Store(id, hex.EncodeToString(secretKey))

	return id, hex.EncodeToString(secretKey), nil
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

	a.appSecrets.Delete(appID)

	return nil
}

func (a *Auth) UpdateRefreshToken(ctx context.Context, token string) (string, error) {
	const op = "auth.UpdateRefreshToken"
	log := a.log.With(slog.String("op", op))
	log.Info("trying to update refresh token", "Old token", fmt.Sprintf("***%s", tokenFingerprint(token)))

	fields, err := a.jwtProvider.GetRefreshTokenFields(ctx, token)
	if err != nil {
		log.Warn("error", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	secret, ok := a.appSecrets.Load(fields.AppId)
	if !ok {
		app, err := a.appProvider.App(ctx, fields.AppId)
		if err != nil {
			log.Warn("error", sl.Err(err))
			return "", fmt.Errorf("%s: %w", op, err)
		}
		secret = app.Secret
	}

	refreshToken, err := jwt.NewRefreshToken(fields.UserID, fields.AppId, a.RefreshTokenTTL, secret.(string))
	if err != nil {
		log.Warn("error", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	err = a.jwtProvider.SetNewRefreshToken(ctx, token, refreshToken, a.RefreshTokenTTL)
	if err != nil {
		log.Warn("error", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return refreshToken, nil
}

func tokenFingerprint(token string) string {
	if token == "" {
		return "empty"
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}
