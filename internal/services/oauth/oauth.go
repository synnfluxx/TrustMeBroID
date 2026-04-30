package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/jwt"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
)

var ErrInvalidFields = errors.New("invailid oauth user data")

type Storage interface {
	SaveOAuthUser(ctx context.Context, email, username string, appID int64) (usr models.User, err error)
	App(ctx context.Context, appID int64) (models.App, error)
	UserByEmail(ctx context.Context, email string, appID int64) (models.User, error)
}

type OAuthService struct {
	config        OAuthConfig
	storage       Storage
	tokenProvider TokenProvider
	log           *slog.Logger
}

type TokenProvider interface {
	SaveRefreshToken(ctx context.Context, token string, userID int64, appID int64, ttl time.Duration) error
}

type OAuthConfig interface {
	URL(state string) string
	Callback(code string) (map[string]string, error)
}

func New(OAuthConfig OAuthConfig, storage Storage, rdb TokenProvider, log *slog.Logger) *OAuthService {
	return &OAuthService{
		config:        OAuthConfig,
		storage:       storage,
		tokenProvider: rdb,
		log:           log,
	}
}

func (o *OAuthService) Login(appID int64) (state string, url string) { // Provider url for permission ask
	b := make([]byte, 16)
	rand.Read(b)
	state = fmt.Sprintf("%s:%d", hex.EncodeToString(b), appID)

	return state, o.config.URL(state)
}

func (o *OAuthService) Callback(ctx context.Context, code string, appID int64, accessTTL, refreshTTL time.Duration) (accessToken string, refreshToken string, err error) {
	oauthUser, err := o.config.Callback(code)
	if err != nil {
		return "", "", err
	}

	username, ok := oauthUser["username"]
	if !ok {
		return "", "", ErrInvalidFields
	}
	email, ok := oauthUser["email"]
	if !ok {
		return "", "", ErrInvalidFields
	}

	usr, err := o.storage.SaveOAuthUser(ctx, email, username, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			usr, err = o.storage.UserByEmail(ctx, email, appID)
			if err != nil {
				o.log.Warn("github oauth callback get user error: ", sl.Err(err))
				return "", "", err
			}
		} else {
			o.log.Warn("github oauth callback save user error: ", sl.Err(err))
			return "", "", err
		}
	}

	app, err := o.storage.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			return "", "", err
		}

		o.log.Warn("github oauth callback get app error: ", sl.Err(err))
		return "", "", err
	}

	accessToken, refreshToken, err = jwt.NewTokens(usr.ID, app.ID, app.Secret, refreshTTL, accessTTL)
	if err != nil {
		o.log.Warn("oauth callback get jwt token error: ", sl.Err(err))
		return "", "", err
	}

	err = o.tokenProvider.SaveRefreshToken(ctx, refreshToken, usr.ID, int64(appID), refreshTTL)
	if err != nil {
		o.log.Warn("save refresh token error", sl.Err(err))
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
