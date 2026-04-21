package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
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
	config  OAuthConfig
	storage Storage
	log *slog.Logger
}

type OAuthConfig interface {
	URL(state string) string
	Callback(code string) (map[string]string, error)
}

func New(OAuthConfig OAuthConfig, storage Storage, log *slog.Logger) *OAuthService {
	return &OAuthService{
		config:  OAuthConfig,
		storage: storage,
		log: log,
	}
}

func (o *OAuthService) Login() (string, string) {
	b := make([]byte, 16)
	rand.Read(b)
	state := hex.EncodeToString(b)

	return state, o.config.URL(state)
}

func (o *OAuthService) Callback(code string, appID int64, tokenTTL time.Duration) (string, error) {
	oauthUser, err := o.config.Callback(code)
	if err != nil {
		return "", err
	}

	username, ok := oauthUser["username"]
	email, ok := oauthUser["email"]
	if !ok {
		return "", ErrInvalidFields
	}

	usr, err := o.storage.SaveOAuthUser(context.Background(), email, username, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			usr, err = o.storage.UserByEmail(context.Background(), email, appID)
			if err != nil {
				o.log.Warn("github oauth callback get user error: ", sl.Err(err))
				return "", err
			}
		} else {
			o.log.Warn("github oauth callback save user error: ", sl.Err(err))
			return "", err
		}
	}

	app, err := o.storage.App(context.Background(), appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			return "", err
		}

		o.log.Warn("github oauth callback get app error: ", sl.Err(err))
		return "", err
	}

	token, err := jwt.NewToken(usr, app, tokenTTL)
	if err != nil {
		o.log.Warn("oauth callback get jwt token error: ", sl.Err(err))
		return "", err
	}

	return token, nil
}
