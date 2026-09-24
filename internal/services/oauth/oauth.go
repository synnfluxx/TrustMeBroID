package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/jwt"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
)

type Storage interface {
	FindOrCreateOAuthUser(ctx context.Context, email, username string, appID int64) (usr models.User, err error)
	App(ctx context.Context, appID int64) (models.App, error)
	UserByEmail(ctx context.Context, email string, appID int64) (models.User, error)
}

type TokenProvider interface {
	SaveRefreshToken(ctx context.Context, token string, userID int64, appID int64, ttl time.Duration) error
}

type OAuthConfig interface {
	URL(state string) string
	Callback(ctx context.Context, code string) (*OAuthUserDetails, error)
}

type OAuthUserDetails struct {
	Email    string
	Username string
	Avatar   string
}

type OAuthService struct {
	config        OAuthConfig
	storage       Storage
	tokenProvider TokenProvider
	log           *slog.Logger
}

func New(OAuthConfig OAuthConfig, storage Storage, rdb TokenProvider, log *slog.Logger) *OAuthService {
	return &OAuthService{
		config:        OAuthConfig,
		storage:       storage,
		tokenProvider: rdb,
		log:           log,
	}
}

func (o *OAuthService) Login(ctx context.Context, appID int64) (state string, url string, err error) { // Provider url for permission ask
	const op = "oauth.Login"
	log := logger.Op(ctx, o.log, op).With(slog.Int64(logger.KeyAppID, appID))

	if _, err = o.storage.App(ctx, appID); err != nil {
		log.Warn("oauth login rejected: unknown application",
			slog.String("reason", "app_not_found"),
			slog.String(logger.KeyOutcome, logger.OutcomeRejected), sl.Err(err))
		return "", "", err
	}

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Previously ignored. Without entropy the CSRF state is predictable,
		// which is the whole point of the parameter.
		log.Error("oauth login failed: no entropy for the state parameter",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return "", "", err
	}
	state = fmt.Sprintf("%s:%d", hex.EncodeToString(b), appID)

	// The state value is a CSRF token, so it is fingerprinted rather than
	// printed; the log still lets the login and the callback be paired up.
	log.Info("oauth authorization started",
		slog.String("provider", "github"),
		sl.Token("state", state))

	return state, o.config.URL(state), nil
}

func (o *OAuthService) Callback(ctx context.Context, code string, appID int64, accessTTL, refreshTTL time.Duration) (accessToken string, refreshToken string, redirectURI string, err error) {
	const op = "oauth.Callback"
	start := time.Now()
	log := logger.Op(ctx, o.log, op).With(
		slog.Int64(logger.KeyAppID, appID),
		slog.String("provider", "github"),
	)

	// The authorization code is a single-use credential and is never logged,
	// only its presence.
	log.Debug("exchanging authorization code", slog.Bool("code_present", code != ""))

	oauthUser, err := o.config.Callback(ctx, code)
	if err != nil {
		log.Error("oauth callback failed: code exchange or profile fetch rejected",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return "", "", "", err
	}

	log = log.With(sl.Email(oauthUser.Email), sl.Username(oauthUser.Username))

	usr, err := o.storage.FindOrCreateOAuthUser(ctx, oauthUser.Email, oauthUser.Username, appID)
	if err != nil {
		log.Error("oauth callback failed: cannot resolve the local account",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return "", "", "", err
	}

	log = log.With(slog.Int64(logger.KeyUserID, usr.ID))

	app, err := o.storage.App(ctx, appID)
	if err != nil {
		log.Error("oauth callback failed: cannot load application secret",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return "", "", "", err
	}

	accessToken, refreshToken, err = jwt.NewOAuthTokens(usr.ID, app.ID, app.Secret, oauthUser.Avatar, refreshTTL, accessTTL)
	if err != nil {
		log.Error("oauth callback failed: cannot sign tokens",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return "", "", "", err
	}

	if err = o.tokenProvider.SaveRefreshToken(ctx, refreshToken, usr.ID, appID, refreshTTL); err != nil {
		log.Error("oauth callback failed: refresh token not persisted",
			slog.String("impact", "the session would end at the first refresh"),
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return "", "", "", err
	}

	// This path issues a session without checking IsVerified, unlike password
	// login. Recording it makes the difference auditable rather than implicit.
	log.Info("oauth login succeeded",
		slog.Bool("account_verified", usr.IsVerified),
		slog.Bool("email_verification_enforced", false),
		sl.Token("refresh", refreshToken),
		slog.String(logger.KeyOutcome, logger.OutcomeSuccess),
		sl.Since(start))

	return accessToken, refreshToken, app.RedirectURI, nil
}
