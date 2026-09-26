package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
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
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	tokengenerator "github.com/synnfluxx/TrustMeBroID/internal/lib/tokenGenerator"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	//ErrInvalidAppID       = errors.New("invalid app id")
	ErrUserExists               = errors.New("user already exists")
	ErrAppExists                = errors.New("app already exists")
	ErrUserNotFound             = errors.New("user not found")
	ErrInvalidIdentifier        = errors.New("invalid identifier")
	ErrUserNotVerified          = errors.New("user not verified")
	ErrVerificationTokenExpired = errors.New("verification token expired")
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
	EmailService    EmailService
	appSecrets      sync.Map
}

type EmailService interface {
	SendVerificationEmail(email, verificationToken string, URL string) error
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, username string, passHash []byte, appID int64, verificationCode string) (uid int64, err error)
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
	VerifyUser(ctx context.Context, email string, appID int64) error
	UpdateVerificationToken(ctx context.Context, email string, appID int64, newToken string) error
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

func New(log *slog.Logger, userSaver UserSaver, userProvider UserProvider, appProvider AppProvider, adminProvider AdminProvider, jwtProvider JWTProvider, passwordVerifier PasswordVerifier, accessTokenTTL, refreshTokenTTL time.Duration, emailService EmailService) *Auth {
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
		EmailService:    emailService,
		appSecrets:      sync.Map{},
	}
}

func (a *Auth) MakeAdmin(ctx context.Context, userID, appID int64) (uid int64, err error) {
	const op = "auth.MakeAdmin"
	log := logger.Op(ctx, a.log, op).With(
		slog.Int64(logger.KeyUserID, userID),
		slog.Int64(logger.KeyAppID, appID),
	)

	// Privilege grants are audit events: they are rare, they are irreversible
	// from the user's side, and someone will eventually need to answer "who
	// made this account an admin, and when".
	log.Info("granting admin privileges")

	uid, err = a.adminProvider.MakeAdmin(ctx, userID, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("admin grant rejected: user does not exist",
				slog.String(logger.KeyOutcome, logger.OutcomeRejected), sl.Err(err))
			return 0, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}

		log.Error("admin grant failed",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("admin privileges granted",
		slog.Int64("admin_row_id", uid),
		slog.String(logger.KeyOutcome, logger.OutcomeSuccess))

	return uid, err
}

func (a *Auth) Login(ctx context.Context, identifier models.UserIdentifier, password string, appID int64) (string, string, error) {
	const op = "auth.Login"
	start := time.Now()

	// identifier_type tells us which login form users actually use, and keeps
	// the three lookup branches distinguishable in the log without printing the
	// identifier itself at every step.
	log := logger.Op(ctx, a.log, op).With(
		slog.Int64(logger.KeyAppID, appID),
		slog.String("identifier_type", identifierType(identifier)),
	)
	log.Debug("login attempt received")

	user, err := a.lookupUser(ctx, log, identifier, appID)
	if err != nil {
		return "", "", err
	}

	log = log.With(slog.Int64(logger.KeyUserID, user.ID))

	if err := a.pwVerifier.Compare(user.PassHash, []byte(password)); err != nil {
		// A wrong password is an ordinary event, not an operational fault, so
		// it stays at warn and never pages anyone. It is logged at all because
		// a burst of these from one peer is how credential stuffing looks.
		log.Warn("login rejected: password mismatch",
			slog.String("reason", "bad_password"),
			slog.String(logger.KeyOutcome, logger.OutcomeRejected),
			sl.Since(start))
		return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	if !user.IsVerified {
		// Distinct from a bad password: this user knows their credentials and
		// is blocked by the verification flow. If this reason dominates the
		// rejections, email delivery is broken, not the users.
		log.Warn("login rejected: email not verified",
			slog.String("reason", "email_not_verified"),
			slog.String(logger.KeyOutcome, logger.OutcomeRejected),
			sl.Since(start))
		return "", "", fmt.Errorf("%s: %w", op, ErrUserNotVerified)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		log.Error("login failed: cannot load application secret",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed),
			sl.Err(err), sl.Since(start))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	accessToken, refreshToken, err := jwt.NewTokens(user.ID, app.ID, app.Secret, a.RefreshTokenTTL, a.AccessTokenTTL)
	if err != nil {
		log.Error("login failed: cannot sign tokens",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed),
			sl.Err(err), sl.Since(start))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	if err := a.jwtProvider.SaveRefreshToken(ctx, refreshToken, user.ID, app.ID, a.RefreshTokenTTL); err != nil {
		// The tokens exist but the refresh token was never persisted, so the
		// session dies at the first refresh. Saying so here saves debugging a
		// "users are randomly logged out" report later.
		log.Error("login failed: refresh token not persisted",
			slog.String("impact", "the session would end at the first refresh"),
			slog.String(logger.KeyOutcome, logger.OutcomeFailed),
			sl.Err(err), sl.Since(start))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("login succeeded",
		sl.Token("refresh", refreshToken),
		slog.Duration("access_ttl", a.AccessTokenTTL),
		slog.Duration("refresh_ttl", a.RefreshTokenTTL),
		slog.String(logger.KeyOutcome, logger.OutcomeSuccess),
		sl.Since(start))

	return accessToken, refreshToken, nil
}

// lookupUser resolves whichever identifier the caller supplied. The three
// branches were previously copy-pasted with identical error handling; folding
// them together means a lookup failure is reported one way instead of three.
func (a *Auth) lookupUser(ctx context.Context, log *slog.Logger, identifier models.UserIdentifier, appID int64) (models.User, error) {
	const op = "auth.Login"

	var (
		user models.User
		err  error
	)

	switch {
	case identifier.Username != nil:
		user, err = a.usrProvider.UserByUsername(ctx, *identifier.Username, appID)
	case identifier.Email != nil:
		user, err = a.usrProvider.UserByEmail(ctx, *identifier.Email, appID)
	case identifier.ID != nil:
		user, err = a.usrProvider.User(ctx, *identifier.ID, appID)
	default:
		log.Warn("login rejected: no identifier supplied",
			slog.String("reason", "missing_identifier"),
			slog.String(logger.KeyOutcome, logger.OutcomeRejected))
		return models.User{}, fmt.Errorf("%s: %w", op, ErrInvalidIdentifier)
	}

	if err == nil {
		return user, nil
	}

	switch {
	case errors.Is(err, storage.ErrUserNotFound):
		log.Warn("login rejected: no such account",
			slog.String("reason", "user_not_found"),
			slog.String(logger.KeyOutcome, logger.OutcomeRejected))
		return models.User{}, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)

	case errors.Is(err, storage.ErrUserDeleted):
		// Same response to the caller as "not found", but a different cause:
		// worth separating so support can tell a deleted account from a typo.
		log.Warn("login rejected: account is soft-deleted",
			slog.String("reason", "user_deleted"),
			slog.String(logger.KeyOutcome, logger.OutcomeRejected))
		return models.User{}, fmt.Errorf("%s: %w", op, ErrInvalidCredentials)

	default:
		log.Error("login failed: user lookup error",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}
}

// identifierType names the branch taken, without revealing the value.
func identifierType(identifier models.UserIdentifier) string {
	switch {
	case identifier.Username != nil:
		return "username"
	case identifier.Email != nil:
		return "email"
	case identifier.ID != nil:
		return "user_id"
	default:
		return "none"
	}
}

func (a *Auth) Logout(ctx context.Context, token string) error {
	const op = "auth.Logout"
	log := logger.Op(ctx, a.log, op).With(sl.Token("refresh", token))

	if err := a.jwtProvider.Logout(ctx, token); err != nil {
		log.Error("logout failed: refresh token could not be revoked",
			slog.String("impact", "the token stays valid until it expires"),
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("refresh token revoked",
		slog.String(logger.KeyOutcome, logger.OutcomeSuccess))

	return nil
}

func (a *Auth) RegisterNewUser(ctx context.Context, email, username, pass string, appID int64) (int64, error) {
	const op = "auth.RegisterNewUser"
	start := time.Now()

	log := logger.Op(ctx, a.log, op).With(
		slog.Int64(logger.KeyAppID, appID),
		sl.Email(email),
		sl.Username(username),
	)
	// The removed line here logged the plaintext password, the address and the
	// username at debug level. Debug is the default level outside production,
	// so every developer's terminal and every dev container's log collector
	// received real credentials. Nothing in this function logs `pass`.
	log.Info("registering user")

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("registration rejected: unknown application",
				slog.String("reason", "app_not_found"),
				slog.String(logger.KeyOutcome, logger.OutcomeRejected), sl.Err(err))
			return 0, storage.ErrAppNotFound
		}

		log.Error("registration failed: cannot load application",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	hashStart := time.Now()
	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Error("registration failed: cannot hash password",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	// bcrypt is the slowest step in registration by an order of magnitude.
	// Tracking it separately keeps a slow registration from being blamed on
	// the database.
	log.Debug("password hashed",
		slog.Int("bcrypt_cost", bcrypt.DefaultCost), sl.Dur(time.Since(hashStart)))

	verificationToken, err := tokengenerator.GenerateToken()
	if err != nil {
		log.Error("registration failed: cannot generate verification token",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.usrSaver.SaveUser(ctx, email, username, passHash, appID, verificationToken)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("registration rejected: account already exists",
				slog.String("reason", "user_exists"),
				slog.String(logger.KeyOutcome, logger.OutcomeRejected), sl.Err(err))
			return 0, ErrUserExists
		}
		log.Error("registration failed: cannot save user",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log = log.With(slog.Int64(logger.KeyUserID, id))
	log.Info("user row created, sending verification email",
		sl.Token("verification", verificationToken))

	if err := a.EmailService.SendVerificationEmail(email, verificationToken, app.RedirectURI); err != nil {
		// The account exists but the user was never told how to activate it,
		// and the caller will see a failed registration. Both halves of that
		// state are recorded so the account can be found and the mail resent.
		log.Error("registration incomplete: verification email was not sent",
			slog.Int64("orphaned_user_id", id),
			slog.String("impact", "account exists but cannot be verified or logged into"),
			slog.String("remedy", "resend verification for this address"),
			slog.String(logger.KeyOutcome, logger.OutcomeFailed),
			sl.Err(err), sl.Since(start))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered",
		slog.String(logger.KeyOutcome, logger.OutcomeSuccess),
		sl.Since(start))

	return id, nil
}

func (a *Auth) DeleteUser(ctx context.Context, identifier models.UserIdentifier, appID int64) error {
	const op = "auth.DeleteUser"
	log := logger.Op(ctx, a.log, op).With(
		slog.Int64(logger.KeyAppID, appID),
		slog.String("identifier_type", identifierType(identifier)),
	)
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
	start := time.Now()
	log := logger.Op(ctx, a.log, op).With(sl.Token("refresh", token))

	data, err := a.jwtProvider.GetRefreshTokenFields(ctx, token)
	if err != nil {
		if errors.Is(err, storage.ErrTokenNotFound) {
			// Expected whenever a token has expired, been rotated or been
			// revoked. It is the normal end of a session, so it is a warn and
			// not an error, but it is recorded: a spike here means sessions
			// are dying earlier than the configured TTL.
			log.Warn("refresh rejected: token not found in store",
				slog.String("reason", "token_not_found"),
				slog.String(logger.KeyOutcome, logger.OutcomeRejected))
			return "", storage.ErrTokenNotFound
		}

		log.Error("refresh failed: token store unreachable",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return "", err
	}

	log = log.With(
		slog.Int64(logger.KeyUserID, data.UserID),
		slog.Int64(logger.KeyAppID, data.AppId),
	)

	secret, ok := a.appSecrets.Load(data.AppId)
	if !ok {
		log.Debug("app secret not cached, loading from storage")

		app, err := a.appProvider.App(ctx, data.AppId)
		if err != nil {
			log.Error("refresh failed: cannot load application secret",
				slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
			return "", err
		}

		secret = app.Secret
		a.appSecrets.Store(app.ID, app.Secret)
	}

	newToken, err := jwt.NewAccessToken(data.UserID, data.AppId, a.AccessTokenTTL, secret.(string))
	if err != nil {
		log.Error("refresh failed: cannot sign access token",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return "", err
	}

	// Refresh runs on every client every few minutes, so the success path stays
	// at debug: the gRPC access log already records that the call happened.
	log.Debug("access token reissued",
		slog.Duration("access_ttl", a.AccessTokenTTL),
		slog.String(logger.KeyOutcome, logger.OutcomeSuccess),
		sl.Since(start))

	return newToken, nil
}

func (a *Auth) IsAdmin(ctx context.Context, UserID int64, appID int64) (bool, error) {
	const op = "auth.IsAdmin"

	log := logger.Op(ctx, a.log, op).With(
		slog.Int64(logger.KeyUserID, UserID),
		slog.Int64(logger.KeyAppID, appID),
	)

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
	log := logger.Op(ctx, a.log, op).With(
		slog.Int64(logger.KeyAppID, appID),
		slog.String("identifier_type", identifierType(identifier)),
	)
	// Revoking admin rights is an audit event for the same reason granting them is.
	log.Info("revoking admin privileges")

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
	// Registering an application mints a signing key for a whole tenant. It is
	// an administrative, audit-worthy event, so it is logged in full — minus
	// the secret, which is what the whole thing protects.
	log := logger.Op(ctx, a.log, op).With(
		slog.String("app_name", appName),
		slog.String("redirect_uri", redirectURI),
	)
	log.Info("registering application")

	secretKey := make([]byte, 16)
	if _, err = io.ReadFull(rand.Reader, secretKey); err != nil {
		log.Error("app registration failed: no entropy for the app secret",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return 0, "", err
	}
	plainSecret := hex.EncodeToString(secretKey)

	masterKey := []byte(os.Getenv("MASTER_KEY"))
	encrypted, err := encryptor.EncryptString(masterKey, []byte(plainSecret))
	if err != nil {
		log.Error("app registration failed: cannot encrypt the app secret",
			slog.Int("master_key_len", len(masterKey)),
			slog.String("expected_key_len", "16, 24 or 32 bytes"),
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return 0, "", err
	}

	id, err := a.appProvider.RegisterApp(ctx, appName, encrypted, redirectURI)
	if err != nil {
		if errors.Is(err, storage.ErrAppExists) {
			log.Warn("app registration rejected: application already exists",
				slog.String("reason", "app_exists"),
				slog.String(logger.KeyOutcome, logger.OutcomeRejected))
			return 0, "", ErrAppExists
		}

		// The original code mapped every storage failure to
		// ErrInvalidCredentials, so a database outage surfaced as a credential
		// problem. The log now records what actually happened.
		log.Error("app registration failed: storage error",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return 0, "", ErrInvalidCredentials
	}

	a.appSecrets.Store(id, plainSecret)

	log.Info("application registered",
		slog.Int64(logger.KeyAppID, id),
		sl.Token("app_secret", plainSecret),
		slog.String(logger.KeyOutcome, logger.OutcomeSuccess))

	return id, plainSecret, nil
}

func (a *Auth) DeleteApp(ctx context.Context, appID int64) error {
	const op = "auth.DeleteApp"
	log := logger.Op(ctx, a.log, op).With(slog.Int64(logger.KeyAppID, appID))
	log.Info("deleting application",
		slog.String("impact", "all tokens signed with this app secret stop validating"))

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
	start := time.Now()
	log := logger.Op(ctx, a.log, op).With(sl.Token("old_refresh", token))

	// Every branch below used to log the word "error" and nothing else, which
	// told an operator that rotation failed but not at which of the four steps.
	fields, err := a.jwtProvider.GetRefreshTokenFields(ctx, token)
	if err != nil {
		if errors.Is(err, storage.ErrTokenNotFound) {
			log.Warn("rotation rejected: token not found in store",
				slog.String("reason", "token_not_found"),
				slog.String(logger.KeyOutcome, logger.OutcomeRejected))
			return "", fmt.Errorf("%s: %w", op, err)
		}
		log.Error("rotation failed: token store unreachable",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log = log.With(
		slog.Int64(logger.KeyUserID, fields.UserID),
		slog.Int64(logger.KeyAppID, fields.AppId),
	)

	secret, ok := a.appSecrets.Load(fields.AppId)
	if !ok {
		log.Debug("app secret not cached, loading from storage")
		app, err := a.appProvider.App(ctx, fields.AppId)
		if err != nil {
			log.Error("rotation failed: cannot load application secret",
				slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
			return "", fmt.Errorf("%s: %w", op, err)
		}
		secret = app.Secret
	}

	refreshToken, err := jwt.NewRefreshToken(fields.UserID, fields.AppId, a.RefreshTokenTTL, secret.(string))
	if err != nil {
		log.Error("rotation failed: cannot sign the new refresh token",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err := a.jwtProvider.SetNewRefreshToken(ctx, token, refreshToken, a.RefreshTokenTTL); err != nil {
		// The client is about to be handed a token the store does not know, so
		// its next refresh will fail and the user will be signed out.
		log.Error("rotation failed: the new token was not persisted",
			slog.String("impact", "client would receive a token the store does not know"),
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("refresh token rotated",
		sl.Token("new_refresh", refreshToken),
		slog.Duration("refresh_ttl", a.RefreshTokenTTL),
		slog.String(logger.KeyOutcome, logger.OutcomeSuccess),
		sl.Since(start))

	return refreshToken, nil
}

// verificationTokenTTL must stay in step with the copy in the email template.
const verificationTokenTTL = 72 * time.Hour

func (a *Auth) VerifyUserEmail(ctx context.Context, email string, VerificationToken string, appID int64) (string, string, error) {
	const op = "auth.VerifyUserEmail"
	start := time.Now()
	log := logger.Op(ctx, a.log, op).With(
		slog.Int64(logger.KeyAppID, appID),
		sl.Email(email),
		sl.Token("presented_verification", VerificationToken),
	)
	log.Debug("verification attempt received")

	usr, err := a.usrProvider.UserByEmail(ctx, email, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("verification rejected: no account for this address",
				slog.String("reason", "user_not_found"),
				slog.String(logger.KeyOutcome, logger.OutcomeRejected))
			return "", "", ErrUserNotFound
		}

		log.Error("verification failed: user lookup error",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log = log.With(slog.Int64(logger.KeyUserID, usr.ID))

	// The code is checked before anything else, including the already-verified
	// shortcut. This call now hands back a session, so a path that skipped the
	// check would let anyone who knows a registered address obtain one.
	if usr.LastTokenGeneratedTime.Valid {
		age := time.Since(usr.LastTokenGeneratedTime.Time)
		if age > verificationTokenTTL {
			log.Warn("verification rejected: token expired",
				slog.String("reason", "token_expired"),
				slog.Time("token_issued_at", usr.LastTokenGeneratedTime.Time),
				slog.Duration("token_age", age),
				slog.Duration("ttl", verificationTokenTTL),
				slog.String(logger.KeyOutcome, logger.OutcomeRejected),
				sl.Since(start))
			return "", "", fmt.Errorf("%s: %w", op, ErrVerificationTokenExpired)
		}
	} else {
		log.Warn("verification token has no issue timestamp, expiry not enforced",
			slog.String("reason", "missing_issued_at"))
	}

	if subtle.ConstantTimeCompare([]byte(usr.VerificationCode), []byte(VerificationToken)) != 1 {
		log.Warn("verification rejected: token mismatch",
			slog.String("reason", "token_mismatch"),
			sl.Token("expected_verification", usr.VerificationCode),
			slog.String(logger.KeyOutcome, logger.OutcomeRejected),
			sl.Since(start))
		return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	if usr.IsVerified {
		// Users click the link twice. The code was still checked above, so
		// issuing a session here is safe and keeps the flow idempotent.
		log.Info("account was already verified, issuing a session anyway",
			slog.String("reason", "already_verified"))
	} else if err := a.usrProvider.VerifyUser(ctx, email, appID); err != nil {
		log.Error("verification failed: cannot mark account verified",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	accessToken, refreshToken, err := a.issueSession(ctx, log, usr.ID, appID)
	if err != nil {
		// The address is confirmed either way; only the session failed. The
		// caller can still log in with the password.
		log.Error("account verified but the session could not be issued",
			slog.String("impact", "the address is confirmed; the user must log in manually"),
			slog.String(logger.KeyOutcome, logger.OutcomeFailed),
			sl.Err(err), sl.Since(start))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("account verified and signed in",
		sl.Token("refresh", refreshToken),
		slog.String(logger.KeyOutcome, logger.OutcomeSuccess),
		sl.Since(start))

	return accessToken, refreshToken, nil
}

// issueSession mints and persists a token pair for a user whose identity has
// just been established. Shared by Login and by email verification so both
// paths produce sessions with identical lifetimes and storage.
func (a *Auth) issueSession(ctx context.Context, log *slog.Logger, userID, appID int64) (string, string, error) {
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		log.Error("cannot load application secret", sl.Err(err))
		return "", "", err
	}

	accessToken, refreshToken, err := jwt.NewTokens(userID, app.ID, app.Secret, a.RefreshTokenTTL, a.AccessTokenTTL)
	if err != nil {
		log.Error("cannot sign tokens", sl.Err(err))
		return "", "", err
	}

	if err := a.jwtProvider.SaveRefreshToken(ctx, refreshToken, userID, app.ID, a.RefreshTokenTTL); err != nil {
		log.Error("refresh token not persisted",
			slog.String("impact", "the session would end at the first refresh"), sl.Err(err))
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (a *Auth) GenerateNewVerificationToken(ctx context.Context, email string, appID int64) error {
	const op = "auth.GenerateNewVerificationToken"
	start := time.Now()
	log := logger.Op(ctx, a.log, op).With(
		slog.Int64(logger.KeyAppID, appID),
		sl.Email(email),
	)
	log.Info("issuing a new verification token")

	usr, err := a.usrProvider.UserByEmail(ctx, email, appID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			// This endpoint takes an arbitrary address, so it doubles as an
			// account-existence probe. Repeated misses from one source are the
			// signature of enumeration and need to be visible.
			log.Warn("resend rejected: no account for this address",
				slog.String("reason", "user_not_found"),
				slog.String(logger.KeyOutcome, logger.OutcomeRejected))
			return ErrUserNotFound
		}

		log.Error("resend failed: user lookup error",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log = log.With(slog.Int64(logger.KeyUserID, usr.ID))

	if usr.IsVerified {
		log.Info("resend requested for an already verified account",
			slog.String("reason", "already_verified"))
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("resend rejected: unknown application",
				slog.String("reason", "app_not_found"),
				slog.String(logger.KeyOutcome, logger.OutcomeRejected))
			return storage.ErrAppNotFound
		}

		log.Error("resend failed: cannot load application",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	newVerificationToken, err := tokengenerator.GenerateToken()
	if err != nil {
		log.Error("resend failed: cannot generate token",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := a.usrProvider.UpdateVerificationToken(ctx, email, appID, newVerificationToken); err != nil {
		log.Error("resend failed: cannot store the new token",
			slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	// Ordering matters for diagnosis: past this point the previous token is
	// already dead, so a send failure leaves the user with no working link.
	log.Debug("verification token rotated, previous token is now invalid",
		sl.Token("new_verification", newVerificationToken))

	if err := a.EmailService.SendVerificationEmail(email, newVerificationToken, app.RedirectURI); err != nil {
		log.Error("resend failed: token was rotated but the email was not sent",
			slog.String("impact", "the previous link no longer works and no new one was delivered"),
			slog.String(logger.KeyOutcome, logger.OutcomeFailed),
			sl.Err(err), sl.Since(start))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("verification email resent",
		slog.String(logger.KeyOutcome, logger.OutcomeSuccess),
		sl.Since(start))
	return nil
}
