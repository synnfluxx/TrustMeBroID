package handlers

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
)

type OAuthService interface {
	Login(ctx context.Context, appID int64) (string, string, error)
	Callback(ctx context.Context, code string, appID int64, accessTTL, refreshTTL time.Duration) (accessToken string, refreshToken string, redirectURI string, err error)
}

func (s *Server) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var appID string
		if appID = r.URL.Query().Get("app_id"); appID == "" {
			s.respondError(w, http.StatusBadRequest, "app_id is required")
			return
		}

		aid, err := strconv.Atoi(appID)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, "invalid app_id")
			return
		}

		state, url, err := s.OAuth.Login(r.Context(), int64(aid))
		if err != nil {
			if errors.Is(err, storage.ErrAppNotFound) {
				s.respondError(w, http.StatusBadRequest, "invalid app_id")
				return
			}
			// Previously execution fell through this block on any other error
			// and redirected the browser to an empty URL.
			logger.From(r.Context(), s.log).Error("oauth login failed",
				slog.Int("app_id", aid),
				slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
			s.respondError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		s.setState(w, state)

		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func (s *Server) CallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logger.From(r.Context(), s.log).With(slog.String(logger.KeyOp, "oauth.callback"))

		appID, err := s.getAndValidateState(r)
		if err != nil {
			// A state mismatch is the signature of a CSRF attempt or of a stale
			// tab, so the rejection is recorded rather than silently answered
			// with a 400.
			log.Warn("oauth callback rejected: state validation failed",
				slog.String("reason", "state_mismatch"),
				slog.String("client_ip", r.RemoteAddr),
				slog.String(logger.KeyOutcome, logger.OutcomeRejected), sl.Err(err))
			s.respondError(w, http.StatusBadRequest, "bad request")
			return
		}

		log = log.With(slog.Int64(logger.KeyAppID, appID))

		token, refreshToken, uri, err := s.OAuth.Callback(r.Context(), r.FormValue("code"), appID, s.accessTokenTTL, s.refreshTokenTTL)
		if err != nil {
			log.Error("oauth callback failed",
				slog.String(logger.KeyOutcome, logger.OutcomeFailed), sl.Err(err))
			s.respondError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		// The redirect carries the access token in the query string, so the
		// target is logged but the built URL never is.
		log.Info("oauth callback completed, redirecting client",
			slog.String("redirect_host", redirectHost(uri)),
			slog.String(logger.KeyOutcome, logger.OutcomeSuccess))

		s.setRefershToken(w, refreshToken)
		redirectURL := fmt.Sprintf("%s?token=%s", uri, token)
		http.Redirect(w, r, redirectURL, http.StatusPermanentRedirect)
	}
}

func (s *Server) getAndValidateState(r *http.Request) (int64, error) {
	// Every failure below used to return the `err` from r.Cookie, which is nil
	// once the cookie has been read successfully. The caller checks
	// `if err != nil`, so a state mismatch returned (appID, nil) and the
	// callback proceeded: the CSRF check never rejected anything.
	oauthState, err := r.Cookie("oauth_state")
	if err != nil {
		return 0, fmt.Errorf("oauth_state cookie is missing: %w", err)
	}

	state := r.URL.Query().Get("state")
	if state == "" {
		return 0, errors.New("state query parameter is missing")
	}

	parts := strings.Split(state, ":")
	if len(parts) < 2 || parts[1] == "" {
		return 0, errors.New(`state is malformed: expected "<nonce>:<app_id>"`)
	}

	appID, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("state carries a non-numeric app id: %w", err)
	}

	// The comparison is the CSRF check itself, so it runs in constant time.
	if subtle.ConstantTimeCompare([]byte(oauthState.Value), []byte(state)) != 1 {
		return 0, errors.New("state does not match the oauth_state cookie")
	}

	return int64(appID), nil
}

func (s *Server) setState(w http.ResponseWriter, state string) {
	cookie := &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HttpOnly: true,
		MaxAge:   600,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
	}
	http.SetCookie(w, cookie)
}

func (s *Server) setRefershToken(w http.ResponseWriter, token string) {
	cookie := &http.Cookie{
		Name:     "refreshToken",
		Value:    token,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.refreshTokenTTL.Seconds()),
		Secure:   true,
	}
	http.SetCookie(w, cookie)
}

// redirectHost reduces a redirect target to its host, so the log shows where a
// user was sent without retaining the token carried in the query string.
func redirectHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "[unparsable]"
	}
	return u.Host
}
