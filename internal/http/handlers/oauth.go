package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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
		}

		s.setState(w, state)

		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func (s *Server) CallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appID, err := s.getAndValidateState(r)
		if err != nil {
			s.log.Warn("state validation error", sl.Err(err))
			s.respondError(w, http.StatusBadRequest, "bad request")
			return
		}

		token, refreshToken, uri, err := s.OAuth.Callback(r.Context(), r.FormValue("code"), appID, s.accessTokenTTL, s.refreshTokenTTL)
		if err != nil {
			s.log.Warn("get tokens error", sl.Err(err))
			s.respondError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		s.setRefershToken(w, refreshToken)
		redirectURL := fmt.Sprintf("%s?token=%s", uri, token)
		http.Redirect(w, r, redirectURL, http.StatusPermanentRedirect)
	}
}

func (s *Server) getAndValidateState(r *http.Request) (int64, error) {
	oauthState, err := r.Cookie("oauth_state")
	if err != nil {
		return 0, err
	}

	state := r.URL.Query().Get("state")
	parts := strings.Split(state, ":")
	if len(parts) < 2 {
		return 0, err
	}

	if len(parts[1]) == 0 {
		return 0, err
	}

	appID, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, err
	}
	
	if oauthState.Value != state {
		return 0, err
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
