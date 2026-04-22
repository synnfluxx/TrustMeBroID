package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/sl"
	"github.com/synnfluxx/TrustMeBroID/internal/services/oauth"
)

type Storage interface {
	SaveOAuthUser(ctx context.Context, email, username string, appID int64) (usr models.User, err error)
	App(ctx context.Context, appID int64) (models.App, error)
	UserByEmail(ctx context.Context, email string, appID int64) (models.User, error)
}

type GitHubUser struct {
	Email    string `json:"email"`
	Username string `json:"login"`
}

type OAuthService interface {
	Login() (string, string)
	Callback(code string, appID int64, tokenTTL time.Duration) (accessToken string, refreshToken string, err error)
}

type Server struct {
	log             *slog.Logger
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	GithubOAuth     *oauth.OAuthService
}

func NewHTTPHandlerServer(storage Storage, tokenProvider oauth.TokenProvider, log *slog.Logger, accessTokenTTL, refreshTokenTTL time.Duration) *Server {
	return &Server{
		log:             log,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
		GithubOAuth:     oauth.New(oauth.NewGithubConfig(), storage, tokenProvider, log),
	}
}

func (s *Server) jsonResponce(w http.ResponseWriter, status int, payload any) {
	resp, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(resp))
}

func (s *Server) respondError(w http.ResponseWriter, code int, message string) {
	s.jsonResponce(w, code, map[string]string{"error": message})
}

func (s *Server) GitHubLoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var appID string
		var uri string
		if appID = r.URL.Query().Get("app_id"); appID == "" {
			s.respondError(w, http.StatusBadRequest, "app_id is required")
			return
		}
		if uri = r.URL.Query().Get("uri"); uri == "" {
			s.respondError(w, http.StatusBadRequest, "uri is required")
			return
		}

		aid, err := strconv.Atoi(appID)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, "invalid app_id")
			return
		}
		state, url := s.GithubOAuth.Login(int64(aid))

		s.setState(w, state)
		s.setURI(uri, w)

		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func (s *Server) GitHubOAuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		oauthState, err := r.Cookie("oauth_state")
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}

		uri, err := r.Cookie("uri")
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}

		state := r.URL.Query().Get("state")
		parts := strings.Split(state, ":")
		if len(parts[1]) == 0 {
			s.respondError(w, http.StatusBadRequest, "invalid state")
			return
		}

		appID, err := strconv.Atoi(parts[1])
		if err != nil {
			s.log.Warn("str to int conv failed: ", sl.Err(err))
			s.respondError(w, http.StatusBadRequest, "bad request")
			return
		}
		if oauthState.Value != state {
			s.respondError(w, http.StatusBadRequest, "bad request")
			return
		}

		token, refreshToken, err := s.GithubOAuth.Callback(r.FormValue("code"), int64(appID), s.accessTokenTTL, s.refreshTokenTTL)
		if err != nil {
			if errors.Is(err, oauth.ErrInvalidFields) {
				s.log.Warn("github oauth callback error: ", sl.Err(err))
				s.respondError(w, http.StatusBadRequest, err.Error())
				return
			}

			s.log.Warn("get tokens error", sl.Err(err))
			s.respondError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		s.setRefershToken(w, refreshToken)
		redirectURL := fmt.Sprintf("%s?token=%s", uri.Value, token)
		http.Redirect(w, r, redirectURL, http.StatusPermanentRedirect)
	}
}

func (s *Server) setState(w http.ResponseWriter, state string) {
	cookie := &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HttpOnly: true,
		MaxAge:   600,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

func (s *Server) setURI(uri string, w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "uri",
		Value:    uri,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
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
	}
	http.SetCookie(w, cookie)
}
