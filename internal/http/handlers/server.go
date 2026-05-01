package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

type Server struct {
	log             *slog.Logger
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	OAuth           OAuthService
}

func NewHTTPOAuthServer(oauthService OAuthService, log *slog.Logger, accessTokenTTL, refreshTokenTTL time.Duration) *Server {
	return &Server{
		log:             log,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
		OAuth:           oauthService,
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
