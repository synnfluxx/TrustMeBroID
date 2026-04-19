package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/oauth2"
)

type GithubOAuth struct {
	config *oauth2.Config
	userAPIURL string
}

type GithubUser struct {
	Email string `json:"email"`
	Username string `json:"login"`
	//TODO: avatar path
}

func NewGithubConfig() *GithubOAuth {
	return &GithubOAuth{
		config: &oauth2.Config{
			RedirectURL:  fmt.Sprintf("%s/auth/github/callback", os.Getenv("BASE_URL")),
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
			Scopes: []string{"user:email", "read:user"},
		},
		userAPIURL: "https://api.github.com/user",
	}
}

func (g *GithubOAuth) URL(state string) string {
	return g.config.AuthCodeURL(state)
}

func (g *GithubOAuth) Callback(code string) (map[string]string, error) {
	const op = "oauth.GitHubOAuthCallback"
	content, err := g.getUserDataFromGitHub(code)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	
	usr := &GithubUser{}
	err = json.Unmarshal(content, usr)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	
	return map[string]string{
		"username": usr.Username,
		"email": usr.Email,
	}, nil
}

func (g *GithubOAuth) getUserDataFromGitHub(code string) ([]byte, error) {
	token, err := g.config.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}

	client := g.config.Client(context.Background(), token)
	resp, err := client.Get(g.userAPIURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return content, err
}
