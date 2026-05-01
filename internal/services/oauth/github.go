package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/oauth2"
)

type GithubOAuth struct {
	config     *oauth2.Config
	userAPIURL string
}

type GithubUser struct {
	Email    string `json:"email"`
	Username string `json:"login"`
	//TODO: avatar path
}

type GithubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
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

func (g *GithubOAuth) Callback(ctx context.Context, code string) (*OAuthUserDetails, error) {
	const op = "oauth.GitHubOAuthCallback"
	usr, err := g.getUserDataFromGitHub(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &OAuthUserDetails{
		Email: usr.Email,
		Username: usr.Username,
	}, nil
}

func (g *GithubOAuth) getUserDataFromGitHub(ctx context.Context, code string) (*GithubUser, error) {
	token, err := g.config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	client := g.config.Client(ctx, token)
	resp, err := client.Get(g.userAPIURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	usr := &GithubUser{}
	if err := json.NewDecoder(resp.Body).Decode(&usr); err != nil {
		return nil, err
	}

	if usr.Email == "" {
		email, err := g.getUserEmail(ctx, client)
		if err != nil {
			return nil, err
		}
		usr.Email = email
	}

	return usr, err
}

func (g *GithubOAuth) getUserEmail(ctx context.Context, client *http.Client) (string, error){
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api user/emails returned status %d", resp.StatusCode)
	}

	var emails []GithubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	if len(emails) > 0 {
		return emails[0].Email, nil
	}

	return "", fmt.Errorf("no email found")
}
