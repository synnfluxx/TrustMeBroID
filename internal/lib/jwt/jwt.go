package jwt

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
)

type JWTRepository interface {
	SaveRefreshToken(ctx context.Context, token string, userID int64, appID int64, ttl time.Duration) error
	SetNewRefreshToken(ctx context.Context, oldToken string, newToken string, ttl time.Duration) error
	GetRefreshTokenFields(ctx context.Context, token string) (*models.RefreshTokenFields, error)
}

type OAuthCustomClaims struct {
	AvatarPath string `json:"avatar_path"`
	jwt.RegisteredClaims
}

func NewAccessToken(userID, appID int64, accessDuration time.Duration, appSecret string) (accessToken string, err error) {
	claims := &jwt.RegisteredClaims{
		Issuer:    fmt.Sprint(appID),
		Subject:   fmt.Sprint(userID),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessDuration)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err = token.SignedString([]byte(appSecret))
	if err != nil {
		return accessToken, err
	}

	return accessToken, err
}

func NewOAuthAccessToken(userID, appID int64, accessDuration time.Duration, appSecret, avatarPath string) (accessToken string, err error) {
	claims := &OAuthCustomClaims{
		AvatarPath: avatarPath,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    fmt.Sprint(appID),
			Subject:   fmt.Sprint(userID),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessDuration)),	
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err = token.SignedString([]byte(appSecret))
	if err != nil {
		return accessToken, err
	}

	return accessToken, err
}

func NewRefreshToken(userID, appID int64, refreshDuration time.Duration, appSecret string) (refreshToken string, err error) {
	claims := &jwt.RegisteredClaims{
		Issuer:    fmt.Sprint(appID),
		Subject:   fmt.Sprint(userID),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshDuration)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	refreshToken, err = token.SignedString([]byte(appSecret))
	if err != nil {
		return refreshToken, err
	}

	return refreshToken, err
}

func NewTokens(userID, appID int64, appSecret string, refreshDuration, accessDuration time.Duration) (accessToken, refreshToken string, err error) {
	refreshToken, err = NewRefreshToken(userID, appID, refreshDuration, appSecret)
	if err != nil {
		return "", "", err
	}

	accessToken, err = NewAccessToken(userID, appID, accessDuration, appSecret)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, err
}

func NewOAuthTokens(userID, appID int64, appSecret, avatarPath string, refreshDuration, accessDuration time.Duration) (accessToken, refreshToken string, err error) {
	refreshToken, err = NewRefreshToken(userID, appID, refreshDuration, appSecret)
	if err != nil {
		return "", "", err
	}

	accessToken, err = NewOAuthAccessToken(userID, appID, accessDuration, appSecret, avatarPath)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, err
}
