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

func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["uid"] = user.ID
	claims["email"] = user.Email
	claims["username"] = user.Username
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = app.ID

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
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
		return "", "", nil
	}

	accessToken, err = NewAccessToken(userID, appID, accessDuration, appSecret)
	if err != nil {
		return "", "", nil
	}

	return accessToken, refreshToken, err
}
