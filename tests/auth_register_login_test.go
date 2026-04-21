package tests

import (
	"log"
	"strconv"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synnfluxx/TrustMeBroID/tests/suite"
	ssov1 "gitlab.com/synnfluxx/protos/sso/gen"
)

const (
	emptyAppID     = 0
	passDefaultLen = 10
	deltaSeconds   = 10
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)
	godotenv.Load()

	email := gofakeit.Email()
	username := gofakeit.Username()
	pw := fakePassword()

	resp, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Username: username,
		Password: pw,
		AppId:    st.AppID,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetUserId())

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{
		Identifier: &ssov1.LoginRequest_Email{
			Email: email,
		},
		Password: pw,
		AppId:    st.AppID,
	})

	loginTime := time.Now()

	require.NoError(t, err)
	assert.NotEmpty(t, respLogin.GetAccessToken())
	assert.NotEmpty(t, respLogin.GetRefreshToken())

	refreshToken := respLogin.GetRefreshToken()
	refreshTokenParsed, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(st.AppSecret), nil
	})
	require.NoError(t, err)

	refreshClaims, ok := refreshTokenParsed.Claims.(jwt.RegisteredClaims)
	require.True(t, ok)

	uid, err := strconv.Atoi(refreshClaims.Subject)
	require.NoError(t, err)

	assert.Equal(t, resp.GetUserId(), int64(uid))
	assert.Equal(t, st.AppID, refreshClaims.Issuer)

	assert.InDelta(t, loginTime.Add(st.Cfg.AccessTokenTTL).Unix(), refreshClaims.ExpiresAt.Unix(), deltaSeconds)

	token := respLogin.GetAccessToken()
	tokenParsed, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(st.AppSecret), nil
	})
	require.NoError(t, err)

	claims, ok := tokenParsed.Claims.(jwt.RegisteredClaims)
	require.True(t, ok)

	uid, err = strconv.Atoi(claims.Subject)
	require.NoError(t, err)

	assert.Equal(t, resp.GetUserId(), int64(uid))
	assert.Equal(t, st.AppID, claims.Issuer)

	assert.InDelta(t, loginTime.Add(st.Cfg.AccessTokenTTL).Unix(), claims.ExpiresAt.Unix(), deltaSeconds)
}

func TestRegisterLogin_Login_DuplicateRegistration(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	username := gofakeit.Username()
	pw := fakePassword()
	log.Printf("%s %s", email, pw)

	resp, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Username: username,
		Password: pw,
		AppId:    st.AppID,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetUserId())

	_, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{
		Email:    email,
		Username: username,
		Password: pw,
		AppId:    st.AppID,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func fakePassword() string {
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}
