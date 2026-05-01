package tests

import (
	"strconv"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synnfluxx/TrustMeBroID/tests/suite"
	ssov1 "gitlab.com/synnfluxx/protos/sso/gen"
)

const (
	passDefaultLen = 10
	deltaSeconds   = 10
)

func TestRegisterLogin_Login_HappyPath(t *testing.T) {
	ctx, st := suite.New(t)

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
	refreshClaims := &jwt.RegisteredClaims{}
	refreshTokenParsed, err := jwt.ParseWithClaims(refreshToken, refreshClaims, func(token *jwt.Token) (interface{}, error) {
		return []byte(st.AppSecret), nil
	})
	require.NoError(t, err)
	require.True(t, refreshTokenParsed.Valid)

	uid, err := jwtSubjectToInt64(refreshClaims.Subject)
	require.NoError(t, err)

	assert.Equal(t, resp.GetUserId(), uid)
	assert.Equal(t, int64ToString(st.AppID), refreshClaims.Issuer)

	assert.InDelta(t, loginTime.Add(st.Cfg.RefreshTokenTTL).Unix(), refreshClaims.ExpiresAt.Unix(), deltaSeconds)

	token := respLogin.GetAccessToken()
	claims := &jwt.RegisteredClaims{}
	tokenParsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(st.AppSecret), nil
	})
	require.NoError(t, err)
	require.True(t, tokenParsed.Valid)

	uid, err = jwtSubjectToInt64(claims.Subject)
	require.NoError(t, err)

	assert.Equal(t, resp.GetUserId(), uid)
	assert.Equal(t, int64ToString(st.AppID), claims.Issuer)

	assert.InDelta(t, loginTime.Add(st.Cfg.AccessTokenTTL).Unix(), claims.ExpiresAt.Unix(), deltaSeconds)
}

func TestRegisterLogin_Login_DuplicateRegistration(t *testing.T) {
	ctx, st := suite.New(t)

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

func jwtSubjectToInt64(subject string) (int64, error) {
	return strconv.ParseInt(subject, 10, 64)
}

func int64ToString(v int64) string {
	return strconv.FormatInt(v, 10)
}
