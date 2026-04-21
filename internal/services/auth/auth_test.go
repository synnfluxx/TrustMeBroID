package auth

import (
	"context"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	"github.com/synnfluxx/TrustMeBroID/internal/lib/logger/handlers/discardHandler"
	"golang.org/x/crypto/bcrypt"
)

const (
	AccessTokenTTL  = 3 * time.Minute
	RefreshTokenTTL = 168 * time.Hour
)

func TestAuth_RegisterNewUser_Success(t *testing.T) {
	t.Parallel()
	log := discardHandler.NewDiscardLogger()
	storage := &mockStorage{}
	redis := &mockRedisStorage{}

	storage.On("Emails",
		mock.Anything,
	).Return([]string{}, nil)
	storage.On("Usernames",
		mock.Anything,
	).Return([]string{}, nil)

	authService, err := New(log, storage, storage, storage, storage, storage, redis, RefreshTokenTTL, AccessTokenTTL)
	require.NoError(t, err)

	app := models.App{
		Name:   gofakeit.Name(),
		Secret: gofakeit.Password(true, true, true, true, false, 16),
		ID:     1,
	}

	var (
		email      = gofakeit.Email()
		pw         = gofakeit.Password(true, true, true, false, false, 32)
		appID      = int64(1)
		expectedID = int64(0)
		username   = gofakeit.Username()
	)

	storage.On("SaveUser",
		mock.Anything,
		email,
		username,
		mock.MatchedBy(func(passHash []byte) bool {
			err := bcrypt.CompareHashAndPassword(passHash, []byte(pw))
			return err == nil
		}),
		appID,
	).Return(expectedID, nil)

	storage.On("App", mock.Anything, appID).Return(app, nil)

	uid, err := authService.RegisterNewUser(context.Background(), email, username, pw, appID)
	assert.NoError(t, err)
	assert.Equal(t, expectedID, uid)
	storage.AssertExpectations(t)
}

func TestAuth_RegisterNewApp_Success(t *testing.T) {
	t.Parallel()
	log := discardHandler.NewDiscardLogger()
	storage := &mockStorage{}
	redis := &mockRedisStorage{}

	storage.On("Emails",
		mock.Anything,
	).Return([]string{}, nil)
	storage.On("Usernames",
		mock.Anything,
	).Return([]string{}, nil)

	authService, err := New(log, storage, storage, storage, storage, storage, redis, RefreshTokenTTL, AccessTokenTTL)
	require.NoError(t, err)

	var (
		appName    = gofakeit.Name()
		expectedID = int64(0)
	)

	storage.On("RegisterApp",
		mock.Anything,
		appName,
		mock.Anything,
	).Return(expectedID, nil)

	aid, secret, err := authService.RegisterApp(context.Background(), appName)
	assert.NoError(t, err)
	assert.Equal(t, expectedID, aid)
	assert.NotNil(t, secret)
	storage.AssertExpectations(t)
}
