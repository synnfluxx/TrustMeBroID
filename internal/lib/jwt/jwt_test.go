package jwt

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
)

func TestJWT_NewToken(t *testing.T) {
	user := models.User{
		ID:    1,
		Email: gofakeit.Email(),
	}
	app := models.App{
		ID:     1,
		Secret: "secret",
	}
	duration := 10 * time.Minute

	str, err := NewToken(user, app, duration)
	assert.NoError(t, err)
	assert.NotEmpty(t, str)
}
