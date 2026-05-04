package redisStorage

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/synnfluxx/TrustMeBroID/internal/domain/models"
	"github.com/synnfluxx/TrustMeBroID/internal/storage"
)

type Storage struct {
	rdb *redis.Client
}

func NewRedis(host string, timeout time.Duration, retries int) (*Storage, error) {
	client := redis.NewClient(&redis.Options{
		Addr:        host,
		Password:    os.Getenv("REDIS_PW"),
		DB:          0,
		DialTimeout: timeout,
		MaxRetries:  retries,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &Storage{
		rdb: client,
	}, nil
}

func (s *Storage) GetRefreshTokenFields(ctx context.Context, token string) (*models.RefreshTokenFields, error) {
	const op = "storage.Redis.RefreshToken"

	refreshTokenFields := &models.RefreshTokenFields{}
	fields := s.rdb.HGetAll(ctx, token)
	if err := fields.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if len(fields.Val()) == 0 {
		return nil, fmt.Errorf("%s: %w", op, storage.ErrTokenNotFound)
	}

	err := fields.Scan(refreshTokenFields)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return refreshTokenFields, nil
}

func (s *Storage) SaveRefreshToken(ctx context.Context, token string, userID int64, appID int64, ttl time.Duration) error {
	const op = "storage.Redis.SaveRefreshToken"

	_, err := saveRefreshTokenScript.Run(ctx, s.rdb, []string{token}, userID, appID, ttl.Seconds()).Result()

	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) SetNewRefreshToken(ctx context.Context, oldToken string, newToken string, ttl time.Duration) error {
	const op = "storage.Redis.SetNewRefreshtoken"

	res, err := setNewTokenScript.Run(ctx, s.rdb, []string{oldToken, newToken}, int(ttl.Seconds())).Result()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if res.(int64) == 0 {
		return fmt.Errorf("%s: %w", op, storage.ErrTokenNotFound)
	}

	return nil
}

func (s *Storage) Logout(ctx context.Context, token string) error {
	const op = "storage.Redis.Logout"

	err := s.rdb.Del(ctx, token)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) Close() error {
	return s.rdb.Close()
}
