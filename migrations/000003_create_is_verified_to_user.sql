-- +goose Up
ALTER TABLE users
    ADD COLUMN is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN verify_token TEXT UNIQUE;

-- +goose Down
ALTER TABLE users
    DROP COLUMN is_verified,
    DROP COLUMN verify_token;