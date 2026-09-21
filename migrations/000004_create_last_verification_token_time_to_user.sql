-- +goose Up
ALTER TABLE users
    ADD COLUMN last_token_generated_time TIMESTAMP NULL;

-- +goose Down
ALTER TABLE users
    DROP COLUMN last_token_generated_time;