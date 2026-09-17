-- +goose Up
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_app_id_key;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_app_id_key;

CREATE UNIQUE INDEX IF NOT EXISTS users_email_app_id_active_key
    ON users (email, app_id) WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS users_username_app_id_active_key
    ON users (username, app_id) WHERE deleted_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS users_email_app_id_active_key;
DROP INDEX IF EXISTS users_username_app_id_active_key;

ALTER TABLE users ADD CONSTRAINT users_email_app_id_key UNIQUE (email, app_id);
ALTER TABLE users ADD CONSTRAINT users_username_app_id_key UNIQUE (username, app_id);