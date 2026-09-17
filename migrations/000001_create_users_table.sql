-- +goose Up

CREATE TABLE IF NOT EXISTS apps
(
    id     SERIAL PRIMARY KEY,
    name   TEXT NOT NULL UNIQUE,
    secret TEXT NOT NULL UNIQUE,
    redirect_uri TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS users
(
    id           SERIAL PRIMARY KEY,
    email        TEXT    NOT NULL,
    username     TEXT    NOT NULL,
    pass_hash    BYTEA,
    app_id       INTEGER NOT NULL,
    deleted_at   TIMESTAMP,

    CONSTRAINT fk_app
        FOREIGN KEY (app_id)
        REFERENCES apps (id)
        ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_app_id_active_key
    ON users (email, app_id) WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS users_username_app_id_active_key
    ON users (username, app_id) WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_email ON users (app_id, email);

-- +goose Down
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS apps;