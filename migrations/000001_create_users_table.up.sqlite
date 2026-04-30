-- migrations/1_init.up.sql

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

    UNIQUE(email, app_id),
    UNIQUE(username, app_id),

    CONSTRAINT fk_app
        FOREIGN KEY (app_id)
        REFERENCES apps (id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_email ON users (app_id, email);
