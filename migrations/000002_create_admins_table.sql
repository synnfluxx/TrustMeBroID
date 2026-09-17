-- +goose Up
CREATE TABLE IF NOT EXISTS admins (
    id      SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    app_id  INTEGER NOT NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,

    UNIQUE(user_id, app_id)
);

-- +goose Down
DROP TABLE admins;