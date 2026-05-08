CREATE TABLE IF NOT EXISTS admins (
    id    SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    username TEXT NOT NULL,
    app_id INTEGER NOT NULL,
    FOREIGN KEY (email, app_id) REFERENCES users(email, app_id) ON UPDATE CASCADE ON DELETE CASCADE,

    UNIQUE(email, app_id),
    UNIQUE(username, app_id)
);
