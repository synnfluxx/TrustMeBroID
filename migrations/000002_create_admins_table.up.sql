CREATE TABLE IF NOT EXISTS admins (
    id    SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    username TEXT NOT NULL,
    app_id INTEGER NOT NULL,
    FOREIGN KEY (email) REFERENCES users(email) ON UPDATE CASCADE ON DELETE CASCADE,

    UNIQUE(email, app_id),
    UNIQUE(username, app_id)
);
