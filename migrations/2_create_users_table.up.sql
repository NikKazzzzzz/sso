CREATE TABLE IF NOT EXISTS users
(
    id        SERIAL PRIMARY KEY,
    email     TEXT NOT NULL UNIQUE,
    pass_hash BYTEA NOT NULL,
    is_admin  BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_email ON users (email);
