CREATE TABLE IF NOT EXISTS apps
(
    id        SERIAL PRIMARY KEY,
    name      TEXT NOT NULL,
    secret    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_app_name ON apps (name);
