-- Migration 0001: Baseline schema
-- All UUIDs are stored as TEXT (canonical hyphenated form).
-- All timestamps are stored as ISO-8601 TEXT (UTC).

CREATE TABLE IF NOT EXISTS users (
    id            TEXT    PRIMARY KEY,
    team_id       TEXT    REFERENCES teams(id) ON DELETE SET NULL,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'player' CHECK(role IN ('player', 'admin')),
    created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS teams (
    id            TEXT    PRIMARY KEY,
    name          TEXT    NOT NULL UNIQUE,
    join_code     TEXT    NOT NULL UNIQUE CHECK(length(join_code) = 6),
    password_hash TEXT    NOT NULL,
    score         INTEGER NOT NULL DEFAULT 0 CHECK(score >= 0),
    created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS solves (
    team_id   TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    level_id  TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    PRIMARY KEY (team_id, level_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id   TEXT,
    user_id   TEXT,
    action    TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

-- Indexes for hot read paths
CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_team_id  ON users(team_id);
CREATE INDEX IF NOT EXISTS idx_solves_team_id ON solves(team_id);
CREATE INDEX IF NOT EXISTS idx_teams_score    ON teams(score DESC);
