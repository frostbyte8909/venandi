-- Migration 0004: dynamic scoring — drop static score column, add computed view.
-- SQLite does not support DROP COLUMN portably; recreate teams table without score column.
PRAGMA foreign_keys = OFF;

CREATE TABLE teams_new (
    id            TEXT    PRIMARY KEY,
    name          TEXT    NOT NULL UNIQUE,
    join_code     TEXT    NOT NULL UNIQUE CHECK(length(join_code) = 6),
    password_hash TEXT    NOT NULL,
    canary_triggered INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL
);

INSERT INTO teams_new (id, name, join_code, password_hash, canary_triggered, created_at)
    SELECT id, name, join_code, password_hash, canary_triggered, created_at FROM teams;

DROP TABLE teams;
ALTER TABLE teams_new RENAME TO teams;

-- Recreate indexes that reference the new table.
CREATE INDEX IF NOT EXISTS idx_users_team_id  ON users(team_id);
CREATE INDEX IF NOT EXISTS idx_solves_team_id ON solves(team_id);

PRAGMA foreign_keys = ON;

-- points_at_solve stores the decayed point value at the moment of the solve.
ALTER TABLE solves ADD COLUMN points_at_solve INTEGER NOT NULL DEFAULT 0;

-- team_scores_view computes total score lazily at read time via SUM of stored decayed points.
CREATE VIEW IF NOT EXISTS team_scores_view AS
    SELECT team_id, SUM(points_at_solve) AS total_score
    FROM solves
    GROUP BY team_id;

-- skibidi toilet
