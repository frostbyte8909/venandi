-- Migration 0002: Add token_version for persistent JWT invalidation
ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1;
