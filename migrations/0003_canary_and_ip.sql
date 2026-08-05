-- Migration 0003: canary flag tracking and ip recording on solves
ALTER TABLE teams ADD COLUMN canary_triggered INTEGER NOT NULL DEFAULT 0;
ALTER TABLE solves ADD COLUMN ip_address TEXT;
