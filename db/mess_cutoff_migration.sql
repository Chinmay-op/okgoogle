-- Mess Cutoff Time Migration
-- Adds value_int column to feature_flags to support integer settings
-- Run this once against your database

-- Add value_int column (ignore error if already exists)
ALTER TABLE feature_flags ADD COLUMN value_int INT DEFAULT NULL;

-- Seed default cutoff hours for mess selection window
-- Open: 9 AM (hour 9), Close: 4 PM (hour 16)
INSERT INTO feature_flags (feature_key, enabled, value_int)
VALUES
    ('mess_open_hour',  1, 9),
    ('mess_close_hour', 1, 16)
ON DUPLICATE KEY UPDATE
    value_int = VALUES(value_int);
