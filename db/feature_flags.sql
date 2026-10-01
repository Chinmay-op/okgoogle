CREATE TABLE IF NOT EXISTS feature_flags (
  feature_key VARCHAR(64) PRIMARY KEY,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  updated_by VARCHAR(100) DEFAULT NULL,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

INSERT INTO feature_flags (feature_key, enabled)
VALUES
  ('room_booking', TRUE),
  ('student_profile_edit', TRUE)
ON DUPLICATE KEY UPDATE feature_key = VALUES(feature_key);
