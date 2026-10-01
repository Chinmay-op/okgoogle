-- Smart Breakfast Management System v2 Schema
-- Drop old tables if they exist (assuming fresh start for v2 as per plan)
-- DROP TABLE IF EXISTS food_selections;
-- DROP TABLE IF EXISTS food_options;

CREATE TABLE IF NOT EXISTS weekly_breakfast_menu (
  id INT AUTO_INCREMENT PRIMARY KEY,
  weekday VARCHAR(20) NOT NULL UNIQUE,
  food_name VARCHAR(100) NOT NULL,
  drink VARCHAR(50),
  description VARCHAR(255),
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS optional_breakfast (
  id INT AUTO_INCREMENT PRIMARY KEY,
  breakfast_date DATE NOT NULL,
  food_name VARCHAR(100) NOT NULL,
  description VARCHAR(255),
  status ENUM('Active', 'Inactive') DEFAULT 'Active',
  created_by VARCHAR(100) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_optional_breakfast_date (breakfast_date),
  INDEX idx_optional_breakfast_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS breakfast_selection (
  id INT AUTO_INCREMENT PRIMARY KEY,
  student_uid VARCHAR(50) NOT NULL,
  student_name VARCHAR(100) NOT NULL,
  room_number VARCHAR(50),
  selected_food VARCHAR(100) NOT NULL,
  selection_type ENUM('DEFAULT', 'OPTIONAL') NOT NULL,
  selection_date DATE NOT NULL,
  selected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY unique_daily_selection_v2 (student_uid, selection_date),
  INDEX idx_breakfast_selection_date (selection_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Initial Seed for weekly_breakfast_menu
INSERT IGNORE INTO weekly_breakfast_menu (weekday, food_name, drink) VALUES
  ('Monday', 'Puri + Moong', 'Tea'),
  ('Tuesday', 'Poha + Chana', 'Coffee'),
  ('Wednesday', 'Upma + Matar', 'Tea'),
  ('Thursday', 'Puri + Aloo', 'Tea'),
  ('Friday', 'Idli + Sambhar', 'Tea'),
  ('Saturday', 'Poha + Chana', 'Coffee'),
  ('Sunday', 'Pav Bhaji', 'Tea');
