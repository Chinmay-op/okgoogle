-- Recreate complaints table with image_path (and optional phone_number).
-- Run in MySQL: source db/complaints_table.sql
-- Or: mysql -u user -p your_db < gatepass/db/complaints_table.sql

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS complaints;

CREATE TABLE complaints (
  id INT NOT NULL AUTO_INCREMENT,
  student_uid VARCHAR(50) NOT NULL,
  description TEXT NOT NULL,
  category VARCHAR(100) DEFAULT NULL,
  image_path VARCHAR(500) DEFAULT NULL,
  phone_number VARCHAR(20) DEFAULT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  status ENUM('pending_approval', 'approved', 'resolved', 'denied') DEFAULT 'pending_approval',
  PRIMARY KEY (id),
  CONSTRAINT fk_student_uid FOREIGN KEY (student_uid) REFERENCES studentdetails(uid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 1;

DESCRIBE complaints;
