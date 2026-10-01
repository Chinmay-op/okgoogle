-- Full bootstrap schema for the TNPS gate pass system
-- Derived from script.md, db/*.sql, and the live application queries in app.js.
-- Adjust the database name below if needed before running.

CREATE DATABASE IF NOT EXISTS `gatepass_db`
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
USE `gatepass_db`;

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS `student_notifications`;
DROP TABLE IF EXISTS `sick_leave_requests`;
DROP TABLE IF EXISTS `sick_leave_logs`;
DROP TABLE IF EXISTS `pass_requests`;
DROP TABLE IF EXISTS `timebound`;
DROP TABLE IF EXISTS `log_details1`;
DROP TABLE IF EXISTS `log_detail`;
DROP TABLE IF EXISTS `complaints`;
DROP TABLE IF EXISTS `password_reset_tokens`;
DROP TABLE IF EXISTS `announcements`;
DROP TABLE IF EXISTS `feature_flags`;
DROP TABLE IF EXISTS `room_bookings`;
DROP TABLE IF EXISTS `payments`;
DROP TABLE IF EXISTS `bookings`;
DROP TABLE IF EXISTS `rooms`;
DROP TABLE IF EXISTS `studentdetails2`;
DROP TABLE IF EXISTS `studentdetails`;
DROP TABLE IF EXISTS `admin`;

CREATE TABLE `admin` (
  `adminid` INT NOT NULL AUTO_INCREMENT,
  `uid` VARCHAR(50) NOT NULL,
  `email` VARCHAR(255) DEFAULT NULL,
  `name` VARCHAR(100) DEFAULT NULL,
  `password` VARCHAR(255) NOT NULL,
  `category` VARCHAR(50) NOT NULL,
  `Hostel` VARCHAR(50) DEFAULT NULL,
  PRIMARY KEY (`adminid`),
  UNIQUE KEY `uq_admin_uid` (`uid`),
  KEY `idx_admin_email` (`email`),
  KEY `idx_admin_category` (`category`),
  KEY `idx_admin_hostel` (`Hostel`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `studentdetails` (
  `uid` VARCHAR(50) NOT NULL,
  `sname` VARCHAR(100) DEFAULT NULL,
  `email` VARCHAR(255) DEFAULT NULL,
  `dept` VARCHAR(100) DEFAULT NULL,
  `address` VARCHAR(255) DEFAULT NULL,
  `year` VARCHAR(50) DEFAULT NULL,
  `category` VARCHAR(50) DEFAULT NULL,
  `gender` VARCHAR(20) DEFAULT NULL,
  `mobileno` VARCHAR(20) DEFAULT NULL,
  `dob` DATE DEFAULT NULL,
  `academicyear` VARCHAR(50) DEFAULT NULL,
  `path` VARCHAR(500) DEFAULT NULL,
  `status` VARCHAR(50) DEFAULT NULL,
  `parentname` VARCHAR(100) DEFAULT NULL,
  `parentnumber` VARCHAR(20) DEFAULT NULL,
  `room_no` VARCHAR(50) DEFAULT NULL,
  `bed_no` VARCHAR(20) DEFAULT NULL,
  `mess_type` VARCHAR(20) DEFAULT NULL,
  `block` VARCHAR(50) DEFAULT NULL,
  `other1` VARCHAR(100) DEFAULT NULL,
  `other2` VARCHAR(100) DEFAULT NULL,
  `other3` VARCHAR(100) DEFAULT NULL,
  `password` VARCHAR(255) DEFAULT NULL,
  `password_reset_code` VARCHAR(100) DEFAULT NULL,
  `password_reset_expires` DATETIME DEFAULT NULL,
  PRIMARY KEY (`uid`),
  KEY `idx_student_email` (`email`),
  KEY `idx_student_dept` (`dept`),
  KEY `idx_student_category` (`category`),
  KEY `idx_student_gender` (`gender`),
  KEY `idx_student_status` (`status`),
  KEY `idx_student_room` (`room_no`, `bed_no`, `block`),
  KEY `idx_student_password_reset_code` (`password_reset_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `studentdetails2` (
  `uid` VARCHAR(50) NOT NULL,
  `sname` VARCHAR(100) DEFAULT NULL,
  `email` VARCHAR(255) DEFAULT NULL,
  `dept` VARCHAR(100) DEFAULT NULL,
  `address` VARCHAR(255) DEFAULT NULL,
  `year` VARCHAR(50) DEFAULT NULL,
  `category` VARCHAR(50) DEFAULT NULL,
  `gender` VARCHAR(20) DEFAULT NULL,
  `mobileno` VARCHAR(20) DEFAULT NULL,
  `dob` DATE DEFAULT NULL,
  `academicyear` VARCHAR(50) DEFAULT NULL,
  `path` VARCHAR(500) DEFAULT NULL,
  `status` VARCHAR(50) DEFAULT NULL,
  `parentname` VARCHAR(100) DEFAULT NULL,
  `parentnumber` VARCHAR(20) DEFAULT NULL,
  `room_no` VARCHAR(50) DEFAULT NULL,
  `bed_no` VARCHAR(20) DEFAULT NULL,
  `mess_type` VARCHAR(20) DEFAULT NULL,
  `block` VARCHAR(50) DEFAULT NULL,
  `other1` VARCHAR(100) DEFAULT NULL,
  `other2` VARCHAR(100) DEFAULT NULL,
  `other3` VARCHAR(100) DEFAULT NULL,
  `password` VARCHAR(255) DEFAULT NULL,
  `password_reset_code` VARCHAR(100) DEFAULT NULL,
  `password_reset_expires` DATETIME DEFAULT NULL,
  PRIMARY KEY (`uid`),
  KEY `idx_studentdetails2_email` (`email`),
  KEY `idx_studentdetails2_room` (`room_no`, `bed_no`, `block`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `bookings` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `room_id` INT NOT NULL,
  `student_id` VARCHAR(50) NOT NULL,
  `booking_date` DATE NOT NULL,
  `total_price` DECIMAL(10,2) NOT NULL,
  `status` ENUM('pending','on_hold','confirmed','cancelled') DEFAULT 'on_hold',
  `payment_id` INT DEFAULT NULL,
  `payment_status` ENUM('pending','paid','refunded') DEFAULT 'pending',
  `rejection_reason` TEXT DEFAULT NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_bookings_room_id` (`room_id`),
  KEY `idx_bookings_student_id` (`student_id`),
  KEY `idx_bookings_booking_date` (`booking_date`),
  KEY `idx_bookings_status` (`status`),
  KEY `idx_bookings_payment_status` (`payment_status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `payments` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `booking_id` INT NOT NULL,
  `amount` DECIMAL(10,2) NOT NULL,
  `payment_date` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `transaction_id` VARCHAR(255) DEFAULT NULL,
  `status` VARCHAR(50) DEFAULT 'pending',
  PRIMARY KEY (`id`),
  KEY `idx_payments_booking_id` (`booking_id`),
  KEY `idx_payments_transaction_id` (`transaction_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `room_bookings` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `room_no` VARCHAR(50) NOT NULL,
  `block` VARCHAR(50) NOT NULL,
  `floor` VARCHAR(50) NOT NULL,
  `bed_no` VARCHAR(20) NOT NULL,
  `uid` VARCHAR(50) NOT NULL,
  `booking_status` ENUM('locked','cancelled') DEFAULT 'locked',
  `payment_status` ENUM('pending','confirmed','cancelled') DEFAULT 'pending',
  `advance_amount` DECIMAL(10,2) DEFAULT NULL,
  `transaction_id` VARCHAR(255) DEFAULT NULL,
  `paid_at` DATETIME DEFAULT NULL,
  `agreement_accepted` TINYINT(1) DEFAULT 0,
  `locked_source` ENUM('student','admin') DEFAULT 'student',
  `locked_by` VARCHAR(100) DEFAULT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_room_bookings_uid_status` (`uid`, `booking_status`),
  KEY `idx_room_bookings_payment_status` (`payment_status`),
  KEY `idx_room_bookings_bed_status` (`room_no`, `block`, `floor`, `bed_no`, `booking_status`)
CREATE TABLE `rooms` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) NOT NULL,
  `capacity` INT NOT NULL,
  `price_per_night` DECIMAL(10,2) NOT NULL,
  `description` TEXT DEFAULT NULL,
  `is_available` TINYINT(1) DEFAULT 1,
  `is_permanent` TINYINT(1) DEFAULT 0,
  `block` VARCHAR(50) DEFAULT 'A',
  `floor` VARCHAR(50) DEFAULT 'Ground Floor',
  `room_type` ENUM('Single','Double','Triple') DEFAULT 'Double',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_rooms_name_block_floor` (`name`, `block`, `floor`),
  KEY `idx_rooms_block` (`block`),
  KEY `idx_rooms_floor` (`floor`),
  KEY `idx_rooms_available` (`is_available`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `feature_flags` (
  `feature_key` VARCHAR(64) NOT NULL,
  `enabled` TINYINT(1) NOT NULL DEFAULT 1,
  `updated_by` VARCHAR(100) DEFAULT NULL,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`feature_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `feature_flags` (`feature_key`, `enabled`)
VALUES
  ('room_booking', 1),
  ('student_profile_edit', 1)
ON DUPLICATE KEY UPDATE `feature_key` = VALUES(`feature_key`);

CREATE TABLE `announcements` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `title` VARCHAR(255) NOT NULL,
  `description` TEXT NOT NULL,
  `target_year` ENUM('all','1','2','3','4') DEFAULT 'all',
  `created_by` VARCHAR(100) DEFAULT NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `is_active` TINYINT(1) DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `idx_announcements_active_created` (`is_active`, `created_at`),
  KEY `idx_announcements_target_year` (`target_year`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `password_reset_tokens` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `user_type` ENUM('student','admin') NOT NULL,
  `email` VARCHAR(255) NOT NULL,
  `otp_hash` VARCHAR(255) NOT NULL,
  `expires_at` DATETIME NOT NULL,
  `attempts` INT DEFAULT 0,
  `used` TINYINT(1) DEFAULT 0,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_prt_lookup` (`email`, `user_type`, `used`, `expires_at`),
  KEY `idx_prt_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `complaints` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `student_uid` VARCHAR(50) DEFAULT NULL,
  `admin_name` VARCHAR(100) DEFAULT NULL,
  `description` TEXT NOT NULL,
  `category` VARCHAR(100) DEFAULT NULL,
  `image_path` VARCHAR(500) DEFAULT NULL,
  `phone_number` VARCHAR(20) DEFAULT NULL,
  `timestamp` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `status` ENUM('pending_approval','approved','resolved','denied') DEFAULT 'pending_approval',
  PRIMARY KEY (`id`),
  KEY `idx_complaints_student_uid` (`student_uid`),
  KEY `idx_complaints_status` (`status`),
  KEY `idx_complaints_timestamp` (`timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `log_detail` (
  `logid` INT NOT NULL AUTO_INCREMENT,
  `uid` VARCHAR(50) DEFAULT NULL,
  `indatetime` DATETIME DEFAULT NULL,
  `GuardName` VARCHAR(100) DEFAULT NULL,
  PRIMARY KEY (`logid`),
  KEY `idx_log_detail_uid` (`uid`),
  KEY `idx_log_detail_indatetime` (`indatetime`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `log_details1` (
  `logid` INT NOT NULL AUTO_INCREMENT,
  `uid` VARCHAR(50) DEFAULT NULL,
  `indatetime` DATETIME DEFAULT NULL,
  `outdatetime` DATETIME DEFAULT NULL,
  `approvaldt` DATETIME DEFAULT NULL,
  `status` VARCHAR(45) DEFAULT NULL,
  `hostelintime` DATETIME DEFAULT NULL,
  `passtype` VARCHAR(45) DEFAULT NULL,
  `hosteloutauth` VARCHAR(100) DEFAULT NULL,
  PRIMARY KEY (`logid`),
  KEY `idx_log_details1_uid` (`uid`),
  KEY `idx_log_details1_status` (`status`),
  KEY `idx_log_details1_approvaldt` (`approvaldt`),
  KEY `idx_log_details1_passtype` (`passtype`),
  KEY `idx_log_details1_hostelintime` (`hostelintime`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `timebound` (
  `tbid` INT NOT NULL AUTO_INCREMENT,
  `days` VARCHAR(60) DEFAULT NULL,
  `start` VARCHAR(60) DEFAULT NULL,
  `end` VARCHAR(60) DEFAULT NULL,
  `start1` VARCHAR(60) DEFAULT NULL,
  `end1` VARCHAR(60) DEFAULT NULL,
  `dayno` VARCHAR(60) DEFAULT NULL,
  `hostel` VARCHAR(60) DEFAULT NULL,
  PRIMARY KEY (`tbid`),
  KEY `idx_timebound_hostel_days` (`hostel`, `days`),
  KEY `idx_timebound_dayno` (`dayno`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `pass_requests` (
  `requestid` INT NOT NULL AUTO_INCREMENT,
  `uid` VARCHAR(50) NOT NULL,
  `student_uid` VARCHAR(50) DEFAULT NULL,
  `passtype` VARCHAR(45) NOT NULL,
  `expected_out` DATETIME DEFAULT NULL,
  `expected_return` DATETIME DEFAULT NULL,
  `reason` TEXT DEFAULT NULL,
  `emergency_contact` VARCHAR(20) DEFAULT NULL,
  `status` ENUM('pending','approved','rejected','cancelled') DEFAULT 'pending',
  `approved_by` VARCHAR(100) DEFAULT NULL,
  `approved_at` DATETIME DEFAULT NULL,
  `rejection_reason` TEXT DEFAULT NULL,
  `request_kind` VARCHAR(20) NOT NULL DEFAULT 'new',
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`requestid`),
  KEY `idx_pass_requests_uid` (`uid`),
  KEY `idx_pass_requests_student_uid` (`student_uid`),
  KEY `idx_pass_requests_status` (`status`),
  KEY `idx_pass_requests_kind` (`request_kind`),
  KEY `idx_pass_requests_created_at` (`created_at`),
  KEY `idx_pass_requests_approved_at` (`approved_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `sick_leave_logs` (
  `logid` INT NOT NULL AUTO_INCREMENT,
  `uid` VARCHAR(50) NOT NULL,
  `illness` VARCHAR(100) NOT NULL,
  `logdate` DATE NOT NULL,
  `logtime` VARCHAR(20) DEFAULT NULL,
  `recorded_by` VARCHAR(100) DEFAULT NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`logid`),
  KEY `idx_sick_leave_logs_uid` (`uid`),
  KEY `idx_sick_leave_logs_logdate` (`logdate`),
  KEY `idx_sick_leave_logs_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `sick_leave_requests` (
  `requestid` INT NOT NULL AUTO_INCREMENT,
  `uid` VARCHAR(50) NOT NULL,
  `illness` VARCHAR(100) NOT NULL,
  `details` TEXT DEFAULT NULL,
  `status` ENUM('pending','approved','rejected','cancelled') DEFAULT 'pending',
  `approved_by` VARCHAR(100) DEFAULT NULL,
  `approved_at` DATETIME DEFAULT NULL,
  `rejection_reason` TEXT DEFAULT NULL,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`requestid`),
  KEY `idx_sick_leave_requests_uid` (`uid`),
  KEY `idx_sick_leave_requests_status` (`status`),
  KEY `idx_sick_leave_requests_created_at` (`created_at`),
  KEY `idx_sick_leave_requests_approved_at` (`approved_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `student_notifications` (
  `notifid` INT NOT NULL AUTO_INCREMENT,
  `uid` VARCHAR(50) NOT NULL,
  `type` VARCHAR(50) DEFAULT 'info',
  `title` VARCHAR(200) NOT NULL,
  `message` TEXT DEFAULT NULL,
  `read` TINYINT(1) DEFAULT 0,
  `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`notifid`),
  KEY `idx_student_notifications_uid` (`uid`),
  KEY `idx_student_notifications_read` (`read`),
  KEY `idx_student_notifications_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;

-- Optional seed row examples:
-- INSERT INTO `feature_flags` (`feature_key`, `enabled`) VALUES ('room_booking', 1), ('student_profile_edit', 1);
