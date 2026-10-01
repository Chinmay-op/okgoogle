-- Combined schema for Tnps-Gate-Pass
-- Generated from SQL dumps in this repository's DB/ folder
-- Edit `CREATE DATABASE` name below as needed before running in MySQL Workbench

CREATE DATABASE IF NOT EXISTS `gatepass_db` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `gatepass_db`;

SET FOREIGN_KEY_CHECKS=0;

-- Table: admin
DROP TABLE IF EXISTS `admin`;
CREATE TABLE `admin` (
  `adminid` int NOT NULL AUTO_INCREMENT,
  `uid` varchar(45) NOT NULL,
  `name` varchar(45) DEFAULT NULL,
  `password` varchar(200) NOT NULL,
  `category` varchar(45) NOT NULL,
  `Hostel` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`adminid`),
  UNIQUE KEY `adminid_UNIQUE` (`adminid`),
  UNIQUE KEY `uid_UNIQUE` (`uid`)
) ENGINE=InnoDB AUTO_INCREMENT=32 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Table: studentdetails
DROP TABLE IF EXISTS `studentdetails`;
CREATE TABLE `studentdetails` (
  `uid` varchar(50) NOT NULL,
  `sname` varchar(50) DEFAULT NULL,
  `email` varchar(50) DEFAULT NULL,
  `dept` varchar(50) DEFAULT NULL,
  `address` varchar(200) DEFAULT NULL,
  `year` varchar(50) DEFAULT NULL,
  `category` varchar(50) DEFAULT NULL,
  `gender` varchar(50) DEFAULT NULL,
  `mobileno` varchar(50) DEFAULT NULL,
  `dob` varchar(50) DEFAULT NULL,
  `academicyear` varchar(50) DEFAULT NULL,
  `path` varchar(500) DEFAULT NULL,
  `status` varchar(50) DEFAULT NULL,
  `parentname` varchar(70) DEFAULT NULL,
  `parentnumber` varchar(45) DEFAULT NULL,
  `other1` varchar(45) DEFAULT NULL,
  `other2` varchar(50) DEFAULT NULL,
  `other3` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Table: studentdetails2 (duplicate/alternate student table)
DROP TABLE IF EXISTS `studentdetails2`;
CREATE TABLE `studentdetails2` (
  `uid` varchar(50) NOT NULL,
  `sname` varchar(50) DEFAULT NULL,
  `email` varchar(50) DEFAULT NULL,
  `dept` varchar(50) DEFAULT NULL,
  `address` varchar(200) DEFAULT NULL,
  `year` varchar(50) DEFAULT NULL,
  `category` varchar(50) DEFAULT NULL,
  `gender` varchar(50) DEFAULT NULL,
  `mobileno` varchar(50) DEFAULT NULL,
  `dob` varchar(50) DEFAULT NULL,
  `academicyear` varchar(50) DEFAULT NULL,
  `path` varchar(500) DEFAULT NULL,
  `status` varchar(50) DEFAULT NULL,
  `parentname` varchar(70) DEFAULT NULL,
  `parentnumber` varchar(45) DEFAULT NULL,
  `other1` varchar(45) DEFAULT NULL,
  `other2` varchar(50) DEFAULT NULL,
  `other3` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`uid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Table: log_detail (simple log table)
DROP TABLE IF EXISTS `log_detail`;
CREATE TABLE `log_detail` (
  `logid` int NOT NULL AUTO_INCREMENT,
  `uid` varchar(45) DEFAULT NULL,
  `indatetime` varchar(45) DEFAULT NULL,
  `GuardName` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`logid`)
) ENGINE=InnoDB AUTO_INCREMENT=59653 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Table: log_details1 (detailed logs with outdatetime and status)
DROP TABLE IF EXISTS `log_details1`;
CREATE TABLE `log_details1` (
  `logid` int NOT NULL AUTO_INCREMENT,
  `uid` varchar(45) DEFAULT NULL,
  `indatetime` varchar(45) DEFAULT NULL,
  `outdatetime` varchar(30) DEFAULT NULL,
  `approvaldt` varchar(45) DEFAULT NULL,
  `status` varchar(45) DEFAULT NULL,
  `hostelintime` varchar(45) DEFAULT NULL,
  `passtype` varchar(45) DEFAULT NULL,
  `hosteloutauth` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`logid`)
) ENGINE=InnoDB AUTO_INCREMENT=34933 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Table: timebound
DROP TABLE IF EXISTS `timebound`;
CREATE TABLE `timebound` (
  `tbid` int NOT NULL AUTO_INCREMENT,
  `days` varchar(60) DEFAULT NULL,
  `start` varchar(60) DEFAULT NULL,
  `end` varchar(60) DEFAULT NULL,
  `start1` varchar(60) DEFAULT NULL,
  `end1` varchar(60) DEFAULT NULL,
  `dayno` varchar(60) DEFAULT NULL,
  `hostel` varchar(60) DEFAULT NULL,
  PRIMARY KEY (`tbid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

SET FOREIGN_KEY_CHECKS=1;

-- Notes:
-- - The original dumps used varchar columns for many date/time fields (e.g. `indatetime`).
--   For better behavior you may want to ALTER these to DATETIME or TIMESTAMP types after import.
-- - Two student tables exist: `studentdetails` and `studentdetails2` (kept as-is).
-- - No explicit foreign keys were present in the source dumps.
-- Dummy dataset for local testing
-- Usage: run `mysql < DB/dummy_studentdetails.sql` after schema import

INSERT INTO `studentdetails`
  (`uid`, `sname`, `email`, `dept`, `address`, `year`, `category`, `gender`,
   `mobileno`, `dob`, `academicyear`, `path`, `status`,
   `parentname`, `parentnumber`, `other1`, `other2`, `other3`)
VALUES
  ('SVP2025001', 'Rahul Patil', 'rahul.patil@example.com', 'CSE', 'Nagpur, MH', 'TE', 'Hostel', 'MALE',
   '9001000100', '2004-02-14', '2024-25', '/images/students/SVP2025001.jpg', 'Unrestrict',
   'Suresh Patil', '9001000101', NULL, NULL, NULL),
  ('SVP2025002', 'Aditi Kulkarni', 'aditi.k@example.com', 'IT', 'Pune, MH', 'SE', 'Hostel', 'FEMALE',
   '9001000200', '2005-07-21', '2024-25', '/images/students/SVP2025002.jpg', 'Restrict',
   'Meera Kulkarni', '9001000201', NULL, NULL, NULL),
  ('SVP2025003', 'Mohit Sharma', 'mohit.sharma@example.com', 'ENTC', 'Akola, MH', 'BE', 'Hostel', 'MALE',
   '9001000300', '2003-11-03', '2023-24', '/images/students/SVP2025003.jpg', 'Unrestrict',
   'Anita Sharma', '9001000301', NULL, NULL, NULL),
  ('SVP2025004', 'Sneha Jain', 'sneha.jain@example.com', 'CSE', 'Indore, MP', 'TE', 'Hostel', 'FEMALE',
   '9001000400', '2004-05-30', '2024-25', '/images/students/SVP2025004.jpg', 'Unrestrict',
   'Rajesh Jain', '9001000401', NULL, NULL, NULL),
  ('SVP2025005', 'Akash Gupta', 'akash.g@example.com', 'MECH', 'Bhopal, MP', 'SE', 'Day Scholar', 'MALE',
   '9001000500', '2005-09-18', '2024-25', '/images/students/SVP2025005.jpg', 'Unrestrict',
   'Neeta Gupta', '9001000501', NULL, 'Bus Route 3', NULL),
  ('SVP2025006', 'Pooja Deshmukh', 'pooja.d@example.com', 'CIVIL', 'Nagpur, MH', 'BE', 'Hostel', 'FEMALE',
   '9001000600', '2003-12-11', '2023-24', '/images/students/SVP2025006.jpg', 'Restrict',
   'Sunil Deshmukh', '9001000601', NULL, NULL, NULL),
  ('SVP2025007', 'Nikhil Verma', 'nikhil.verma@example.com', 'CSE', 'Raipur, CG', 'FE', 'Hostel', 'MALE',
   '9001000700', '2006-08-09', '2024-25', '/images/students/SVP2025007.jpg', 'Unrestrict',
   'Kiran Verma', '9001000701', NULL, NULL, NULL),
  ('SVP2025008', 'Isha More', 'isha.more@example.com', 'IT', 'Thane, MH', 'TE', 'Hostel', 'FEMALE',
   '9001000800', '2004-01-27', '2024-25', '/images/students/SVP2025008.jpg', 'Unrestrict',
   'Anjali More', '9001000801', NULL, NULL, NULL),
  ('SVP2025009', 'Yashwant Kale', 'yashwant.k@example.com', 'ENTC', 'Wardha, MH', 'BE', 'Hostel', 'MALE',
   '9001000900', '2003-04-05', '2023-24', '/images/students/SVP2025009.jpg', 'Restrict',
   'Pankaj Kale', '9001000901', NULL, NULL, NULL),
  ('SVP2025010', 'Lavanya Iyer', 'lavanya.iyer@example.com', 'CSE', 'Chennai, TN', 'FE', 'Hostel', 'FEMALE',
   '9001001000', '2006-10-02', '2024-25', '/images/students/SVP2025010.jpg', 'Unrestrict',
   'Priya Iyer', '9001001001', NULL, NULL, NULL);

-- MySQL script to create sick_leave_logs table
-- This table stores sick leave records for students

CREATE TABLE IF NOT EXISTS `sick_leave_logs` (
  `logid` int NOT NULL AUTO_INCREMENT,
  `uid` varchar(50) NOT NULL,
  `illness` varchar(100) NOT NULL,
  `logdate` date NOT NULL,
  `logtime` varchar(20) DEFAULT NULL,
  `recorded_by` varchar(100) DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`logid`),
  KEY `idx_uid` (`uid`),
  KEY `idx_logdate` (`logdate`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Add foreign key constraint if studentdetails table exists
-- ALTER TABLE `sick_leave_logs` 
-- ADD CONSTRAINT `fk_sick_leave_student` 
-- FOREIGN KEY (`uid`) REFERENCES `studentdetails` (`uid`) 
-- ON DELETE CASCADE ON UPDATE CASCADE;



CREATE DATABASE IF NOT EXISTS `gatepass_db` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE `gatepass_db`;


-- MySQL script to create sick_leave_logs table
-- This table stores sick leave records for students

CREATE TABLE IF NOT EXISTS `sick_leave_logs` (
  `logid` int NOT NULL AUTO_INCREMENT,
  `uid` varchar(50) NOT NULL,
  `illness` varchar(100) NOT NULL,
  `logdate` date NOT NULL,
  `logtime` varchar(20) DEFAULT NULL,
  `recorded_by` varchar(100) DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`logid`),
  KEY `idx_uid` (`uid`),
  KEY `idx_logdate` (`logdate`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Add foreign key constraint if studentdetails table exists
-- ALTER TABLE `sick_leave_logs` 
-- ADD CONSTRAINT `fk_sick_leave_student` 
-- FOREIGN KEY (`uid`) REFERENCES `studentdetails` (`uid`) 
-- ON DELETE CASCADE ON UPDATE CASCADE;


-- Student Portal Additional Tables
-- Run this SQL to add the required tables for student portal features

-- Add password field to studentdetails if not exists
ALTER TABLE studentdetails ADD COLUMN password VARCHAR(200) DEFAULT NULL;
-- Pass Requests Table (for student self-service pass requests)
CREATE TABLE IF NOT EXISTS `pass_requests` (
  `requestid` int NOT NULL AUTO_INCREMENT,
  `uid` varchar(50) NOT NULL,
  `passtype` varchar(45) NOT NULL,
  `expected_out` datetime DEFAULT NULL,
  `expected_return` datetime DEFAULT NULL,
  `reason` text,
  `emergency_contact` varchar(20) DEFAULT NULL,
  `status` enum('pending','approved','rejected','cancelled') DEFAULT 'pending',
  `approved_by` varchar(45) DEFAULT NULL,
  `approved_at` datetime DEFAULT NULL,
  `rejection_reason` text,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`requestid`),
  KEY `idx_uid` (`uid`),
  KEY `idx_status` (`status`),
  KEY `idx_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Student Notifications Table
CREATE TABLE IF NOT EXISTS `student_notifications` (
  `notifid` int NOT NULL AUTO_INCREMENT,
  `uid` varchar(50) NOT NULL,
  `type` varchar(50) DEFAULT 'info',
  `title` varchar(200) NOT NULL,
  `message` text,
  `read` tinyint(1) DEFAULT 0,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`notifid`),
  KEY `idx_uid` (`uid`),
  KEY `idx_read` (`read`),
  KEY `idx_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Indexes for better performance on existing tables
-- (Run only if these indexes don't exist)
-- ALTER TABLE log_details1 ADD INDEX idx_uid (uid);
-- ALTER TABLE log_details1 ADD INDEX idx_status (status);
-- ALTER TABLE log_details1 ADD INDEX idx_approvaldt (approvaldt);


select * from admin;


INSERT INTO studentdetails (
    uid, sname, email, dept, address, year, category, gender, mobileno, dob,
    academicyear, path, status, parentname, parentnumber, other1, other2, other3, password
) VALUES (
    '23016049',
    'Aryan',
    'aryanseth.23@stvincentngp.edu.in',
    'CSBS',
    '123 Sample Street, Sample City',
    '3rd Year',
    'Open',
    'Male',
    '7054017835'
    '25-05-2004',
    '2024-2025',
    '/uploads/students/23001063.jpg',
    'active',
    'Ashish Seth',
    '9889104047'
    'Value1',
    'Value2',
    'Value3',
    '7054017835'
);

delete from admin where adminid=38;

select * from admin;