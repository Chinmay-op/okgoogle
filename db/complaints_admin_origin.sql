-- Allow admin-originated complaints: nullable student_uid and admin_name.
-- Complaints status ENUM is unchanged: 'pending_approval', 'approved', 'resolved', 'denied'.
-- Run once: mysql -u user -p your_db < db/complaints_admin_origin.sql
-- If admin_name already exists, skip the first ALTER or run the rest only.

-- Add admin_name for complaints sent from admin panel
ALTER TABLE complaints ADD COLUMN admin_name VARCHAR(255) NULL AFTER student_uid;

-- Allow NULL student_uid for admin-originated complaints (drop FK first)
ALTER TABLE complaints DROP FOREIGN KEY fk_student_uid;
ALTER TABLE complaints MODIFY COLUMN student_uid VARCHAR(50) NULL;
