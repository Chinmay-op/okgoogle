-- Add image_path column to complaints for optional complaint image attachment.
-- Run once: mysql -u user -p your_db < db/add_complaint_image.sql
-- If image_path already exists, this will error; that is fine.

ALTER TABLE complaints ADD COLUMN image_path VARCHAR(500) NULL AFTER category;
