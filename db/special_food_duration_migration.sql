-- Add admin-defined duration for special food items
-- Safe to run on existing databases

ALTER TABLE special_food_items
  ADD COLUMN duration_days INT NOT NULL DEFAULT 30 AFTER quantity_desc;

UPDATE special_food_items
SET duration_days = 30
WHERE duration_days IS NULL OR duration_days = 0;
