-- studentdetails day-scholar rollover migration
-- Run the preview SELECT first and verify the actual counts against the expected counts.
-- If any preview count is off, stop here and do not run the UPDATE statements below.

-- ============================================================
-- STEP 0: Normalize 2 dirty ordinal rows before anything else
-- ============================================================
UPDATE studentdetails SET year = '3' WHERE uid = '21008027' AND category = 'Day Scholar';
UPDATE studentdetails SET year = '2' WHERE uid = '24056032' AND category = 'Day Scholar';

SELECT bucket, expected_count, actual_count
FROM (
  SELECT 1 AS sort_order, 'B.Voc 3+1 -> PassOut' AS bucket, 121 AS expected_count, COUNT(*) AS actual_count
  FROM studentdetails
  WHERE category = 'Day Scholar'
    AND dept IN (
      'B.VOC. in Software Development',
      'B.VOC. in Cyber Security',
      'B.VOC. in Virtual Reality & Augmented Reality',
      'B Vocational'
    )
    AND dept NOT IN ('M.TECH CADCAM', 'M.TECH CSE', 'MECHANICAL CAD-CAM')
    AND year = '3+1'

  UNION ALL

  SELECT 2 AS sort_order, 'B.Voc 4+1 anomaly -> PassOut' AS bucket, 67 AS expected_count, COUNT(*) AS actual_count
  FROM studentdetails
  WHERE category = 'Day Scholar'
    AND dept IN (
      'B.VOC. in Software Development',
      'B.VOC. in Cyber Security',
      'B.VOC. in Virtual Reality & Augmented Reality',
      'B Vocational'
    )
    AND dept NOT IN ('M.TECH CADCAM', 'M.TECH CSE', 'MECHANICAL CAD-CAM')
    AND year = '4+1'

  UNION ALL

  SELECT 3 AS sort_order, 'B.Voc 3 -> 3+1' AS bucket, 116 AS expected_count, COUNT(*) AS actual_count
  FROM studentdetails
  WHERE category = 'Day Scholar'
    AND dept IN (
      'B.VOC. in Software Development',
      'B.VOC. in Cyber Security',
      'B.VOC. in Virtual Reality & Augmented Reality',
      'B Vocational'
    )
    AND dept NOT IN ('M.TECH CADCAM', 'M.TECH CSE', 'MECHANICAL CAD-CAM')
    AND year = '3'

  UNION ALL

  SELECT 4 AS sort_order, 'B.Voc 2 -> 3' AS bucket, 98 AS expected_count, COUNT(*) AS actual_count
  FROM studentdetails
  WHERE category = 'Day Scholar'
    AND dept IN (
      'B.VOC. in Software Development',
      'B.VOC. in Cyber Security',
      'B.VOC. in Virtual Reality & Augmented Reality',
      'B Vocational'
    )
    AND dept NOT IN ('M.TECH CADCAM', 'M.TECH CSE', 'MECHANICAL CAD-CAM')
    AND year = '2'

  UNION ALL

  SELECT 5 AS sort_order, 'B.Voc 1 -> 2' AS bucket, 83 AS expected_count, COUNT(*) AS actual_count
  FROM studentdetails
  WHERE category = 'Day Scholar'
    AND dept IN (
      'B.VOC. in Software Development',
      'B.VOC. in Cyber Security',
      'B.VOC. in Virtual Reality & Augmented Reality',
      'B Vocational'
    )
    AND dept NOT IN ('M.TECH CADCAM', 'M.TECH CSE', 'MECHANICAL CAD-CAM')
    AND year = '1'

  UNION ALL

  SELECT 6 AS sort_order, 'Regular 4+1 -> PassOut' AS bucket, 549 AS expected_count, COUNT(*) AS actual_count
  FROM studentdetails
  WHERE category = 'Day Scholar'
    AND dept NOT IN (
      'B.VOC. in Software Development',
      'B.VOC. in Cyber Security',
      'B.VOC. in Virtual Reality & Augmented Reality',
      'B Vocational',
      'M.TECH CADCAM',
      'M.TECH CSE',
      'MECHANICAL CAD-CAM'
    )
    AND year = '4+1'

  UNION ALL

  SELECT 7 AS sort_order, 'Regular 4 -> 4+1' AS bucket, 733 AS expected_count, COUNT(*) AS actual_count
  FROM studentdetails
  WHERE category = 'Day Scholar'
    AND dept NOT IN (
      'B.VOC. in Software Development',
      'B.VOC. in Cyber Security',
      'B.VOC. in Virtual Reality & Augmented Reality',
      'B Vocational',
      'M.TECH CADCAM',
      'M.TECH CSE',
      'MECHANICAL CAD-CAM'
    )
    AND year = '4'

  UNION ALL

  SELECT 8 AS sort_order, 'Regular 3 -> 4' AS bucket, 904 AS expected_count, COUNT(*) AS actual_count
  FROM studentdetails
  WHERE category = 'Day Scholar'
    AND dept NOT IN (
      'B.VOC. in Software Development',
      'B.VOC. in Cyber Security',
      'B.VOC. in Virtual Reality & Augmented Reality',
      'B Vocational',
      'M.TECH CADCAM',
      'M.TECH CSE',
      'MECHANICAL CAD-CAM'
    )
    AND year = '3'

  UNION ALL

  SELECT 9 AS sort_order, 'Regular 2 -> 3' AS bucket, 727 AS expected_count, COUNT(*) AS actual_count
  FROM studentdetails
  WHERE category = 'Day Scholar'
    AND dept NOT IN (
      'B.VOC. in Software Development',
      'B.VOC. in Cyber Security',
      'B.VOC. in Virtual Reality & Augmented Reality',
      'B Vocational',
      'M.TECH CADCAM',
      'M.TECH CSE',
      'MECHANICAL CAD-CAM'
    )
    AND year = '2'

  UNION ALL

  SELECT 10 AS sort_order, 'Regular 1 -> 2' AS bucket, 701 AS expected_count, COUNT(*) AS actual_count
  FROM studentdetails
  WHERE category = 'Day Scholar'
    AND dept NOT IN (
      'B.VOC. in Software Development',
      'B.VOC. in Cyber Security',
      'B.VOC. in Virtual Reality & Augmented Reality',
      'B Vocational',
      'M.TECH CADCAM',
      'M.TECH CSE',
      'MECHANICAL CAD-CAM'
    )
    AND year = '1'

  UNION ALL

  SELECT 11 AS sort_order, 'Excluded (M.Tech/CAD-CAM)' AS bucket, 21 AS expected_count, COUNT(*) AS actual_count
  FROM studentdetails
  WHERE category = 'Day Scholar'
    AND dept IN ('M.TECH CADCAM', 'M.TECH CSE', 'MECHANICAL CAD-CAM')
) preview
ORDER BY sort_order;

START TRANSACTION;

UPDATE studentdetails
SET category = 'PassOut'
WHERE category = 'Day Scholar'
  AND dept IN (
    'B.VOC. in Software Development',
    'B.VOC. in Cyber Security',
    'B.VOC. in Virtual Reality & Augmented Reality',
    'B Vocational'
  )
  AND dept NOT IN ('M.TECH CADCAM', 'M.TECH CSE', 'MECHANICAL CAD-CAM')
  AND year = '3+1';

UPDATE studentdetails
SET category = 'PassOut'
WHERE category = 'Day Scholar'
  AND dept IN (
    'B.VOC. in Software Development',
    'B.VOC. in Cyber Security',
    'B.VOC. in Virtual Reality & Augmented Reality',
    'B Vocational'
  )
  AND dept NOT IN ('M.TECH CADCAM', 'M.TECH CSE', 'MECHANICAL CAD-CAM')
  AND year = '4+1';

UPDATE studentdetails
SET year = '3+1'
WHERE category = 'Day Scholar'
  AND dept IN (
    'B.VOC. in Software Development',
    'B.VOC. in Cyber Security',
    'B.VOC. in Virtual Reality & Augmented Reality',
    'B Vocational'
  )
  AND dept NOT IN ('M.TECH CADCAM', 'M.TECH CSE', 'MECHANICAL CAD-CAM')
  AND year = '3';

UPDATE studentdetails
SET year = '3'
WHERE category = 'Day Scholar'
  AND dept IN (
    'B.VOC. in Software Development',
    'B.VOC. in Cyber Security',
    'B.VOC. in Virtual Reality & Augmented Reality',
    'B Vocational'
  )
  AND dept NOT IN ('M.TECH CADCAM', 'M.TECH CSE', 'MECHANICAL CAD-CAM')
  AND year = '2';

UPDATE studentdetails
SET year = '2'
WHERE category = 'Day Scholar'
  AND dept IN (
    'B.VOC. in Software Development',
    'B.VOC. in Cyber Security',
    'B.VOC. in Virtual Reality & Augmented Reality',
    'B Vocational'
  )
  AND dept NOT IN ('M.TECH CADCAM', 'M.TECH CSE', 'MECHANICAL CAD-CAM')
  AND year = '1';

UPDATE studentdetails
SET category = 'PassOut'
WHERE category = 'Day Scholar'
  AND dept NOT IN (
    'B.VOC. in Software Development',
    'B.VOC. in Cyber Security',
    'B.VOC. in Virtual Reality & Augmented Reality',
    'B Vocational',
    'M.TECH CADCAM',
    'M.TECH CSE',
    'MECHANICAL CAD-CAM'
  )
  AND year = '4+1';

UPDATE studentdetails
SET year = '4+1'
WHERE category = 'Day Scholar'
  AND dept NOT IN (
    'B.VOC. in Software Development',
    'B.VOC. in Cyber Security',
    'B.VOC. in Virtual Reality & Augmented Reality',
    'B Vocational',
    'M.TECH CADCAM',
    'M.TECH CSE',
    'MECHANICAL CAD-CAM'
  )
  AND year = '4';

UPDATE studentdetails
SET year = '4'
WHERE category = 'Day Scholar'
  AND dept NOT IN (
    'B.VOC. in Software Development',
    'B.VOC. in Cyber Security',
    'B.VOC. in Virtual Reality & Augmented Reality',
    'B Vocational',
    'M.TECH CADCAM',
    'M.TECH CSE',
    'MECHANICAL CAD-CAM'
  )
  AND year = '3';

UPDATE studentdetails
SET year = '3'
WHERE category = 'Day Scholar'
  AND dept NOT IN (
    'B.VOC. in Software Development',
    'B.VOC. in Cyber Security',
    'B.VOC. in Virtual Reality & Augmented Reality',
    'B Vocational',
    'M.TECH CADCAM',
    'M.TECH CSE',
    'MECHANICAL CAD-CAM'
  )
  AND year = '2';

UPDATE studentdetails
SET year = '2'
WHERE category = 'Day Scholar'
  AND dept NOT IN (
    'B.VOC. in Software Development',
    'B.VOC. in Cyber Security',
    'B.VOC. in Virtual Reality & Augmented Reality',
    'B Vocational',
    'M.TECH CADCAM',
    'M.TECH CSE',
    'MECHANICAL CAD-CAM'
  )
  AND year = '1';

COMMIT;

SELECT year, category, COUNT(*)
FROM studentdetails
WHERE category IN ('Day Scholar', 'PassOut')
  AND dept NOT IN ('M.TECH CADCAM', 'M.TECH CSE', 'MECHANICAL CAD-CAM')
GROUP BY year, category
ORDER BY year, category;

SELECT dept, year, category, COUNT(*)
FROM studentdetails
WHERE dept IN ('M.TECH CADCAM', 'M.TECH CSE', 'MECHANICAL CAD-CAM')
GROUP BY dept, year, category;