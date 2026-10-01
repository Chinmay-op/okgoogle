/**
 * CANONICAL DEPARTMENT LIST -- Single source of truth.
 *
 * Rules:
 *  - value  = exact string stored in the database (studentdetails.dept / hostel_admission_applications.branch)
 *  - label  = human-friendly display text shown in dropdowns
 *  - Never change these values without a corresponding database migration.
 *  - Only these 24 values are accepted by the backend API routes.
 */
(function (global) {
  global.CANONICAL_DEPARTMENTS = [
    { label: 'Computer Science & Engineering (CSE)',              value: 'COMPUTER ENGINEERING' },
    { label: 'Electrical Engineering',                            value: 'ELECTRICAL ENGINEERING' },
    { label: 'Information Technology (IT)',                       value: 'INFORMATION TECHNOLOGY' },
    { label: 'Electronics & Telecommunication Engineering (ETC)', value: 'ELECTRONICS & TELECOMMUNICATION ENGINEERING' },
    { label: 'Mechanical Engineering',                            value: 'MECHANICAL ENGINEERING' },
    { label: 'Civil Engineering',                                 value: 'CIVIL ENGINEERING' },
    { label: 'Artificial Intelligence (AI)',                      value: 'ARTIFICIAL INTELLIGENCE' },
    { label: 'Computer Science & Engineering (Data Science)',     value: 'COMPUTER SCIENCE & ENGINEERING (DATA SCIENCE)' },
    { label: 'Computer Science & Engineering (Cyber Security)',   value: 'COMPUTER SCIENCE & ENGINEERING (CYBER SECURITY)' },
    { label: 'Industrial IoT (IIoT)',                             value: 'INDUSTRIAL IOT' },
    { label: 'Computer Science and Business Systems (CSBS)',      value: 'COMPUTER SCIENCE AND BUSINESS SYSTEMS' },
    { label: 'Robotics & Artificial Intelligence (RAI)',          value: 'ROBOTICS & ARTIFICIAL INTELLIGENCE' },
    { label: 'Mechanical CAD-CAM',                                value: 'MECHANICAL CAD-CAM' },
    { label: 'B.Voc. in Cyber Security',                          value: 'B.VOC. IN CYBER SECURITY' },
    { label: 'B.Voc. in Software Development',                    value: 'B.VOC. IN SOFTWARE DEVELOPMENT' },
    { label: 'B.Voc. in Virtual Reality & Augmented Reality',    value: 'B.VOC. IN VIRTUAL REALITY & AUGMENTED REALITY' },
    { label: 'B Vocational',                                      value: 'B VOCATIONAL' },
    { label: 'BCA',                                               value: 'BCA' },
    { label: 'BBA',                                               value: 'BBA' },
    { label: 'MCA',                                               value: 'MCA' },
    { label: 'MBA',                                               value: 'MBA' },
    { label: 'M.Tech',                                            value: 'M.TECH' },
    { label: 'M.Tech CSE',                                        value: 'M.TECH CSE' },
    { label: 'M.Tech CAD-CAM',                                    value: 'M.TECH CADCAM' }
  ];
})(typeof window !== 'undefined' ? window : global);