CREATE TABLE IF NOT EXISTS room_bookings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    room_no VARCHAR(50) NOT NULL,
    block VARCHAR(50) NOT NULL,
    floor VARCHAR(50) NOT NULL,
    bed_no VARCHAR(20) NOT NULL,
    uid VARCHAR(50) NOT NULL,
    booking_status ENUM('locked','cancelled') DEFAULT 'locked',
    payment_status ENUM('pending','confirmed','cancelled') DEFAULT 'pending',
    advance_amount DECIMAL(10,2) DEFAULT NULL,
    transaction_id VARCHAR(255) DEFAULT NULL,
    paid_at DATETIME DEFAULT NULL,
    agreement_accepted BOOLEAN DEFAULT FALSE,
    locked_source ENUM('student','admin') DEFAULT 'student',
    locked_by VARCHAR(100) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_room_bookings_uid_status ON room_bookings (uid, booking_status);
CREATE INDEX idx_room_bookings_bed_status ON room_bookings (room_no, block, floor, bed_no, booking_status);
