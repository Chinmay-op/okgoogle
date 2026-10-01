CREATE TABLE IF NOT EXISTS rooms (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    capacity INT NOT NULL,
    price_per_night DECIMAL(10, 2) NOT NULL,
    description TEXT,
    is_available BOOLEAN DEFAULT TRUE,
    block VARCHAR(50) DEFAULT 'A',
    block VARCHAR(50) DEFAULT 'B',
    floor VARCHAR(50) DEFAULT 'Ground Floor',
    floor varchar(50) default 'First Floor',
    floor varchar(50) default 'Second Floor',
    room_type ENUM('Single', 'Double', 'Triple') DEFAULT 'Double'
);

CREATE TABLE IF NOT EXISTS bookings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    room_id INT NOT NULL,
    student_id INT NOT NULL, -- Assuming student_id links to an existing students table
    booking_date DATE NOT NULL,
    total_price DECIMAL(10, 2) NOT NULL,
    status ENUM('pending', 'on_hold', 'confirmed', 'cancelled') DEFAULT 'on_hold',
    payment_id INT,
    payment_status ENUM('pending', 'paid', 'refunded') DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (room_id) REFERENCES rooms(id),
    FOREIGN KEY (payment_id) REFERENCES payments(id)
);

CREATE TABLE IF NOT EXISTS payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    booking_id INT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    payment_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    transaction_id VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending', -- e.g., 'pending', 'completed', 'failed'
    FOREIGN KEY (booking_id) REFERENCES bookings(id)
);