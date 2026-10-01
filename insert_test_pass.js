const mysql = require('mysql2');
const connection = mysql.createConnection({
  host: 'MYSQL8003.site4now.net',
  user: 'a2df89_hostel',
  password: 'wcw4576K!',
  database: 'db_a2df89_hostel'
});

connection.connect(err => {
  if (err) {
    console.error('Error connecting:', err);
    return;
  }
  
  const uid = '23016049';
  const passtype = 'City Pass';
  const expectedOut = '2026-08-27 15:00:00';
  const expectedReturn = '2026-08-27 18:00:00';
  const reason = 'Testing pass request creation 2';
  const status = 'pending';
  const createdAt = '2026-08-27 14:05:00';
  
  const sql = `INSERT INTO pass_requests 
  (uid, passtype, expected_out, expected_return, reason, status, created_at, request_kind, is_emergency) 
  VALUES (?, ?, ?, ?, ?, ?, ?, 'new', 0)`;
  
  connection.query(sql, [uid, passtype, expectedOut, expectedReturn, reason, status, createdAt], (err, result) => {
    if (err) {
      console.error('Error inserting:', err);
    } else {
      console.log('Successfully inserted pass request with ID:', result.insertId);
    }
    connection.end();
  });
});
