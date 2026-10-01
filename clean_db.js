const dbbconnection = require('./server');

dbbconnection.getConnection(function (err, connection) {
  if (err) {
    console.error('Connection error:', err.message);
    process.exit(1);
  }
  
  // Delete all hostel students
  const sql = 'DELETE FROM studentdetails WHERE category="Hostel"';
  connection.query(sql, function (err, result) {
    connection.release();
    if (err) {
      console.error('Error:', err.message);
      process.exit(1);
    }
    console.log(`✓ Deleted ${result.affectedRows} hostel student records`);
    process.exit(0);
  });
});
