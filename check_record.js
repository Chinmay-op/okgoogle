const dbbconnection = require('./server');

dbbconnection.getConnection(function (err, connection) {
  if (err) {
    console.error('Connection error:', err.message);
    process.exit(1);
  }
  
  const sql = 'SELECT * FROM studentdetails WHERE category="Hostel" LIMIT 1';
  connection.query(sql, function (err, result) {
    connection.release();
    if (err) {
      console.error('Error:', err.message);
      process.exit(1);
    }
    
    if (result.length > 0) {
      console.log('Sample record structure:');
      const row = result[0];
      Object.keys(row).forEach(key => {
        console.log(`  ${key}: ${row[key]}`);
      });
    }
    process.exit(0);
  });
});
