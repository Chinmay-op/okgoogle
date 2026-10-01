const dbbconnection = require('./server');

dbbconnection.getConnection(function (err, connection) {
  if (err) {
    console.error('❌ Connection error:', err.message);
    process.exit(1);
  }
  
  // Check hostel students
  connection.query('SELECT COUNT(*) as count FROM studentdetails WHERE category="Hostel"', function (err, result) {
    if (err) {
      console.error('Error:', err.message);
      connection.release();
      process.exit(1);
    }
    console.log(`✓ Total Hostel students: ${result[0].count}`);
    
    // Show first 10 with uid and sname
    connection.query('SELECT uid, sname, room_no, bed_no FROM studentdetails WHERE category="Hostel" ORDER BY sname LIMIT 10', function (err, result) {
      connection.release();
      if (err) {
        console.error('Error:', err.message);
        process.exit(1);
      }
      console.log('\nFirst 10 Hostel Students:');
      result.forEach((row, i) => {
        console.log(`  ${i+1}. ${row.sname} (UID: ${row.uid}, Room: ${row.room_no}, Bed: ${row.bed_no})`);
      });
      process.exit(0);
    });
  });
});
