const dbbconnection = require('./server');

dbbconnection.getConnection(function (err, connection) {
  if (err) {
    console.error('❌ Connection error:', err.message);
    process.exit(1);
  }
  
  console.log('✓ Connected to database');
  
  // Check total students
  connection.query('SELECT COUNT(*) as count FROM studentdetails', function (err, result) {
    if (err) {
      console.error('Error:', err.message);
      connection.release();
      process.exit(1);
    }
    console.log(`✓ Total students in DB: ${result[0].count}`);
    
    // Check hostel students
    connection.query('SELECT COUNT(*) as count FROM studentdetails WHERE category="Hostel"', function (err, result) {
      if (err) {
        console.error('Error:', err.message);
        connection.release();
        process.exit(1);
      }
      console.log(`✓ Hostel students: ${result[0].count}`);
      
      // Show sample
      connection.query('SELECT uid, sname, category FROM studentdetails WHERE category="Hostel" LIMIT 5', function (err, result) {
        connection.release();
        if (err) {
          console.error('Error:', err.message);
          process.exit(1);
        }
        console.log('\nSample Hostel Students:');
        result.forEach(row => console.log(`  - UID: ${row.uid}, Name: ${row.sname}, Category: ${row.category}`));
        process.exit(0);
      });
    });
  });
});
