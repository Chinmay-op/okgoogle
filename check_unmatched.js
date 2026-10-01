const dbbconnection = require('./server');

dbbconnection.getConnection(function (err, connection) {
  if (err) process.exit(1);
  connection.query('SELECT sname, uid FROM studentdetails WHERE (year="2025" OR academicyear="2025" OR academicyear LIKE "%2025%") AND (path IS NULL OR path = "" OR path = "0") LIMIT 20', function (err, result) {
    console.log(`Unmatched 2025 students:`, result);
    connection.release();
    process.exit(0);
  });
});
