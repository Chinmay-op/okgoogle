const dbbconnection = require('./server');

dbbconnection.getConnection(function (err, connection) {
  if (err) process.exit(1);
  connection.query('SELECT uid, sname, path FROM studentdetails WHERE (year="2025" OR year="1" OR uid LIKE "25%") AND path IS NOT NULL AND path != "" AND path != "0" LIMIT 5', function (err, result) {
    console.log(`2025 new students with paths:`, result);
    connection.release();
    process.exit(0);
  });
});
