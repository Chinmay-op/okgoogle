const dbbconnection = require('./server');

dbbconnection.getConnection(function (err, connection) {
  if (err) process.exit(1);
  connection.query('SELECT COUNT(*) as count FROM studentdetails WHERE path IS NOT NULL AND path != "" AND path != "0"', function (err, result) {
    console.log(`Students with paths: ${result[0].count}`);
    connection.release();
    process.exit(0);
  });
});
