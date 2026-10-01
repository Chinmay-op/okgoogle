const dbbconnection = require('./server');

dbbconnection.getConnection(function (err, connection) {
  if (err) process.exit(1);
  connection.query('SELECT uid, sname, path FROM studentdetails WHERE path IS NOT NULL AND path != "" AND path != "0" AND path NOT LIKE "/images%" LIMIT 10', function (err, result) {
    console.log(`Other weird paths:`, result);
    connection.release();
    process.exit(0);
  });
});
