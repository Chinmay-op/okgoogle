const dbbconnection = require('./server');

dbbconnection.getConnection(function (err, connection) {
  if (err) process.exit(1);
  connection.query('UPDATE studentdetails SET path = REPLACE(path, "/PHOTO/", "/images/student_pics/") WHERE path LIKE "/PHOTO/%"', function (err, result) {
    console.log(`Replaced /PHOTO/ with correct path for ${result.affectedRows} students`);
    connection.release();
    process.exit(0);
  });
});
