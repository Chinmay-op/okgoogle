require('dotenv').config();
var mysql = require('mysql2');

// const connection = mysql.createPool({ 
//   host: process.env.DB_HOST || 'localhost', 
//     // host for connection 
//     port: 3306, 
//     // default port for mysql is 3306 
//     database: process.env.DB_NAME || 'gatepass_db', 
//     // database from which we want to connect out node application 
//     user: process.env.DB_USER || 'root', 
//     // username of the mysql connection 
//     password: process.env.DB_PASSWORD || 'anuj1234',
//     // password of the mysql connection 
//     multipleStatements: true,
//     connectionLimit: 5,
//     waitForConnections: true,
//     queueLimit: 0,
//     // Set timezone to UTC to prevent automatic timezone conversion
//     // This ensures datetimes are stored/retrieved exactly as provided
//     timezone: '+00:00'
// });

const connection = mysql.createPool({ 
  host: process.env.DB_HOST || 'localhost', 
    // host for connection 
    port: 3306, 
    // default port for mysql is 3306 
    database: process.env.DB_NAME, 
    // database from which we want to connect out node application 
    user: process.env.DB_USER, 
    // username of the mysql connection 
    password: process.env.DB_PASSWORD,
    // password of the mysql connection 
    multipleStatements: true,
    connectionLimit: 5,
    waitForConnections: true,
    queueLimit: 0,
    // Set timezone to UTC to prevent automatic timezone conversion
    // This ensures datetimes are stored/retrieved exactly as provided
    timezone: '+00:00'
});

connection.getConnection(function (err, connection) {
    if(err){
        console.log(err);
    }
    else{
        console.log("connection created with Mysql successfully");
        // Set session timezone to UTC to ensure consistent datetime handling
        connection.query("SET time_zone = '+00:00'", function(err) {
            if (err) {
                console.log("Warning: Could not set timezone:", err);
            }
        });
        connection.release();
    }
 });

if (process.env.NODE_ENV !== 'production') {
    connection.on('connection', function(conn) {
        conn.query("SET time_zone = '+00:00'", function(err) {
            if (err) console.log("Warning: Could not set timezone on pool connection:", err);
        });
    });
}

 module.exports = connection; 