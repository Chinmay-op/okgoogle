const mysql = require('mysql2');
const db = mysql.createConnection({host:'localhost',user:'root',password:'vedant@2005',database:'gatepass_db'});
db.query("SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_NAME = 'breakfast_selection' AND CONSTRAINT_NAME != 'PRIMARY'", (err, res) => {
    console.log(res);
    db.end();
});
