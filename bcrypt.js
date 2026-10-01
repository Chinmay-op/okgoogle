var connection  = require('./server'); 
const bcrypt = require('bcrypt');

         
          var sql ="Select uid,password from admin";
          connection.query(sql,async function(err, result){
           if (err) throw err;
            for(i=0;i<result.length;i++){
            var password = await bcrypt.hash(result[i].password,12);
           
                  var sql1 ="Update admin set password='"+password+"'  where uid='"+result[i].uid+"'";
                  connection.query(sql1,async function(err, result){
                    if (err) throw err;
                    console.log("bcrypt password");
                  });
           
        }
          });
        