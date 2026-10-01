const fs = require('fs');
const path = require('path');
const dbbconnection = require('./server');

const picsDir = path.join(__dirname, 'public', 'images', 'student_pics');

function normalizeName(name) {
  // Remove non-alphanumeric, split into words, sort alphabetically, join
  return name.replace(/[^a-zA-Z0-9\s]/g, '')
             .replace(/\s+/g, ' ')
             .trim()
             .toUpperCase()
             .split(' ')
             .sort()
             .join(' ');
}

dbbconnection.getConnection(function (err, connection) {
  if (err) {
    console.error('Connection error:', err.message);
    process.exit(1);
  }

  // Get all students first to do in-memory mapping
  connection.query('SELECT uid, sname FROM studentdetails', (err, students) => {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    
    // Create a normalized map
    const studentMap = new Map();
    students.forEach(s => {
      if (s.sname) {
         const norm = normalizeName(s.sname);
         // store array of uids in case of duplicates
         if (!studentMap.has(norm)) studentMap.set(norm, []);
         studentMap.get(norm).push({ uid: s.uid, sname: s.sname });
      }
    });

    const years = fs.readdirSync(picsDir);
    let totalFiles = 0;
    let matches = 0;
    let updates = [];

    years.forEach(year => {
      const yearDir = path.join(picsDir, year);
      if (!fs.statSync(yearDir).isDirectory()) return;

      const files = fs.readdirSync(yearDir);
      totalFiles += files.length;

      files.forEach(file => {
        const ext = path.extname(file);
        const rawName = path.basename(file, ext);
        const normName = normalizeName(rawName);
        
        const relativePath = `/images/student_pics/${year}/${file}`;
        
        if (studentMap.has(normName)) {
           const matchesFound = studentMap.get(normName);
           matchesFound.forEach(m => {
              updates.push({ path: relativePath, uid: m.uid, rawName, dbName: m.sname });
           });
        }
      });
    });

    console.log(`Found ${totalFiles} photos. Doing fuzzy mapping... found ${updates.length} db matches.`);
    
    async function processUpdates() {
      let updatedRows = 0;
      for (const update of updates) {
        await new Promise((resolve) => {
          connection.query('UPDATE studentdetails SET path = ? WHERE uid = ?', [update.path, update.uid], (err, result) => {
            if (err) {
              console.error('Error updating:', err.message);
            } else {
              if (result.affectedRows > 0) updatedRows += result.affectedRows;
            }
            resolve();
          });
        });
      }
      console.log(`Successfully updated ${updatedRows} student paths using fuzzy logic.`);
      connection.release();
      process.exit(0);
    }

    processUpdates();
  });
});
