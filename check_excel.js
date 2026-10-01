const XLSX = require('xlsx');
const fs = require('fs');
const path = require('path');

// Look for uploaded Excel files
const uploadsDir = './uploads';
if (!fs.existsSync(uploadsDir)) {
  console.log('No uploads directory found');
  process.exit(0);
}

const files = fs.readdirSync(uploadsDir).filter(f => f.endsWith('.xlsx') || f.endsWith('.xls'));

if (files.length === 0) {
  console.log('No Excel files found in uploads');
  process.exit(0);
}

const filePath = path.join(uploadsDir, files[0]);
console.log(`Checking file: ${filePath}`);

const workbook = XLSX.readFile(filePath);
const worksheet = workbook.Sheets[workbook.SheetNames[0]];
const rows = XLSX.utils.sheet_to_json(worksheet);

if (rows.length > 0) {
  console.log('\nExcel Column Headers:');
  console.log(Object.keys(rows[0]));
  
  console.log('\nFirst Row Data:');
  const firstRow = rows[0];
  Object.entries(firstRow).forEach(([key, value]) => {
    console.log(`  ${key}: ${value}`);
  });
}

process.exit(0);
