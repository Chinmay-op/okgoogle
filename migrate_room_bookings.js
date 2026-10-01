const db = require('./server');

db.getConnection((err, conn) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  const queries = [
    "ALTER TABLE room_bookings ADD COLUMN bed_no VARCHAR(10) NOT NULL AFTER floor;",
    "ALTER TABLE room_bookings DROP INDEX unique_room_lock;",
    "ALTER TABLE room_bookings ADD UNIQUE KEY unique_bed_lock (room_no, block, floor, bed_no);"
  ];
  
  let i = 0;
  function next() {
    if (i >= queries.length) {
      console.log('Migration complete');
      conn.release();
      process.exit(0);
    }
    console.log('Running:', queries[i]);
    conn.query(queries[i], (qErr) => {
      if (qErr) {
        console.error('Error on query', i, qErr);
        // Continue if the error is just "Duplicate column name" etc
      }
      i++;
      next();
    });
  }
  next();
});
