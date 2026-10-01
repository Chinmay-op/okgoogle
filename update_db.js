const db = require('./server'); 
const queries = [
  'ALTER TABLE weekly_optional_menu ADD COLUMN food_type VARCHAR(20) DEFAULT "Veg" AFTER meal_type;',
  'ALTER TABLE weekly_optional_menu DROP INDEX idx_unique_weekday_meal;',
  'ALTER TABLE weekly_optional_menu DROP INDEX unique_day_meal;',
  'ALTER TABLE weekly_optional_menu ADD UNIQUE INDEX unique_day_meal_type (weekday, meal_type, food_type);'
];

async function run() {
  for (let q of queries) {
    try {
      await new Promise((res, rej) => db.query(q, (err) => err ? rej(err) : res()));
      console.log('Success:', q);
    } catch(e) {
      console.error('Error on:', q, e.message);
    }
  }
  process.exit();
}
run();
