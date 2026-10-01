const fs = require('fs');
const lines = fs.readFileSync('app.js', 'utf8').split('\n');

const routes = [];
let currentRoute = null;

for (let i = 0; i < lines.length; i++) {
    const routeMatch = lines[i].match(/app\.(get|post)\(['"]([^'"]+)['"]/);
    if (routeMatch) {
        currentRoute = routeMatch[0];
    }
    
    if (lines[i].includes('res.render') && lines[i].includes('breakfast')) {
        routes.push({ line: i+1, route: currentRoute, render: lines[i].trim() });
    }
}

console.log(JSON.stringify(routes, null, 2));
