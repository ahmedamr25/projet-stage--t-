const http = require('http');
const req = http.request({host:'localhost', port:5000, path:'/api/auth/me'}, (res) => {
  console.log('Status:', res.statusCode);
  process.exit(0);
});
req.on('error', (e) => {
  console.log('Error:', e.code);
  process.exit(1);
});
req.end();
