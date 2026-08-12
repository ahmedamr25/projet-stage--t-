const fs = require('fs');
const path = require('path');

const src = path.join(__dirname, '..', 'chrome-extension', 'icon.png');
const dst = path.join(__dirname, 'icon.png');

if (fs.existsSync(src)) {
  fs.copyFileSync(src, dst);
  console.log('Icon copied successfully');
} else {
  console.log('Source icon not found');
}
