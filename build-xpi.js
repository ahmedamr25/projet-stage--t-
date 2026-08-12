const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const srcDir = path.join(__dirname, 'firefox-extension');
const zipPath = path.join(__dirname, 'securpass-firefox-temp.zip');
const xpiPath = path.join(__dirname, 'securpass-firefox.xpi');

try { fs.unlinkSync(xpiPath); } catch (e) {}
try { fs.unlinkSync(zipPath); } catch (e) {}

const cmd = `powershell -Command "Compress-Archive -Path '${srcDir}\\*' -DestinationPath '${zipPath}' -Force"`;
execSync(cmd, { stdio: 'pipe' });

fs.renameSync(zipPath, xpiPath);
console.log('XPI created:', xpiPath);
