// Génération de certificat auto-signé avec selfsigned / Node.js
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import selfsigned from 'selfsigned';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const certsDir = path.join(__dirname, 'certs');
if (!fs.existsSync(certsDir)) {
  fs.mkdirSync(certsDir, { recursive: true });
}

console.log('🔐 Génération de certificats SSL auto-signés avec selfsigned...\n');

try {
  const attrs = [{ name: 'commonName', value: 'localhost' }];
  const options = {
    days: 3650,
    keySize: 2048,
    algorithm: 'sha256',
    extensions: [{
      name: 'subjectAltName',
      altNames: [
        { type: 2, value: 'localhost' },
        { type: 7, ip: '127.0.0.1' }
      ]
    }]
  };

  const pems = await selfsigned.generate(attrs, options);

  fs.writeFileSync(path.join(certsDir, 'server.key'), pems.private, 'utf8');
  fs.writeFileSync(path.join(certsDir, 'server.crt'), pems.cert, 'utf8');

  console.log('✅ Certificats TLS générés avec succès !');
  console.log('\n📁 Fichiers créés:');
  console.log('   - Clé privée  : backend/certs/server.key');
  console.log('   - Certificat  : backend/certs/server.crt');
} catch (error) {
  console.error('❌ Erreur lors de la génération des certificats:', error.message);
  process.exit(1);
}

