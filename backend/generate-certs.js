import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const certsDir = path.join(__dirname, 'certs');
if (!fs.existsSync(certsDir)) {
  fs.mkdirSync(certsDir, { recursive: true });
}

console.log('🔐 Génération de certificats SSL auto-signés...');

try {
  // Méthode 1: Utiliser OpenSSL si disponible (Windows/Git Bash)
  try {
    execSync(
      `openssl req -x509 -newkey rsa:2048 -nodes -sha256 -subj "/CN=localhost" ` +
      `-keyout "${path.join(certsDir, 'server.key')}" ` +
      `-out "${path.join(certsDir, 'server.crt')}" ` +
      `-days 3650`,
      { stdio: 'inherit' }
    );
    console.log('✅ Certificats TLS générés avec OpenSSL !');
  } catch (opensslError) {
    // Méthode 2: Utiliser le package selfsigned
    console.log('⚠️  OpenSSL non disponible, utilisation du package Node.js...');
    
    const selfsigned = await import('selfsigned');
    
    const attrs = [{ name: 'commonName', value: 'localhost' }];
    const options = { 
      days: 3650,
      keySize: 2048,
      algorithm: 'sha256',
      extensions: [{
        name: 'subjectAltName',
        altNames: [{
          type: 2, // DNS
          value: 'localhost'
        }, {
          type: 7, // IP
          ip: '127.0.0.1'
        }]
      }]
    };

    const pems = await selfsigned.default.generate(attrs, options);

    if (!pems || !pems.private || !pems.cert) {
      throw new Error('Échec de génération des certificats');
    }

    fs.writeFileSync(path.join(certsDir, 'server.key'), pems.private, 'utf8');
    fs.writeFileSync(path.join(certsDir, 'server.crt'), pems.cert, 'utf8');
    
    console.log('✅ Certificats TLS générés avec selfsigned !');
  }

  console.log('\n📁 Fichiers créés :');
  console.log('   - Certificat : backend/certs/server.crt');
  console.log('   - Clé privée : backend/certs/server.key');
  console.log('\n⚠️  Note : Ces certificats sont auto-signés.');
  console.log('   Votre navigateur affichera un avertissement de sécurité.');
  console.log('   Cliquez sur "Avancé" puis "Continuer vers localhost".');

} catch (error) {
  console.error('❌ Erreur lors de la génération des certificats:', error.message);
  console.error('\n💡 Solution alternative : Le serveur fonctionnera en HTTP (port 5000)');
  process.exit(1);
}
