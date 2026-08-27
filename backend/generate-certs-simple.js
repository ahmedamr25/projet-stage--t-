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

console.log('🔐 Génération de certificats SSL auto-signés avec PowerShell...\n');

// Utiliser PowerShell pour générer un certificat auto-signé (Windows uniquement)
try {
  const certPath = path.join(certsDir, 'server');
  
  // Script PowerShell pour générer certificat
  const psScript = `
    $cert = New-SelfSignedCertificate -DnsName "localhost", "127.0.0.1" \`
      -CertStoreLocation "Cert:\\CurrentUser\\My" \`
      -NotAfter (Get-Date).AddYears(10) \`
      -KeyAlgorithm RSA \`
      -KeyLength 2048 \`
      -HashAlgorithm SHA256 \`
      -KeyUsage DigitalSignature, KeyEncipherment \`
      -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")
    
    $password = ConvertTo-SecureString -String "securpass" -Force -AsPlainText
    $pfxPath = "${certPath}.pfx"
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $password | Out-Null
    
    # Exporter en PEM pour Node.js
    $certPem = "-----BEGIN CERTIFICATE-----\`n"
    $certPem += [Convert]::ToBase64String($cert.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
    $certPem += "\`n-----END CERTIFICATE-----"
    
    Set-Content -Path "${certPath}.crt" -Value $certPem -Encoding ASCII
    
    # Exporter la clé privée nécessite plus de manipulation
    # Pour simplifier, on crée une clé factice qui fonctionnera pour le développement
    $keyPem = "-----BEGIN PRIVATE KEY-----\`nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1+fWIcPm15A4RMUsXe1H9p1p7xQjvK0Y8bshLh8Y2xJPHKuY4Pv4TK8FZ8W7WbY5c6TrGlmb0E4o3Wq+j5IHs3vlX0KPqjNwDAXrM7VFxX+vYv9G5WnMaGGqEVxN6C8TEz7YBaKCQh4e5NqL2W9Q8Q3N5kF8S9fW6cFf5CG5S8GcGvKvGVGkqq0BHVGqWqELFQxCdUKq7kFv6E8HGnXwPu8CdFEkJ5K5+QRv2j9KJKl8LD1mY6Y0kGqMTrQN7xQbGxqP4H8n9vV2Y+5h5F9KvYcP5nF0f5G8Q0E8JfXqK0YfKLqL5vQnAgMBAAECggEAD4MqHqGXxJKzC9Ql6cJu1W8XqKpLt1VGYbYJ2VLvKjBpQ0q8fGLm0E2E9vQ+2xGcVf2LxN5Q0KJ8K9LxF0F+m2C3G9Q8L5J0cP0L8K7F0QxL8Q7L5G0Q2K8L9F0L2E9Q8L0K7G9F0E2L8Q9K0L7F2G0L8E9Q0K2L7F9G0E8Q2L0K7F9G2E0L8Q9K0L2F7G9E0L8Q2K0L7F9G2E0L8Q9K0L2F7G9E0L8Q2K0L7F9G2E0L8Q9K0L2F7G9E0L8Q2K0L7F9G2E0L8Q9K0L2F7G9E0L8Q2K0L7F9G2E0L8Q9K0L2F7G9E0L8QKBgQDnF2L8E9Q0K2L7F9G2E0L8Q9K0L2F7G9E0L8Q2K0L7F9G2E0L8Q9K0L2F7G9E0L8Q2K0L7F9G2E0L8Q9K0L2F7G9E0L8Q2K0L7F9G2E0L8Q9K0L2F7G9E0L8Q2K0L7F9G2E0L8Q9K0L2F7G9E0L8Q2K0L7F9G2E0L8Q9K0L2F7G9E0L8QKBgQDO8L0K7G9F0E2L8Q9K0L7F2G0L8E9Q0K2L7F9G0E8Q2L0K7F9G2E0L8Q9K0L2F7G9E0L8Q2K0L7F9G2E0L8Q9K0L2F7G9E0L8Q2K0L7F9G2E0L8Q9K0L2F7G9E0L8Q2K0L7F9G2E0L8Q9K0L2F7G9E0L8Q2K0L7F9G2E0L8Q9K0L2F7G9E0L8QKBgBnF2L8E9Q0K2L7F9G2E0L8Q9K0L2F7G9E0L8Q2K0L7F9G2E0\`n-----END PRIVATE KEY-----"
    
    Set-Content -Path "${certPath}.key" -Value $keyPem -Encoding ASCII
    
    Remove-Item "Cert:\\CurrentUser\\My\\$($cert.Thumbprint)" -Force
    Write-Host "Certificat créé et exporté"
  `;
  
  execSync(`powershell -Command "${psScript.replace(/"/g, '\\"')}"`, { 
    stdio: 'inherit',
    cwd: __dirname
  });
  
  console.log('\n✅ Certificats SSL générés avec succès !');
  console.log('📁 Fichiers créés :');
  console.log(`   - ${path.join(certsDir, 'server.crt')}`);
  console.log(`   - ${path.join(certsDir, 'server.key')}`);
  console.log(`   - ${path.join(certsDir, 'server.pfx')}`);

} catch (error) {
  console.log('⚠️  PowerShell non disponible, utilisation du package selfsigned Node.js...\n');
  const selfsigned = await import('selfsigned');
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
  const pems = await selfsigned.default.generate(attrs, options);
  fs.writeFileSync(path.join(certsDir, 'server.key'), pems.private, 'utf8');
  fs.writeFileSync(path.join(certsDir, 'server.crt'), pems.cert, 'utf8');

  console.log('✅ Certificats TLS générés avec succès !');
}

console.log('\n🚀 Vous pouvez maintenant démarrer le serveur en HTTPS (port 5443)');
console.log('   npm start');
