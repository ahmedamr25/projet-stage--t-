import ldap from 'ldapjs';

const LDAP_URL = 'ldap://192.168.93.198:389';
const DOMAIN_SUFFIX = '@tiznit.local';

// Test direct: connexion en tant qu'utilisateur
const TEST_USERNAME = 'ahmed';
const TEST_PASSWORD = 'Moroc2026Moroc2026'; // Mot de passe d'ahmed

const userPrincipalName = `${TEST_USERNAME}${DOMAIN_SUFFIX}`;

console.log('=== TEST LDAP CONNEXION DIRECTE ===\n');
console.log(`Tentative de connexion: ${userPrincipalName}`);

const client = ldap.createClient({
  url: LDAP_URL,
  timeout: 5000,
  connectTimeout: 5000
});

client.bind(userPrincipalName, TEST_PASSWORD, (err) => {
  if (err) {
    console.error('❌ ERREUR:', err.message);
    console.error('CODE:', err.code);
    client.destroy();
    process.exit(1);
  }

  console.log('✅ Connexion réussie!');
  console.log(`   Utilisateur: ${userPrincipalName}`);
  console.log(`   UPN: ${userPrincipalName}`);
  
  client.destroy();
  process.exit(0);
});
