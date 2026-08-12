import ldap from 'ldapjs';

const LDAP_URL = 'ldap://192.168.93.198:389';
const BASE_DN = 'dc=tiznit,dc=local';
const ADMIN_DN = 'cn=Administrateur,cn=Users,dc=tiznit,dc=local';
const ADMIN_PASSWORD = 'Moroc2026Moroc2026'; // Mot de passe admin mis à jour

console.log('=== DIAGNOSTIC LDAP ===\n');

const client = ldap.createClient({
  url: LDAP_URL,
  timeout: 5000,
  connectTimeout: 5000
});

// Test 1: Liaison admin
console.log(`[TEST 1] Liaison admin: ${ADMIN_DN}`);
client.bind(ADMIN_DN, ADMIN_PASSWORD, (err) => {
  if (err) {
    console.error('❌ ERREUR:', err.message);
    console.error('CODE:', err.code);
    process.exit(1);
  }

  console.log('✅ Liaison admin réussie\n');

  // Test 2: Lister tous les utilisateurs
  console.log('[TEST 2] Recherche de tous les utilisateurs (sAMAccountName=*)');
  
  client.search(BASE_DN, {
    filter: '(sAMAccountName=*)',
    scope: 'sub',
    attributes: ['sAMAccountName', 'displayName', 'mail']
  }, (searchErr, res) => {
    if (searchErr) {
      console.error('❌ ERREUR recherche:', searchErr.message);
      process.exit(1);
    }

    let count = 0;
    const users = [];

    res.on('searchEntry', (entry) => {
      count++;
      users.push({
        sAMAccountName: entry.object.sAMAccountName,
        displayName: entry.object.displayName,
        mail: entry.object.mail
      });
    });

    res.on('error', (err) => {
      console.error('❌ ERREUR:', err.message);
    });

    res.on('end', (result) => {
      console.log(`\n✅ Trouvé ${count} utilisateurs:\n`);
      users.forEach(u => {
        console.log(`  - ${u.sAMAccountName} | ${u.displayName} | ${u.mail}`);
      });

      client.destroy();
      process.exit(0);
    });
  });
});
