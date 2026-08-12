import ldap from 'ldapjs';

const LDAP_URL = 'ldap://192.168.93.198:389';

// Essayer différents formats de liaison
const testAccounts = [
  { dn: 'cn=Administrateur,cn=Users,dc=tiznit,dc=local', password: 'Moroc2026Moroc2026', name: 'CN format' },
  { dn: 'Administrator@tiznit.local', password: 'Moroc2026Moroc2026', name: 'UPN format' },
  { dn: 'TIZNIT\\Administrateur', password: 'Moroc2026Moroc2026', name: 'Domaine\\User format' },
  { dn: 'ahmed@tiznit.local', password: 'Moroc2026Moroc2026', name: 'Ahmed UPN' },
];

console.log('=== TEST MULTI-FORMAT LDAP ===\n');

let currentIndex = 0;

function testNext() {
  if (currentIndex >= testAccounts.length) {
    console.log('\n❌ AUCUN FORMAT NE FONCTIONNE');
    process.exit(1);
  }

  const account = testAccounts[currentIndex];
  console.log(`[${currentIndex + 1}/${testAccounts.length}] Test: ${account.name}`);
  console.log(`    DN: ${account.dn}`);

  const client = ldap.createClient({
    url: LDAP_URL,
    timeout: 5000,
    connectTimeout: 5000
  });

  client.bind(account.dn, account.password, (err) => {
    client.destroy();
    
    if (err) {
      console.log(`    ❌ Erreur: ${err.message}\n`);
    } else {
      console.log(`    ✅ SUCCÈS!\n`);
      console.log(`>>> LE FORMAT CORRECT EST: ${account.dn}`);
      process.exit(0);
    }

    currentIndex++;
    testNext();
  });
}

testNext();
