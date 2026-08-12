import ldap from 'ldapjs';

console.log('=== DIAGNOSTIC LDAP SIMPLIFIÉ ===\n');

const tests = [
  {
    name: 'Port 389 (Standard)',
    url: 'ldap://192.168.93.198:389',
    dn: 'cn=Administrateur,cn=Users,dc=tiznit,dc=local',
    password: '1234@AMR@@'
  },
  {
    name: 'Port 50000 (Alternatif)',
    url: 'ldap://192.168.93.198:50000',
    dn: 'cn=Administrateur,cn=Users,dc=tiznit,dc=local',
    password: '1234@AMR@@'
  },
  {
    name: 'UPN Format',
    url: 'ldap://192.168.93.198:389',
    dn: 'Administrator@tiznit.local',
    password: '1234@AMR@@'
  }
];

let testIndex = 0;

function runNextTest() {
  if (testIndex >= tests.length) {
    console.log('\n❌ TOUS LES TESTS ONT ÉCHOUÉ');
    console.log('\n📋 VÉRIFIEZ:');
    console.log('  1. ✅ L\'IP 192.168.93.198 est accessible (ping OK)');
    console.log('  2. ❓ Le port LDAP (389 ou 50000)?');
    console.log('  3. ❓ Le compte "Administrateur" existe-t-il?');
    console.log('  4. ❓ Le mot de passe "Moroc2026Moroc2026" est-il correct?');
    console.log('\nPour continuer avec l\'app: mettez LDAP_MOCK=true dans .env\n');
    process.exit(1);
  }

  const test = tests[testIndex];
  console.log(`[TEST ${testIndex + 1}/${tests.length}] ${test.name}`);
  console.log(`  URL: ${test.url}`);
  console.log(`  DN: ${test.dn}`);

  const client = ldap.createClient({
    url: test.url,
    timeout: 3000,
    connectTimeout: 3000
  });

  client.bind(test.dn, test.password, (err) => {
    if (err) {
      console.log(`  ❌ Erreur: ${err.message}`);
      console.log(`     Code: ${err.code}\n`);
    } else {
      console.log(`  ✅ SUCCÈS! Identifiants corrects!\n`);
      console.log(`📝 CONFIGURATION À UTILISER:`);
      console.log(`  LDAP_MOCK=false`);
      console.log(`  LDAP_URL=${test.url}`);
      console.log(`  LDAP_BIND_DN=${test.dn}`);
      console.log(`  LDAP_BIND_PASSWORD=${test.password}\n`);
      client.destroy();
      process.exit(0);
    }

    client.destroy();
    testIndex++;
    runNextTest();
  });
}

runNextTest();
