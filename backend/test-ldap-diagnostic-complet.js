import ldap from 'ldapjs';

console.log('=== DIAGNOSTIC COMPLET LDAP ===\n');

// Configuration à tester
const AD_IP = '192.168.93.198';
const DOMAIN = 'tiznit.local';
const BASE_DN = 'dc=tiznit,dc=local';

// Étape 1: Test de connectivité de base
console.log('[ÉTAPE 1] Test de connectivité brute');
console.log(`  IP: ${AD_IP}`);
console.log(`  Domaine: ${DOMAIN}\n`);

// Étape 2: Test des ports LDAP
const ports = [
  { port: 389, type: 'LDAP standard' },
  { port: 50000, type: 'Port alternatif' },
  { port: 636, type: 'LDAPS (chiffré)' }
];

let successPort = null;

async function testPorts() {
  for (const portConfig of ports) {
    const url = `ldap://${AD_IP}:${portConfig.port}`;
    console.log(`[ÉTAPE 2] Test port ${portConfig.port} (${portConfig.type})`);
    
    await new Promise((resolve) => {
      const client = ldap.createClient({
        url: url,
        timeout: 3000,
        connectTimeout: 3000
      });

      const timeout = setTimeout(() => {
        client.destroy();
        console.log(`  ❌ Timeout - Port ${portConfig.port} non accessible\n`);
        resolve();
      }, 3500);

      client.on('connect', () => {
        clearTimeout(timeout);
        console.log(`  ✅ Connexion TCP OK sur port ${portConfig.port}`);
        successPort = portConfig.port;
        client.destroy();
        resolve();
      });

      client.on('error', (err) => {
        clearTimeout(timeout);
        console.log(`  ❌ Erreur: ${err.message}\n`);
        client.destroy();
        resolve();
      });
    });

    if (successPort) break;
  }

  if (!successPort) {
    console.log('❌ AUCUN PORT LDAP N\'EST ACCESSIBLE\n');
    process.exit(1);
  }

  console.log(`\n✅ Port LDAP fonctionnel: ${successPort}\n`);
  await testAuthentication();
}

async function testAuthentication() {
  console.log(`[ÉTAPE 3] Test d'authentification\n`);

  // Essayer différents formats de DN
  const adminAccounts = [
    {
      dn: 'cn=Administrateur,cn=Users,dc=tiznit,dc=local',
      password: 'Moroc2026Moroc2026',
      description: 'CN format (français)'
    },
    {
      dn: 'Administrator@tiznit.local',
      password: 'Moroc2026Moroc2026',
      description: 'UPN format (Administrator)'
    },
    {
      dn: 'TIZNIT\\Administrateur',
      password: 'Moroc2026Moroc2026',
      description: 'NetBIOS format'
    }
  ];

  let authSuccess = false;

  for (const account of adminAccounts) {
    console.log(`  Tentative ${adminAccounts.indexOf(account) + 1}/${adminAccounts.length}: ${account.description}`);
    console.log(`    DN: ${account.dn}`);

    await new Promise((resolve) => {
      const client = ldap.createClient({
        url: `ldap://${AD_IP}:${successPort}`,
        timeout: 5000,
        connectTimeout: 5000
      });

      client.bind(account.dn, account.password, (err) => {
        if (err) {
          console.log(`    ❌ Erreur: ${err.message}\n`);
        } else {
          console.log(`    ✅ AUTHENTIFICATION RÉUSSIE!\n`);
          authSuccess = true;
          
          // Tester une recherche simple
          console.log('  Test de recherche d\'utilisateurs...');
          client.search(BASE_DN, {
            filter: '(sAMAccountName=*)',
            scope: 'sub',
            attributes: ['sAMAccountName', 'displayName']
          }, (searchErr, res) => {
            if (searchErr) {
              console.log(`    ❌ Erreur recherche: ${searchErr.message}`);
            } else {
              let userCount = 0;
              res.on('searchEntry', () => userCount++);
              res.on('end', () => {
                console.log(`    ✅ Trouvé ${userCount} utilisateurs\n`);
                client.destroy();
                resolve();
              });
            }
          });
        }

        if (err) {
          client.destroy();
          resolve();
        }
      });
    });

    if (authSuccess) break;
  }

  if (!authSuccess) {
    console.log('\n❌ AUCUN COMPTE N\'A PU SE CONNECTER');
    console.log('\n📋 VÉRIFIEZ:');
    console.log('  1. Le mot de passe du compte Administrateur');
    console.log('  2. Si le compte existe dans Active Directory');
    console.log('  3. La structure du domaine DC (dc=tiznit,dc=local)');
    process.exit(1);
  }

  console.log('✅ TOUT FONCTIONNE - CONFIGURATION AD OK!');
  process.exit(0);
}

testPorts();
