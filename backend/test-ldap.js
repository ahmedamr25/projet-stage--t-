import ldap from 'ldapjs';

// Configuration du test
const LDAP_URL = 'ldap://192.168.93.198:389';
const BASE_DN = 'dc=tiznit,dc=local';
const ADMIN_DN = 'cn=Administrateur,cn=Users,dc=tiznit,dc=local';
const ADMIN_PASSWORD = '1234@AMR@@'; // À remplacer par le vrai mot de passe admin

// Compte utilisateur à tester
const TEST_USERNAME = 'ahmed';
const TEST_PASSWORD = 'Moroc2026Moroc2026'; // Entrez le mot de passe d'ahmed

console.log('=== TEST LDAP CONFIGURATION ===\n');

// Étape 1: Tester la liaison admin
console.log(`[1] Tentative de liaison ADMIN: ${ADMIN_DN}`);
const adminClient = ldap.createClient({
  url: LDAP_URL,
  timeout: 5000,
  connectTimeout: 5000
});

adminClient.bind(ADMIN_DN, ADMIN_PASSWORD, (adminErr) => {
  if (adminErr) {
    console.error('❌ ERREUR liaison admin:', adminErr.message);
    adminClient.destroy();
    process.exit(1);
  }

  console.log('✅ Liaison admin réussie\n');

  // Étape 2: Rechercher l'utilisateur
  console.log(`[2] Recherche de l'utilisateur: ${TEST_USERNAME}`);
  const filter = `(sAMAccountName=${TEST_USERNAME})`;

  adminClient.search(BASE_DN, {
    filter: filter,
    scope: 'sub',
    attributes: ['dn', 'displayName', 'mail', 'memberOf']
  }, (searchErr, res) => {
    if (searchErr) {
      console.error('❌ ERREUR recherche:', searchErr.message);
      adminClient.destroy();
      process.exit(1);
    }

    let userEntry = null;

    res.on('searchEntry', (entry) => {
      userEntry = entry.object;
      console.log('✅ Utilisateur trouvé:', entry.object.dn);
    });

    res.on('error', (err) => {
      console.error('❌ ERREUR durant la recherche:', err.message);
    });

    res.on('end', (result) => {
      adminClient.destroy();

      if (!userEntry) {
        console.error('❌ Utilisateur non trouvé');
        process.exit(1);
      }

      // Étape 3: Tester la liaison utilisateur
      console.log(`\n[3] Tentative de liaison UTILISATEUR: ${userEntry.dn}`);
      const userClient = ldap.createClient({
        url: LDAP_URL,
        timeout: 5000,
        connectTimeout: 5000
      });

      userClient.bind(userEntry.dn, TEST_PASSWORD, (userErr) => {
        if (userErr) {
          console.error('❌ ERREUR mot de passe:', userErr.message);
          userClient.destroy();
          process.exit(1);
        }

        console.log('✅ Liaison utilisateur réussie\n');
        console.log('📊 RÉSUMÉ:');
        console.log('  - DN:', userEntry.dn);
        console.log('  - Nom:', userEntry.displayName);
        console.log('  - Email:', userEntry.mail);
        console.log('  - Groupes:', userEntry.memberOf || 'Aucun');

        userClient.destroy();
        process.exit(0);
      });
    });
  });
});
