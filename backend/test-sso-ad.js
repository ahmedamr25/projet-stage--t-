import ldap from 'ldapjs';
import dotenv from 'dotenv';
dotenv.config();

const LDAP_URL = process.env.LDAP_URL;
const BASE_DN = process.env.LDAP_BASE_DN;
const BIND_DN = process.env.LDAP_BIND_DN;
const BIND_PASSWORD = process.env.LDAP_BIND_PASSWORD;

console.log('=== TEST CONNEXION AD VMware ===');
console.log(`Serveur : ${LDAP_URL}`);
console.log(`Base DN : ${BASE_DN}`);
console.log(`Bind DN : ${BIND_DN}`);
console.log('');

const client = ldap.createClient({
  url: LDAP_URL,
  timeout: 5000,
  connectTimeout: 5000
});

client.on('error', (err) => {
  console.error('❌ Impossible de se connecter au serveur AD VMware:', err.message);
  process.exit(1);
});

client.bind(BIND_DN, BIND_PASSWORD, (err) => {
  if (err) {
    console.error('❌ Échec bind admin:', err.message);
    client.destroy();
    process.exit(1);
  }

  console.log('✅ Connexion admin réussie au serveur VMware AD\n');

  // Lister TOUS les utilisateurs pour voir ce qui existe
  console.log('--- Liste de tous les utilisateurs AD ---');
  const filter = '(&(objectCategory=person)(objectClass=user))';

  client.search(BASE_DN, {
    filter,
    scope: 'sub',
    attributes: ['sAMAccountName', 'displayName', 'mail', 'cn'],
    sizeLimit: 50
  }, (searchErr, res) => {
    if (searchErr) {
      console.error('❌ Erreur recherche:', searchErr.message);
      client.destroy();
      process.exit(1);
    }

    const users = [];

    res.on('searchEntry', (entry) => {
      const attrs = entry.pojo ? entry.pojo.attributes : [];
      const user = {};
      attrs.forEach(a => { user[a.type] = a.values.join(', '); });
      users.push(user);
    });

    res.on('error', (err) => {
      console.error('❌ Erreur flux:', err.message);
      client.destroy();
    });

    res.on('end', () => {
      client.destroy();
      if (users.length === 0) {
        console.log('❌ Aucun utilisateur trouvé dans l\'annuaire AD !');
      } else {
        console.log(`✅ ${users.length} utilisateur(s) trouvé(s) :\n`);
        users.forEach((u, i) => {
          console.log(`  ${i + 1}. sAMAccountName: ${u.sAMAccountName || '(vide)'}`);
          console.log(`     displayName:    ${u.displayName || '(vide)'}`);
          console.log(`     cn:             ${u.cn || '(vide)'}`);
          console.log(`     mail:           ${u.mail || '(vide)'}`);
          console.log('');
        });
      }
      process.exit(0);
    });
  });
});
