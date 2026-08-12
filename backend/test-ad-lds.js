import ldap from 'ldapjs';

async function testADLDS() {
    const host = '192.168.93.198';
    const port = 50000;
    const baseDN = 'dc=tiznit,dc=local';
    
    console.log('🔍 TEST AD LDS - PORT 50000');
    console.log('='.repeat(50));
    
    // Test avec différentes combinaisons
    const tests = [
  
        {
            name: 'Administrateur (français)',
            dn: 'CN=Administrateur,CN=Users,dc=tiznit,dc=local',
            pwd: '1234@AMR@@'
        },
        {
            name: 'Administrator (anglais)',
            dn: 'CN=Administrator,CN=Users,dc=tiznit,dc=local',
            pwd: '1234@AMR@@'
        },
        {
            name: 'Admin direct (sans OU)',
            dn: 'CN=admin,dc=tiznit,dc=local',
            pwd: '1234@AMR@@'
        }
    ];
    
    for (const test of tests) {
        console.log(`\n📋 Test: ${test.name}`);
        console.log(`   DN: ${test.dn}`);
        
        try {
            await new Promise((resolve) => {
                const client = ldap.createClient({
                    url: `ldap://${host}:${port}`,
                    timeout: 10000,
                    connectTimeout: 5000,
                    reconnect: false
                });
                
                let timeout = setTimeout(() => {
                    console.log('   ⏰ Timeout (10s)');
                    client.destroy();
                    resolve();
                }, 10000);
                
                client.bind(test.dn, test.pwd, (err) => {
                    clearTimeout(timeout);
                    
                    if (err) {
                        console.log(`   ❌ Échec: ${err.message}`);
                        if (err.message.includes('80090304')) {
                            console.log('   📌 Erreur 0x80090304: Mot de passe ou DN incorrect');
                        }
                    } else {
                        console.log(`   ✅ SUCCÈS !`);
                        console.log(`   ✅ DN valide trouvé: ${test.dn}`);
                        
                        // Test de recherche après bind
                        const opts = {
                            filter: '(objectClass=*)',
                            scope: 'base',
                            attributes: ['*']
                        };
                        
                        client.search(baseDN, opts, (err, res) => {
                            if (err) {
                                console.log(`   ❌ Recherche échouée: ${err.message}`);
                            } else {
                                res.on('searchEntry', (entry) => {
                                    console.log(`   📋 Structure de l'annuaire:`);
                                    console.log(`      ${JSON.stringify(entry.object, null, 2)}`);
                                });
                                res.on('error', (err) => {
                                    console.log(`   ❌ Erreur recherche: ${err.message}`);
                                });
                                res.on('end', () => {
                                    client.destroy();
                                    resolve();
                                });
                            }
                        });
                    }
                });
            });
        } catch (err) {
            console.log(`   ❌ Erreur: ${err.message}`);
        }
    }
    
    console.log('\n' + '='.repeat(50));
    console.log('💡 Si aucun test ne fonctionne:');
    console.log('   1. Vérifiez que le service AD LDS tourne (Get-Service ADAM_Instance1)');
    console.log('   2. Vérifiez le mot de passe (doit respecter la politique)');
    console.log('   3. Utilisez ADSI Edit pour explorer la structure');
}

testADLDS().catch(console.error);