import ldap from 'ldapjs';
import dotenv from 'dotenv';
import crypto from 'crypto';
import fs from 'fs';
import tls from 'tls';

dotenv.config();

const isMock = process.env.LDAP_MOCK === 'true';

export function escapeLdapFilterValue(value) {
  return String(value).replace(/[\0\(\)\*\\]/g, (ch) => {
    switch (ch) {
      case '\0': return '\\00';
      case '(': return '\\28';
      case ')': return '\\29';
      case '*': return '\\2a';
      case '\\': return '\\5c';
      default: return ch;
    }
  });
}

function escapeLdapDnValue(value) {
  return String(value).replace(/[,+"\\<>;=#]/g, (ch) => '\\' + ch);
}

const USERNAME_PATTERN = /^[a-z0-9._-]{2,64}$/;

export function sanitizeUsername(username) {
  const sanitized = String(username || '').trim().toLowerCase();
  if (!sanitized || sanitized.length < 2 || sanitized.length > 64) {
    return { valid: false, error: 'Nom d\'utilisateur invalide (2 à 64 caractères).' };
  }
  if (!USERNAME_PATTERN.test(sanitized)) {
    return { valid: false, error: 'Caractères non autorisés dans le nom d\'utilisateur.' };
  }
  return { valid: true, username: sanitized };
}

export function sanitizeDisplayName(name) {
  const sanitized = String(name || '').trim();
  if (!sanitized || sanitized.length < 2 || sanitized.length > 128) {
    return { valid: false, error: 'Nom d\'affichage invalide (2 à 128 caractères).' };
  }
  if (/[\0\(\)\*\\<>;]/.test(sanitized)) {
    return { valid: false, error: 'Caractères non autorisés dans le nom d\'affichage.' };
  }
  return { valid: true, displayName: sanitized };
}

export function sanitizeEmail(email) {
  const sanitized = String(email || '').trim().toLowerCase();
  if (!sanitized) return { valid: true, email: '' };
  if (sanitized.length > 254 || !/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(sanitized)) {
    return { valid: false, error: 'Adresse e-mail invalide.' };
  }
  return { valid: true, email: sanitized };
}

function getUserSuffixDomain() {
  const suffix = process.env.LDAP_USER_SUFFIX || '';
  return suffix.startsWith('@') ? suffix.slice(1) : suffix;
}

function validateLdapConfigOrThrow() {
  if (isMock) return;
  const required = ['LDAP_URL', 'LDAP_BASE_DN'];
  const missing = required.filter((k) => !process.env[k] || !String(process.env[k]).trim());
  if (missing.length > 0) {
    throw new Error(`Configuration LDAP manquante: ${missing.join(', ')}`);
  }
}

function formatBindDN(dn) {
  if (!dn) return dn;
  return dn.replace(/cn=Utilisateurs/i, 'cn=Users');
}

// ==========================================
// FACTORY CENTRALISÉE DE CLIENT LDAP/LDAPS
// ==========================================

/**
 * Crée un client LDAP avec support automatique de LDAPS (TLS/SSL).
 * Si LDAPS_ENABLED=true dans le .env, utilise ldaps:// avec les options TLS.
 * @param {Object} overrides - Options supplémentaires pour le client
 * @returns {Object} Client ldapjs configuré
 */
function createLdapClient(overrides = {}) {
  const ldapsEnabled = process.env.LDAPS_ENABLED === 'true';
  const ldapUrl = ldapsEnabled
    ? (process.env.LDAPS_URL || process.env.LDAP_URL)
    : process.env.LDAP_URL;

  const clientOptions = {
    url: ldapUrl,
    timeout: 5000,
    connectTimeout: 5000,
    ...overrides
  };

  // Configuration TLS/SSL pour LDAPS
  if (ldapsEnabled) {
    const tlsOptions = {
      rejectUnauthorized: process.env.LDAPS_REJECT_UNAUTHORIZED !== 'false'
    };

    // Charger le certificat CA si configuré
    const caCertPath = process.env.LDAPS_CA_CERT_PATH;
    if (caCertPath) {
      try {
        if (fs.existsSync(caCertPath)) {
          tlsOptions.ca = [fs.readFileSync(caCertPath)];
          console.log(`[LDAPS] Certificat CA chargé : ${caCertPath}`);
        } else {
          console.warn(`[LDAPS] Certificat CA introuvable : ${caCertPath}`);
        }
      } catch (err) {
        console.error(`[LDAPS] Erreur de chargement du certificat CA : ${err.message}`);
      }
    }

    clientOptions.tlsOptions = tlsOptions;
    console.log(`[LDAPS] Connexion sécurisée à ${ldapUrl} (TLS activé, rejectUnauthorized=${tlsOptions.rejectUnauthorized})`);
  }

  return ldap.createClient(clientOptions);
}

function extractGroups(memberOf) {
  if (!memberOf) return [];
  const groups = Array.isArray(memberOf) ? memberOf : [memberOf];
  return groups.map(dn => {
    const match = dn.match(/^CN=([^,]+)/i);
    return match ? match[1] : dn;
  }).filter(Boolean);
}

function getEntryObject(entry) {
  if (!entry) return {};
  if (entry.object && !entry.attributes) {
    return entry.object;
  }
  const obj = {};
  const attributes = entry.attributes || (entry.pojo && entry.pojo.attributes) || [];
  for (const attr of attributes) {
    const type = attr.type;
    const values = attr.values || [];
    let val;
    if (values.length === 1) {
      val = values[0];
    } else if (values.length > 1) {
      val = values;
    } else {
      val = null;
    }
    obj[type] = val;
    obj[type.toLowerCase()] = val;
  }
  if (entry.dn) {
    obj.dn = entry.dn.toString();
  } else if (entry.pojo && entry.pojo.objectName) {
    obj.dn = entry.pojo.objectName;
  }
  return obj;
}

// ==========================================
// MODE MOCK
// ==========================================

const mockUsersStore = {
  'admin': {
    password: 'Admin@2026!',
    displayName: 'Administrateur Système',
    email: 'admin@entreprise.local',
    memberOf: ['Domain Admins', 'IT-Security'],
    whenCreated: '2026-01-01T10:00:00Z'
  },
  'ahmed': {
    password: 'Ahmed2026!',
    displayName: 'Ahmed Utilisateur',
    email: 'ahmed@entreprise.local',
    memberOf: ['Domain Users'],
    whenCreated: '2026-02-15T14:30:00Z'
  },
  'user': {
    password: 'User@2026!',
    displayName: 'Collaborateur Entreprise',
    email: 'user@entreprise.local',
    memberOf: ['Domain Users'],
    whenCreated: '2026-03-10T09:15:00Z'
  },
  'administrateur': {
    password: 'Admin@2026!',
    displayName: 'Administrateur Système',
    email: 'administrateur@entreprise.local',
    memberOf: ['Domain Admins', 'IT-Security'],
    whenCreated: '2026-01-01T10:00:00Z'
  },
  'test.user': {
    password: 'Test@2026!',
    displayName: 'Test User',
    email: 'test.user@entreprise.local',
    memberOf: ['Domain Users'],
    whenCreated: '2026-05-20T11:45:00Z'
  }
};

function getMockUserList() {
  return Object.entries(mockUsersStore).map(([username, data]) => ({
    username,
    displayName: data.displayName,
    email: data.email,
    groups: data.memberOf,
    whenCreated: data.whenCreated || null
  }));
}

function handleMockAuth(username, password, resolve) {
  console.log(`[LDAP MOCK] Authentification pour: ${username}`);

  const user = mockUsersStore[username];
  
  if (!user) {
    console.warn(`[LDAP MOCK] Tentative d'accès échouée pour: ${username}`);
    return resolve({ success: false, error: 'Identifiant ou mot de passe incorrect.' });
  }

  if (user.password !== password) {
    console.warn(`[LDAP MOCK] Mot de passe incorrect pour: ${username}`);
    return resolve({ success: false, error: 'Identifiant ou mot de passe incorrect.' });
  }

  console.log(`[LDAP MOCK] Authentification réussie: ${username}`);
  return resolve({
    success: true,
    user: {
      username,
      displayName: user.displayName,
      email: user.email,
      groups: user.memberOf
    }
  });
}

// ==========================================
// AUTHENTIFICATION LDAP RÉELLE
// ==========================================

function handleRealLDAPAuth(username, password, resolve) {
  const ldapUrl = process.env.LDAP_URL;
  const baseDN = process.env.LDAP_BASE_DN;
  const userSuffix = process.env.LDAP_USER_SUFFIX || '';
  const bindDN = process.env.LDAP_BIND_DN;
  const bindPassword = process.env.LDAP_BIND_PASSWORD;

  // ✅ S'assurer que le mot de passe est une string
  const passwordStr = String(password || '');
  
  if (!passwordStr || passwordStr.length === 0) {
    console.error('[LDAP] Mot de passe vide');
    return resolve({ success: false, error: 'Mot de passe requis.' });
  }

  if (!ldapUrl || !baseDN) {
    console.error('[LDAP] Configuration LDAP incomplète');
    return resolve({ success: false, error: 'Configuration LDAP invalide.' });
  }

  console.log(`[LDAP REAL] Connexion à ${ldapUrl}...`);

  const client = createLdapClient({
    reconnect: {
      initialDelay: 100,
      maxDelay: 3000,
      failAfter: 3
    }
  });

  let settled = false;
  const safeResolve = (payload) => {
    if (settled) return;
    settled = true;
    resolve(payload);
  };

  client.on('error', (err) => {
    console.error('[LDAP] Erreur client:', err.message);
    client.destroy();
    safeResolve({ success: false, error: 'Erreur de connexion LDAP.' });
  });

  if (!bindDN || !bindPassword) {
    return performDirectBind(client, username, passwordStr, userSuffix, baseDN, safeResolve);
  }

  const formattedBindDN = formatBindDN(bindDN);
  console.log(`[LDAP] Utilisation du compte de liaison: ${formattedBindDN}`);

  performServiceAccountBind(client, username, passwordStr, formattedBindDN, bindPassword, baseDN, userSuffix, safeResolve);
}

// ==========================================
// AUTHENTIFICATION AVEC COMPTE DE SERVICE - CORRIGÉE
// ==========================================

function performServiceAccountBind(client, username, password, bindDN, bindPassword, baseDN, userSuffix, resolve) {
  console.log(`[LDAP] Bind avec compte de service: ${bindDN}`);
  
  client.bind(bindDN, bindPassword, (err) => {
    if (err) {
      console.error('[LDAP] Échec bind service:', err.message);
      client.destroy();
      return resolve({ success: false, error: 'Erreur d\'authentification LDAP. Vérifiez les identifiants du compte de liaison.' });
    }

    console.log('[LDAP] Bind service réussi, recherche de l\'utilisateur...');

    const escaped = escapeLdapFilterValue(username);
    const domain = getUserSuffixDomain() || 'tiznit.local';
    const filter = `(&(objectClass=user)(|(sAMAccountName=${escaped})(cn=${escaped})(userPrincipalName=${escaped}@${domain})))`;
    
    console.log(`[LDAP] Filtre de recherche: ${filter}`);

    client.search(baseDN, {
      filter,
      scope: 'sub',
      attributes: ['dn', 'displayName', 'mail', 'memberOf', 'sAMAccountName', 'cn', 'userPrincipalName'],
      sizeLimit: 1,
      timeLimit: 10
    }, (searchErr, res) => {
      if (searchErr) {
        console.error('[LDAP] Erreur recherche:', searchErr.message);
        client.destroy();
        return resolve({ success: false, error: 'Erreur de recherche LDAP.' });
      }

      let userEntry = null;

      res.on('searchEntry', (entry) => {
        if (!userEntry) {
          userEntry = entry;
          console.log(`[LDAP] Utilisateur trouvé: ${entry.dn}`);
        }
      });

      res.on('error', (err) => {
        console.error('[LDAP] Erreur recherche:', err.message);
        client.destroy();
        resolve({ success: false, error: 'Erreur de recherche LDAP.' });
      });

      res.on('end', () => {
        if (!userEntry) {
          console.warn(`[LDAP] Utilisateur non trouvé: ${username}`);
          client.destroy();
          return resolve({ success: false, error: 'Utilisateur non trouvé.' });
        }

        const userDN = userEntry.dn.toString();
        console.log(`[LDAP] Tentative de bind pour: ${userDN}`);
        console.log(`[LDAP] Type du mot de passe: ${typeof password}, longueur: ${password ? password.length : 0}`);

        // ✅ CRUCIAL: Convertir en string explicite
        const passwordStr = String(password);
        
        if (!passwordStr || passwordStr.length === 0) {
          console.error('[LDAP] Mot de passe invalide après conversion');
          client.destroy();
          return resolve({ success: false, error: 'Mot de passe requis.' });
        }

        console.log(`[LDAP] Mot de passe converti en string (longueur: ${passwordStr.length})`);

        // ✅ Utiliser passwordStr qui est une string
        client.bind(userDN, passwordStr, (userBindErr) => {
          if (userBindErr) {
            console.warn(`[LDAP] Échec bind utilisateur: ${username} - ${userBindErr.message}`);
            client.destroy();
            
            if (userBindErr.message && userBindErr.message.includes('data 773')) {
              return resolve({ success: false, error: 'Mot de passe expiré. Veuillez changer votre mot de passe.' });
            }
            if (userBindErr.message && userBindErr.message.includes('data 775')) {
              return resolve({ success: false, error: 'Compte verrouillé. Contactez l\'administrateur.' });
            }
            if (userBindErr.message && userBindErr.message.includes('data 52e')) {
              return resolve({ success: false, error: 'Mot de passe incorrect.' });
            }
            
            return resolve({ success: false, error: `Échec d'authentification: ${userBindErr.message}` });
          }

          // ✅ SUCCÈS
          const obj = getEntryObject(userEntry);
          const userInfo = {
            username: obj.sAMAccountName || obj.samaccountname || username,
            displayName: obj.displayName || obj.displayname || obj.cn || username,
            email: obj.mail || `${username}${userSuffix}`,
            groups: extractGroups(obj.memberOf || obj.memberof)
          };

          console.log(`[LDAP] Authentification réussie: ${username}`);
          client.destroy();
          resolve({ success: true, user: userInfo });
        });
      });
    });
  });
}

// ==========================================
// AUTHENTIFICATION DIRECTE
// ==========================================

function performDirectBind(client, username, password, userSuffix, baseDN, resolve) {
  const userPrincipalName = username.includes('@') ? username : `${username}${userSuffix}`;
  
  console.log(`[LDAP] Bind direct avec: ${userPrincipalName}`);
  
  // ✅ S'assurer que le mot de passe est une string
  const passwordStr = String(password);
  
  client.bind(userPrincipalName, passwordStr, (err) => {
    if (err) {
      console.warn(`[LDAP] Échec bind direct: ${userPrincipalName} - ${err.message}`);
      client.destroy();
      
      if (err.message && err.message.includes('data 773')) {
        return resolve({ success: false, error: 'Mot de passe expiré. Veuillez changer votre mot de passe.' });
      }
      if (err.message && err.message.includes('data 775')) {
        return resolve({ success: false, error: 'Compte verrouillé. Contactez l\'administrateur.' });
      }
      
      return resolve({ success: false, error: 'Identifiant ou mot de passe incorrect.' });
    }

    const escaped = escapeLdapFilterValue(username);
    const filter = `(sAMAccountName=${escaped})`;
    
    client.search(baseDN, {
      filter,
      scope: 'sub',
      attributes: ['displayName', 'mail', 'memberOf'],
      sizeLimit: 1,
      timeLimit: 5
    }, (searchErr, res) => {
      let userInfo = {
        username,
        displayName: username,
        email: userPrincipalName,
        groups: []
      };

      res.on('searchEntry', (entry) => {
        const obj = getEntryObject(entry);
        userInfo.displayName = obj.displayName || obj.displayname || username;
        userInfo.email = obj.mail || userPrincipalName;
        userInfo.groups = extractGroups(obj.memberOf || obj.memberof);
      });

      res.on('end', () => {
        client.destroy();
        console.log(`[LDAP] Authentification réussie: ${username}`);
        resolve({ success: true, user: userInfo });
      });

      res.on('error', (err) => {
        console.warn(`[LDAP] Erreur de recherche post-bind: ${err.message}`);
        client.destroy();
        resolve({ success: true, user: userInfo });
      });
    });
  });
}

// ==========================================
// FONCTION PRINCIPALE - EXPORTÉE
// ==========================================

export function authenticateUser(username, password) {
  return new Promise((resolve) => {
    try {
      validateLdapConfigOrThrow();
    } catch (e) {
      console.error('[LDAP] Configuration invalide:', e.message);
      return resolve({ success: false, error: 'Configuration LDAP invalide côté serveur.' });
    }

    if (!username || !password) {
      return resolve({ 
        success: false, 
        error: 'Identifiant et mot de passe requis.' 
      });
    }

    const usernameCheck = sanitizeUsername(username);
    if (!usernameCheck.valid) {
      return resolve({ success: false, error: usernameCheck.error });
    }

    if (isMock) {
      return handleMockAuth(usernameCheck.username, password, resolve);
    }

    return handleRealLDAPAuth(usernameCheck.username, password, resolve);
  });
}

// ==========================================
// OBTENIR TOUS LES UTILISATEURS AD/LDAP
// ==========================================

export function getAllUsers() {
  return new Promise((resolve) => {
    if (isMock) {
      console.log('[LDAP MOCK] Récupération de tous les utilisateurs');
      return resolve({ success: true, users: getMockUserList() });
    }

    try {
      validateLdapConfigOrThrow();
    } catch (e) {
      console.error('[LDAP] Configuration brute invalide:', e.message);
      return resolve({ success: false, error: 'Configuration LDAP invalide.' });
    }

    const ldapUrl = process.env.LDAP_URL;
    const baseDN = process.env.LDAP_BASE_DN;
    const bindDN = process.env.LDAP_BIND_DN;
    const bindPassword = process.env.LDAP_BIND_PASSWORD;

    if (!bindDN || !bindPassword) {
      return resolve({ success: false, error: 'Compte de liaison LDAP non configuré.' });
    }

    console.log(`[LDAP REAL] Connexion à ${ldapUrl} pour lister les utilisateurs...`);

    const client = ldap.createClient({
      url: ldapUrl,
      timeout: 5000,
      connectTimeout: 5000
    });

    client.on('error', (err) => {
      console.error('[LDAP] Erreur lors de la liste des utilisateurs:', err.message);
      client.destroy();
      resolve({ success: false, error: 'Erreur de connexion LDAP.' });
    });

    const formattedBindDN = formatBindDN(bindDN);

    client.bind(formattedBindDN, bindPassword, (bindErr) => {
      if (bindErr) {
        console.error('[LDAP] Échec bind service pour liste:', bindErr.message);
        client.destroy();
        return resolve({ success: false, error: 'Échec de liaison au service LDAP.' });
      }

      const filter = '(&(objectCategory=person)(objectClass=user))';
      console.log(`[LDAP] Recherche des utilisateurs avec filtre: ${filter}`);

      client.search(baseDN, {
        filter,
        scope: 'sub',
        attributes: ['sAMAccountName', 'displayName', 'mail', 'memberOf', 'whenCreated'],
        sizeLimit: 100
      }, (searchErr, res) => {
        if (searchErr) {
          console.error('[LDAP] Erreur recherche liste:', searchErr.message);
          client.destroy();
          return resolve({ success: false, error: 'Erreur de recherche LDAP.' });
        }

        const users = [];

        res.on('searchEntry', (entry) => {
          const obj = getEntryObject(entry);
          users.push({
            username: obj.sAMAccountName || obj.samaccountname || '',
            displayName: obj.displayName || obj.displayname || obj.cn || '',
            email: obj.mail || '',
            groups: extractGroups(obj.memberOf || obj.memberof),
            whenCreated: obj.whenCreated || obj.whencreated || null
          });
        });

        res.on('error', (err) => {
          console.error('[LDAP] Erreur flux recherche liste:', err.message);
          client.destroy();
          resolve({ success: false, error: 'Erreur de lecture LDAP.' });
        });

        res.on('end', () => {
          client.destroy();
          const filtered = users
            .filter(u => u.username && u.username.trim())
            .sort((a, b) => (a.displayName || a.username).localeCompare(b.displayName || b.username, 'fr'));
          console.log(`[LDAP] ${filtered.length} utilisateurs récupérés.`);
          resolve({ success: true, users: filtered });
        });
      });
    });
  });
}

/**
 * Crée un utilisateur dans l'annuaire Active Directory (ou en mode mock).
 * @param {Object} params - Les informations de l'utilisateur.
 * @param {string} params.username L'identifiant réseau de l'utilisateur.
 * @param {string} params.displayName Le nom d'affichage.
 * @param {string} params.email L'adresse e-mail.
 * @param {string} params.password Le mot de passe initial.
 * @returns {Promise<Object>} Promesse résolue avec { success, user } ou { success, error }.
 */
export function createUser({ username, displayName, email, password }) {
  return new Promise((resolve) => {
    const usernameCheck = sanitizeUsername(username);
    if (!usernameCheck.valid) {
      return resolve({ success: false, error: usernameCheck.error });
    }

    const displayCheck = sanitizeDisplayName(displayName);
    if (!displayCheck.valid) {
      return resolve({ success: false, error: displayCheck.error });
    }

    const emailCheck = sanitizeEmail(email);
    if (!emailCheck.valid) {
      return resolve({ success: false, error: emailCheck.error });
    }

    const passwordStr = String(password || '');
    if (passwordStr.length < 8 || passwordStr.length > 128) {
      return resolve({ success: false, error: 'Le mot de passe doit contenir entre 8 et 128 caractères.' });
    }

    if (isMock) {
      if (mockUsersStore[usernameCheck.username]) {
        return resolve({ success: false, error: 'Cet utilisateur existe déjà.' });
      }

      mockUsersStore[usernameCheck.username] = {
        password: passwordStr,
        displayName: displayCheck.displayName,
        email: emailCheck.email || `${usernameCheck.username}@entreprise.local`,
        memberOf: ['Domain Users'],
        whenCreated: new Date().toISOString()
      };

      console.log(`[LDAP MOCK] Utilisateur créé: ${usernameCheck.username}`);
      return resolve({
        success: true,
        user: {
          username: usernameCheck.username,
          displayName: displayCheck.displayName,
          email: emailCheck.email || `${usernameCheck.username}@entreprise.local`,
          groups: ['Domain Users'],
          whenCreated: mockUsersStore[usernameCheck.username].whenCreated
        }
      });
    }

    try {
      validateLdapConfigOrThrow();
    } catch (e) {
      return resolve({ success: false, error: 'Configuration LDAP invalide.' });
    }

    const ldapUrl = process.env.LDAP_URL;
    const baseDN = process.env.LDAP_BASE_DN;
    const bindDN = process.env.LDAP_BIND_DN;
    const bindPassword = process.env.LDAP_BIND_PASSWORD;
    const userSuffix = process.env.LDAP_USER_SUFFIX || '';
    const usersOU = process.env.LDAP_USERS_OU || `cn=Users,${baseDN}`;

    if (!bindDN || !bindPassword) {
      return resolve({ success: false, error: 'Compte de liaison LDAP non configuré.' });
    }

    const client = ldap.createClient({ url: ldapUrl, timeout: 10000, connectTimeout: 10000 });

    client.on('error', (err) => {
      console.error('[LDAP] Erreur création utilisateur:', err.message);
      client.destroy();
      resolve({ success: false, error: 'Erreur de connexion LDAP.' });
    });

    const formattedBindDN = formatBindDN(bindDN);
    const userDN = `cn=${escapeLdapDnValue(displayCheck.displayName)},${usersOU}`;
    const upn = `${usernameCheck.username}${userSuffix}`;

    client.bind(formattedBindDN, bindPassword, (bindErr) => {
      if (bindErr) {
        console.error('[LDAP] Échec bind pour création:', bindErr.message);
        client.destroy();
        return resolve({ success: false, error: 'Échec de liaison au service LDAP.' });
      }

      const entry = {
        objectClass: ['top', 'person', 'organizationalPerson', 'user'],
        cn: displayCheck.displayName,
        sAMAccountName: usernameCheck.username,
        userPrincipalName: upn,
        displayName: displayCheck.displayName,
        mail: emailCheck.email || upn,
        userAccountControl: 514
      };

      client.add(userDN, entry, (addErr) => {
        if (addErr) {
          console.error('[LDAP] Échec création utilisateur:', addErr.message);
          client.destroy();
          if (addErr.message && addErr.message.includes('ENTRY_ALREADY_EXISTS')) {
            return resolve({ success: false, error: 'Cet utilisateur existe déjà dans l\'annuaire AD.' });
          }
          return resolve({ success: false, error: `Impossible de créer l'utilisateur AD: ${addErr.message}` });
        }

        console.log(`[LDAP] Utilisateur AD créé: ${userDN}`);
        client.destroy();
        resolve({
          success: true,
          user: {
            username: usernameCheck.username,
            displayName: displayCheck.displayName,
            email: emailCheck.email || upn,
            groups: ['Domain Users'],
            whenCreated: new Date().toISOString()
          },
          warning: 'Utilisateur créé. Le mot de passe doit être activé via la console Active Directory (LDAP non sécurisé).'
        });
      });
    });
  });
}

export function updateUser({ username, displayName, email }) {
  return new Promise((resolve) => {
    const usernameCheck = sanitizeUsername(username);
    if (!usernameCheck.valid) {
      return resolve({ success: false, error: usernameCheck.error });
    }
    const displayCheck = sanitizeDisplayName(displayName);
    if (!displayCheck.valid) {
      return resolve({ success: false, error: displayCheck.error });
    }
    const emailCheck = sanitizeEmail(email);
    if (!emailCheck.valid) {
      return resolve({ success: false, error: emailCheck.error });
    }

    if (isMock) {
      const existing = mockUsersStore[usernameCheck.username];
      if (!existing) {
        return resolve({ success: false, error: 'Utilisateur introuvable.' });
      }
      existing.displayName = displayCheck.displayName;
      existing.email = emailCheck.email || existing.email;
      console.log(`[LDAP MOCK] Utilisateur mis à jour: ${usernameCheck.username}`);
      return resolve({ success: true, user: { username: usernameCheck.username, displayName: existing.displayName, email: existing.email, groups: existing.memberOf, whenCreated: existing.whenCreated } });
    }

    try {
      validateLdapConfigOrThrow();
    } catch (e) {
      return resolve({ success: false, error: 'Configuration LDAP invalide.' });
    }

    const ldapUrl = process.env.LDAP_URL;
    const baseDN = process.env.LDAP_BASE_DN;
    const bindDN = process.env.LDAP_BIND_DN;
    const bindPassword = process.env.LDAP_BIND_PASSWORD;
    const userSuffix = process.env.LDAP_USER_SUFFIX || '';

    if (!bindDN || !bindPassword) {
      return resolve({ success: false, error: 'Compte de liaison LDAP non configuré.' });
    }

    const client = ldap.createClient({ url: ldapUrl, timeout: 10000, connectTimeout: 10000 });
    client.on('error', (err) => {
      console.error('[LDAP] Erreur update utilisateur:', err.message);
      client.destroy();
      resolve({ success: false, error: 'Erreur de connexion LDAP.' });
    });

    const formattedBindDN = formatBindDN(bindDN);
    const userPrincipalName = `${usernameCheck.username}${userSuffix}`;
    const searchFilter = `(&(objectClass=user)(|(sAMAccountName=${escapeLdapFilterValue(usernameCheck.username)})(userPrincipalName=${escapeLdapFilterValue(userPrincipalName)})))`;

    client.bind(formattedBindDN, bindPassword, (bindErr) => {
      if (bindErr) {
        console.error('[LDAP] Échec bind service pour update:', bindErr.message);
        client.destroy();
        return resolve({ success: false, error: 'Échec de liaison au service LDAP.' });
      }

      client.search(baseDN, { filter: searchFilter, scope: 'sub', sizeLimit: 1, attributes: ['dn'] }, (searchErr, res) => {
        if (searchErr) {
          console.error('[LDAP] Erreur recherche update:', searchErr.message);
          client.destroy();
          return resolve({ success: false, error: 'Erreur de recherche LDAP.' });
        }

        let entryDN = null;
        res.on('searchEntry', (entry) => { entryDN = entry.dn.toString(); });
        res.on('error', (err) => {
          console.error('[LDAP] Erreur flux recherche update:', err.message);
          client.destroy();
          resolve({ success: false, error: 'Erreur de lecture LDAP.' });
        });
        res.on('end', () => {
          if (!entryDN) {
            client.destroy();
            return resolve({ success: false, error: 'Utilisateur introuvable.' });
          }

          const changes = [];
          if (displayCheck.displayName) {
            changes.push(new ldap.Change({ operation: 'replace', modification: { displayName: displayCheck.displayName } }));
          }
          if (emailCheck.valid) {
            changes.push(new ldap.Change({ operation: 'replace', modification: { mail: emailCheck.email || `${usernameCheck.username}${userSuffix}` } }));
          }

          if (changes.length === 0) {
            client.destroy();
            return resolve({ success: false, error: 'Aucune modification fournie.' });
          }

          client.modify(entryDN, changes, (modifyErr) => {
            if (modifyErr) {
              console.error('[LDAP] Erreur modification utilisateur:', modifyErr.message);
              client.destroy();
              return resolve({ success: false, error: 'Impossible de mettre à jour l\'utilisateur AD.' });
            }
            client.destroy();
            resolve({ success: true, message: 'Utilisateur AD mis à jour.', user: { username: usernameCheck.username, displayName: displayCheck.displayName, email: emailCheck.email || `${usernameCheck.username}${userSuffix}` } });
          });
        });
      });
    });
  });
}

export function deleteUser(username) {
  return new Promise((resolve) => {
    const usernameCheck = sanitizeUsername(username);
    if (!usernameCheck.valid) {
      return resolve({ success: false, error: usernameCheck.error });
    }

    if (isMock) {
      if (!mockUsersStore[usernameCheck.username]) {
        return resolve({ success: false, error: 'Utilisateur introuvable.' });
      }
      delete mockUsersStore[usernameCheck.username];
      console.log(`[LDAP MOCK] Utilisateur supprimé: ${usernameCheck.username}`);
      return resolve({ success: true });
    }

    try {
      validateLdapConfigOrThrow();
    } catch (e) {
      return resolve({ success: false, error: 'Configuration LDAP invalide.' });
    }

    const ldapUrl = process.env.LDAP_URL;
    const baseDN = process.env.LDAP_BASE_DN;
    const bindDN = process.env.LDAP_BIND_DN;
    const bindPassword = process.env.LDAP_BIND_PASSWORD;
    const userSuffix = process.env.LDAP_USER_SUFFIX || '';

    if (!bindDN || !bindPassword) {
      return resolve({ success: false, error: 'Compte de liaison LDAP non configuré.' });
    }

    const client = ldap.createClient({ url: ldapUrl, timeout: 10000, connectTimeout: 10000 });
    client.on('error', (err) => {
      console.error('[LDAP] Erreur suppression utilisateur:', err.message);
      client.destroy();
      resolve({ success: false, error: 'Erreur de connexion LDAP.' });
    });

    const formattedBindDN = formatBindDN(bindDN);
    const userPrincipalName = `${usernameCheck.username}${userSuffix}`;
    const searchFilter = `(&(objectClass=user)(|(sAMAccountName=${escapeLdapFilterValue(usernameCheck.username)})(userPrincipalName=${escapeLdapFilterValue(userPrincipalName)})))`;

    client.bind(formattedBindDN, bindPassword, (bindErr) => {
      if (bindErr) {
        console.error('[LDAP] Échec bind service pour suppression:', bindErr.message);
        client.destroy();
        return resolve({ success: false, error: 'Échec de liaison au service LDAP.' });
      }

      client.search(baseDN, { filter: searchFilter, scope: 'sub', sizeLimit: 1, attributes: ['dn'] }, (searchErr, res) => {
        if (searchErr) {
          console.error('[LDAP] Erreur recherche suppression:', searchErr.message);
          client.destroy();
          return resolve({ success: false, error: 'Erreur de recherche LDAP.' });
        }

        let entryDN = null;
        res.on('searchEntry', (entry) => { entryDN = entry.dn.toString(); });
        res.on('error', (err) => {
          console.error('[LDAP] Erreur flux recherche suppression:', err.message);
          client.destroy();
          resolve({ success: false, error: 'Erreur de lecture LDAP.' });
        });
        res.on('end', () => {
          if (!entryDN) {
            client.destroy();
            return resolve({ success: false, error: 'Utilisateur introuvable.' });
          }

          client.del(entryDN, (delErr) => {
            if (delErr) {
              console.error('[LDAP] Erreur suppression utilisateur:', delErr.message);
              client.destroy();
              return resolve({ success: false, error: 'Impossible de supprimer l\'utilisateur AD.' });
            }
            client.destroy();
            resolve({ success: true });
          });
        });
      });
    });
  });
}

export function findUserByUsername(username) {
  return new Promise((resolve) => {
    const usernameCheck = sanitizeUsername(username);
    const sanitizedUsername = usernameCheck.valid ? usernameCheck.username : String(username || '').trim().toLowerCase();
    
    if (isMock) {
      const user = mockUsersStore[sanitizedUsername];
      if (user) {
        return resolve({
          success: true,
          user: {
            username: sanitizedUsername,
            displayName: user.displayName,
            email: user.email,
            groups: user.memberOf
          }
        });
      } else {
        // Fallback dynamique pour que le SSO fonctionne avec n'importe quel compte Windows de dev
        return resolve({
          success: true,
          user: {
            username: sanitizedUsername,
            displayName: `Windows User (${sanitizedUsername})`,
            email: `${sanitizedUsername}@entreprise.local`,
            groups: ['Domain Users']
          }
        });
      }
    }

    try {
      validateLdapConfigOrThrow();
    } catch (e) {
      return resolve({ success: false, error: 'Configuration LDAP invalide.' });
    }

    const ldapUrl = process.env.LDAP_URL;
    const baseDN = process.env.LDAP_BASE_DN;
    const bindDN = process.env.LDAP_BIND_DN;
    const bindPassword = process.env.LDAP_BIND_PASSWORD;
    const userSuffix = process.env.LDAP_USER_SUFFIX || '';

    if (!bindDN || !bindPassword) {
      return resolve({ success: false, error: 'Compte de liaison LDAP non configuré.' });
    }

    const client = ldap.createClient({
      url: ldapUrl,
      timeout: 5000,
      connectTimeout: 5000
    });

    client.on('error', (err) => {
      console.error('[LDAP] Erreur de connexion lors de la recherche SSO:', err.message);
      client.destroy();
      resolve({ success: false, error: 'Erreur de connexion LDAP.' });
    });

    const formattedBindDN = formatBindDN(bindDN);

    client.bind(formattedBindDN, bindPassword, (bindErr) => {
      if (bindErr) {
        console.error('[LDAP] Échec bind service pour SSO:', bindErr.message);
        client.destroy();
        return resolve({ success: false, error: 'Échec de liaison au service LDAP.' });
      }

      const escaped = escapeLdapFilterValue(sanitizedUsername);
      const filter = `(&(objectClass=user)(|(sAMAccountName=${escaped})(cn=${escaped})))`;

      client.search(baseDN, {
        filter,
        scope: 'sub',
        attributes: ['displayName', 'mail', 'memberOf', 'sAMAccountName', 'cn'],
        sizeLimit: 1
      }, (searchErr, res) => {
        if (searchErr) {
          console.error('[LDAP] Erreur recherche AD SSO:', searchErr.message);
          client.destroy();
          return resolve({ success: false, error: 'Erreur de recherche LDAP.' });
        }

        let userEntry = null;

        res.on('searchEntry', (entry) => {
          userEntry = entry;
        });

        res.on('error', (err) => {
          console.error('[LDAP] Erreur flux recherche AD SSO:', err.message);
          client.destroy();
          resolve({ success: false, error: 'Erreur de lecture LDAP.' });
        });

        res.on('end', () => {
          client.destroy();
          if (!userEntry) {
            return resolve({ success: false, error: 'Utilisateur non trouvé dans l\'annuaire AD.' });
          }
          const obj = getEntryObject(userEntry);
          const userInfo = {
            username: obj.sAMAccountName || obj.samaccountname || sanitizedUsername,
            displayName: obj.displayName || obj.displayname || obj.cn || sanitizedUsername,
            email: obj.mail || `${sanitizedUsername}${userSuffix}`,
            groups: extractGroups(obj.memberOf || obj.memberof)
          };
          resolve({ success: true, user: userInfo });
        });
      });
    });
  });
}