import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { authenticateUser, getAllUsers, findUserByUsername, createUser, updateUser, deleteUser, sanitizeUsername } from './ldap.js';
import { createType2Message, parseType3Message } from './ntlm.js';
import { encrypt, decrypt } from './crypto.js';
import { checkLoginAttempts, recordFailedAttempt, clearLoginAttempts } from './loginAttempts.js';
import { addRegistrationLog, getRegistrationLogs, clearRegistrationLogs } from './registrationLogs.js';
import { logPasswordChange, getPasswordHistory, clearPasswordHistory } from './passwordHistory.js';
import { logAudit, getAuditLogs, clearAuditLogs, AUDIT_ACTIONS } from './auditLog.js';
import { getPolicy, updatePolicy, validatePasswordPolicy, isPasswordExpired } from './passwordPolicy.js';
import * as db from './db.js';

dotenv.config();

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_pour_gestionnaire_de_mots_de_passe_2026';

// ==========================================
// FONCTION DE CALCUL DE FORCE DE MOT DE PASSE
// ==========================================

/**
 * Calcule un score de force pour un mot de passe.
 * @param {string} password - Le mot de passe à évaluer
 * @returns {number} Score de 1 (faible) à 4 (fort)
 */
function calculatePasswordStrength(password) {
  if (!password) return 1;
  
  let score = 0;
  const len = password.length;
  
  // Critère 1 : Longueur
  if (len >= 8) score += 1;
  if (len >= 12) score += 1;
  if (len >= 16) score += 1;
  
  // Critère 2 : Diversité de caractères
  if (/[a-z]/.test(password)) score += 1;  // Minuscules
  if (/[A-Z]/.test(password)) score += 1;  // Majuscules
  if (/[0-9]/.test(password)) score += 1;  // Chiffres
  if (/[^a-zA-Z0-9]/.test(password)) score += 1;  // Symboles
  
  // Pénalités pour patterns courants
  if (/^[a-zA-Z]+$/.test(password)) score -= 1;  // Uniquement des lettres
  if (/^[0-9]+$/.test(password)) score -= 2;  // Uniquement des chiffres
  if (/(.)(\1{2,})/.test(password)) score -= 1;  // Caractères répétés (aaa, 111)
  if (/^(123|abc|password|qwerty|azerty)/i.test(password)) score -= 2;  // Patterns communs
  
  // Normaliser le score sur une échelle de 1 à 4
  if (score <= 2) return 1;  // Faible
  if (score <= 4) return 2;  // Passable
  if (score <= 6) return 3;  // Bon
  return 4;                   // Fort
}

function signToken(user) {
  return jwt.sign(
    {
      username: user.username,
      displayName: user.displayName,
      groups: user.groups || []
    },
    JWT_SECRET,
    { expiresIn: '8h' }
  );
}

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
}

// ==========================================
// MIDDLEWARE DE SÉCURITÉ JWT
// ==========================================
export function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  // Le token est envoyé sous la forme "Bearer TOKEN"
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Accès refusé. Token manquant.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Session expirée ou token invalide. Veuillez vous reconnecter.' });
    }
    req.user = user;
    next();
  });
}

// ==========================================
// ROUTES D'AUTHENTIFICATION
// ==========================================

// Endpoint SSO (Single Sign-On) Active Directory via NTLM ou fallback automatique
router.get('/auth/sso', async (req, res) => {
  // Mode automatique : le frontend envoie ?mock=true pour une connexion SSO sans NTLM
  // Le backend détecte automatiquement l'utilisateur Windows et le recherche dans l'annuaire AD
  if (req.query.mock === 'true') {
    let lookupUsername = req.query.user || process.env.USERNAME || 'ahmed';
    console.log(`[SSO AUTO] Utilisateur Windows PC détecté : ${lookupUsername}`);

    try {
      // Recherche directe de l'utilisateur dans l'annuaire AD / MOCK
      let adResult = await findUserByUsername(lookupUsername);

      // Si l'utilisateur du PC n'est pas trouvé, tenter avec le suffixe domaine
      if (!adResult.success) {
        const userSuffix = process.env.LDAP_USER_SUFFIX || '';
        const suffix = userSuffix.startsWith('@') ? userSuffix : `@${userSuffix}`;
        const usernameWithSuffix = `${lookupUsername}${suffix}`;
        console.log(`[SSO AUTO] Tentative avec suffixe : ${usernameWithSuffix}`);
        adResult = await findUserByUsername(usernameWithSuffix);
      }

      // Dernier recours : utilisateur de secours configuré dans le .env
      if (!adResult.success) {
        const fallbackUser = process.env.SSO_FALLBACK_USER;
        if (fallbackUser) {
          console.log(`[SSO AUTO] Utilisateur '${lookupUsername}' non trouvé. Tentative fallback : ${fallbackUser}`);
          adResult = await findUserByUsername(fallbackUser);
        }
      }

      if (!adResult.success) {
        return res.status(401).json({ error: adResult.error || 'Utilisateur non trouvé dans l\'annuaire Active Directory.' });
      }

      const token = signToken(adResult.user);
      console.log(`[SSO AUTO] ✅ Connexion SSO réussie pour : ${adResult.user.displayName} (${adResult.user.username})`);

      return res.json({
        message: 'Connexion SSO réussie',
        token,
        user: adResult.user
      });
    } catch (e) {
      console.error('[SSO AUTO ERROR] :', e);
      return res.status(500).json({ error: 'Erreur interne lors de la connexion SSO.' });
    }
  }

  const authHeader = req.headers['authorization'] || '';
  
  if (!authHeader) {
    res.setHeader('WWW-Authenticate', 'NTLM');
    return res.status(401).json({ error: 'Authentification NTLM requise.' });
  }
  
  if (!authHeader.startsWith('NTLM ')) {
    res.setHeader('WWW-Authenticate', 'NTLM');
    return res.status(401).json({ error: 'Protocole incorrect. NTLM requis.' });
  }
  
  try {
    const tokenBase64 = authHeader.substring(5);
    const tokenBuf = Buffer.from(tokenBase64, 'base64');
    
    const sig = tokenBuf.toString('ascii', 0, 8);
    if (sig !== 'NTLMSSP\0') {
      res.setHeader('WWW-Authenticate', 'NTLM');
      return res.status(401).json({ error: 'Signature NTLMSSP invalide.' });
    }
    
    const messageType = tokenBuf.readUInt32LE(8);
    
    if (messageType === 1) {
      // Type 1 Message : Negotiate. Le serveur répond avec un challenge Type 2
      const type2Buf = createType2Message();
      res.setHeader('WWW-Authenticate', `NTLM ${type2Buf.toString('base64')}`);
      return res.status(401).json({ error: 'Défi NTLM généré.' });
    }
    
    if (messageType === 3) {
      // Type 3 Message : Authenticate. Le client répond au défi
      const ntlmInfo = parseType3Message(tokenBuf);
      if (!ntlmInfo || !ntlmInfo.username) {
        res.setHeader('WWW-Authenticate', 'NTLM');
        return res.status(401).json({ error: 'Échec de lecture des informations de négociation NTLM.' });
      }
      
      console.log(`[SSO NTLM] Authentification de l'utilisateur AD : ${ntlmInfo.domain}\\${ntlmInfo.username}`);

      let lookupUsername = ntlmInfo.username;

      // Si le nom Windows ne correspond pas directement, tenter avec le suffixe domaine
      let adResult = await findUserByUsername(lookupUsername);
      if (!adResult.success) {
        const userSuffix = process.env.LDAP_USER_SUFFIX || '';
        const suffix = userSuffix.startsWith('@') ? userSuffix : `@${userSuffix}`;
        const usernameWithSuffix = `${lookupUsername}${suffix}`;
        console.log(`[SSO NTLM] Tentative avec suffixe : ${usernameWithSuffix}`);
        adResult = await findUserByUsername(usernameWithSuffix);
      }

      // Dernier recours : utilisateur de secours configuré dans le .env
      if (!adResult.success) {
        const fallbackUser = process.env.SSO_FALLBACK_USER;
        if (fallbackUser) {
          console.log(`[SSO NTLM] Utilisateur '${lookupUsername}' non trouvé. Tentative fallback : ${fallbackUser}`);
          adResult = await findUserByUsername(fallbackUser);
        }
      }

      if (!adResult.success) {
        return res.status(401).json({ error: adResult.error || 'Utilisateur non trouvé dans l\'Active Directory.' });
      }
      
      // Connexion SSO Réussie ! Génération du jeton JWT
      const token = signToken(adResult.user);
      
      return res.json({
        message: 'Connexion SSO réussie',
        token,
        user: adResult.user
      });
    }
    
    res.setHeader('WWW-Authenticate', 'NTLM');
    return res.status(401).json({ error: 'Type de message NTLM non supporté.' });
  } catch (error) {
    console.error('[SSO NTLM ERROR] :', error);
    res.setHeader('WWW-Authenticate', 'NTLM');
    return res.status(500).json({ error: 'Erreur interne du serveur lors de la poignée de main SSO.' });
  }
});

router.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const passwordStr = String(password || '');
  if (!username || !passwordStr) {
    return res.status(400).json({ error: 'Nom d\'utilisateur LDAP et mot de passe requis.' });
  }

  const usernameCheck = sanitizeUsername(username);
  if (!usernameCheck.valid) {
    return res.status(400).json({ error: usernameCheck.error });
  }

  const clientIp = getClientIp(req);
  const attemptCheck = checkLoginAttempts(clientIp, usernameCheck.username);
  if (!attemptCheck.allowed) {
    return res.status(429).json({ error: attemptCheck.error, remainingAttempts: 0 });
  }

  try {
    const authResult = await authenticateUser(usernameCheck.username, passwordStr);

    if (!authResult.success) {
      const failInfo = recordFailedAttempt(clientIp, usernameCheck.username);
      await logAudit({
        action: AUDIT_ACTIONS.LOGIN_FAIL,
        username: usernameCheck.username,
        ip: clientIp,
        success: false,
        details: authResult.error || failInfo.error
      });
      return res.status(401).json({
        error: failInfo.error || authResult.error || 'Authentification échouée.',
        remainingAttempts: failInfo.remaining
      });
    }

    clearLoginAttempts(clientIp, usernameCheck.username);

    await logAudit({
      action: AUDIT_ACTIONS.LOGIN_SUCCESS,
      username: usernameCheck.username,
      ip: clientIp,
      success: true
    });

    const token = signToken(authResult.user);

    res.json({
      message: 'Connexion réussie',
      token,
      user: authResult.user
    });
  } catch (error) {
    console.error('Erreur lors du login :', error);
    res.status(500).json({ error: 'Erreur interne du serveur lors de la connexion.' });
  }
});

// Route optionnelle pour valider la session actuelle
router.get('/auth/me', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// ==========================================
// ROUTES DU COFFRE-FORT (SECURE VIA JWT)
// ==========================================

// Récupérer tous les mots de passe de l'utilisateur (déchiffrés pour l'interface client)
router.get('/vault', authenticateToken, async (req, res) => {
  try {
    const passwords = await db.getUserPasswords(req.user.username);
    
    // Déchiffrement à la volée avant de renvoyer au client
    const decryptedPasswords = passwords.map(item => ({
      id: item.id,
      title: item.title,
      websiteUrl: item.websiteUrl,
      username: item.username,
      // On déchiffre le mot de passe stocké
      password: decrypt(item.encryptedPassword),
      category: item.category,
      notes: item.notes,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt
    }));

    res.json(decryptedPasswords);
  } catch (error) {
    console.error('Erreur de récupération du coffre-fort :', error);
    res.status(500).json({ error: 'Erreur de récupération des mots de passe.' });
  }
});

// ==========================================
// ROUTES DE L'HISTORIQUE DES MOTS DE PASSE
// ==========================================
// IMPORTANT: Ces routes statiques (/vault/history) sont définies AVANT les routes
// paramétrées (/vault/:id) pour qu'Express ne les interprète pas comme un :id.

// Récupérer l'historique des anciens mots de passe (avant changement)
router.get('/vault/history', authenticateToken, async (req, res) => {
  try {
    const history = await getPasswordHistory(req.user.username);
    res.json(history);
  } catch (error) {
    console.error('Erreur de récupération de l\'historique :', error);
    res.status(500).json({ error: 'Impossible de récupérer l\'historique des mots de passe.' });
  }
});

// Effacer tout l'historique de l'utilisateur connecté
router.delete('/vault/history', authenticateToken, async (req, res) => {
  try {
    const deleted = await clearPasswordHistory(req.user.username);
    res.json({ success: true, message: `${deleted} entrée(s) d'historique supprimée(s).` });
  } catch (error) {
    console.error('Erreur de suppression de l\'historique :', error);
    res.status(500).json({ error: 'Impossible de supprimer l\'historique.' });
  }
});

// Ajouter un nouveau mot de passe
router.post('/vault', authenticateToken, async (req, res) => {
  const { title, websiteUrl, username, password, category, notes } = req.body;

  if (!title || !password) {
    return res.status(400).json({ error: 'Le titre et le mot de passe sont obligatoires.' });
  }

  try {
    // Chiffrement du mot de passe
    const encryptedPassword = encrypt(password);

    const newRecord = await db.addPassword(req.user.username, {
      title,
      websiteUrl,
      username,
      encryptedPassword,
      category,
      notes
    });

    const clientIp = getClientIp(req);
    await logAudit({
      action: AUDIT_ACTIONS.VAULT_ADD,
      username: req.user.username,
      ip: clientIp,
      target: title
    });

    res.status(201).json({
      id: newRecord.id,
      title: newRecord.title,
      websiteUrl: newRecord.websiteUrl,
      username: newRecord.username,
      password: password, // Renvoyé en clair pour affichage immédiat
      category: newRecord.category,
      notes: newRecord.notes,
      createdAt: newRecord.createdAt,
      updatedAt: newRecord.updatedAt
    });
  } catch (error) {
    console.error('Erreur d\'ajout du mot de passe :', error);
    res.status(500).json({ error: 'Impossible de sauvegarder le mot de passe.' });
  }
});

// Mettre à jour un mot de passe
router.put('/vault/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { title, websiteUrl, username, password, category, notes } = req.body;

  try {
    // Vérifier d'abord s'il appartient bien à l'utilisateur
    const existing = await db.getPasswordById(id, req.user.username);
    if (!existing) {
      return res.status(404).json({ error: 'Mot de passe non trouvé ou non autorisé.' });
    }

    // 📋 HISTORIQUE : Si le mot de passe change, sauvegarder l'ancien
    if (password !== undefined && existing.encryptedPassword) {
      try {
        const oldPassword = decrypt(existing.encryptedPassword);
        if (oldPassword && !oldPassword.startsWith('🔑')) {
          await logPasswordChange(
            req.user.username,
            id,
            existing.title || 'Sans titre',
            oldPassword,
            req.user.username
          );
          console.log(`[VAULT] Ancien mot de passe de "${existing.title}" sauvegardé dans l'historique.`);
        }
      } catch (histErr) {
        console.warn('[VAULT] Erreur lors de la sauvegarde de l\'historique :', histErr.message);
        // On continue la mise à jour même si l'historique échoue
      }
    }

    const updateData = {};
    if (title !== undefined) updateData.title = title;
    if (websiteUrl !== undefined) updateData.websiteUrl = websiteUrl;
    if (username !== undefined) updateData.username = username;
    if (category !== undefined) updateData.category = category;
    if (notes !== undefined) updateData.notes = notes;
    
    // Si le mot de passe est mis à jour, on le chiffre
    if (password !== undefined) {
      updateData.encryptedPassword = encrypt(password);
    }

    const updatedRecord = await db.updatePassword(id, req.user.username, updateData);
    
    const clientIp = getClientIp(req);
    await logAudit({
      action: AUDIT_ACTIONS.VAULT_UPDATE,
      username: req.user.username,
      ip: clientIp,
      target: updatedRecord.title
    });
    
    res.json({
      id: updatedRecord.id,
      title: updatedRecord.title,
      websiteUrl: updatedRecord.websiteUrl,
      username: updatedRecord.username,
      password: password !== undefined ? password : decrypt(updatedRecord.encryptedPassword),
      category: updatedRecord.category,
      notes: updatedRecord.notes,
      createdAt: updatedRecord.createdAt,
      updatedAt: updatedRecord.updatedAt
    });
  } catch (error) {
    console.error('Erreur de mise à jour du mot de passe :', error);
    res.status(500).json({ error: 'Impossible de mettre à jour le mot de passe.' });
  }
});

// Supprimer un mot de passe
router.delete('/vault/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const deleted = await db.deletePassword(id, req.user.username);
    if (!deleted) {
      return res.status(404).json({ error: 'Mot de passe non trouvé ou non autorisé.' });
    }
    const clientIp = getClientIp(req);
    await logAudit({
      action: AUDIT_ACTIONS.VAULT_DELETE,
      username: req.user.username,
      ip: clientIp,
      target: id
    });
    res.json({ success: true, message: 'Mot de passe supprimé avec succès.' });
  } catch (error) {
    console.error('Erreur de suppression du mot de passe :', error);
    res.status(500).json({ error: 'Impossible de supprimer le mot de passe.' });
  }
});

// ==========================================
// ROUTE DU GÉNÉRATEUR DE MOT DE PASSE SECURISE
// ==========================================
router.post('/passwords/generate', (req, res) => {
  const { 
    length = 16, 
    uppercase = true, 
    lowercase = true, 
    numbers = true, 
    symbols = true, 
    excludeSimilar = false 
  } = req.body;

  try {
    const len = Math.max(8, Math.min(64, parseInt(length) || 16));
    
    let uppercaseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let lowercaseChars = 'abcdefghijklmnopqrstuvwxyz';
    let numberChars = '0123456789';
    let symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (excludeSimilar) {
      // Exclure o, O, 0, i, I, l, 1
      uppercaseChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
      lowercaseChars = 'abcdefghjkmnpqrstuvwxyz';
      numberChars = '23456789';
      symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?'; // les symboles n'ont pas trop de confusion
    }

    let charset = '';
    const activeSets = [];

    if (uppercase) {
      charset += uppercaseChars;
      activeSets.push(uppercaseChars);
    }
    if (lowercase) {
      charset += lowercaseChars;
      activeSets.push(lowercaseChars);
    }
    if (numbers) {
      charset += numberChars;
      activeSets.push(numberChars);
    }
    if (symbols) {
      charset += symbolChars;
      activeSets.push(symbolChars);
    }

    if (charset.length === 0) {
      // Fallback si rien n'est coché
      charset = lowercaseChars + numberChars;
      activeSets.push(lowercaseChars);
      activeSets.push(numberChars);
    }

    let password = '';
    
    // Assurer au moins un caractère de chaque type sélectionné
    activeSets.forEach(set => {
      if (password.length < len) {
        const randIdx = crypto.randomInt(0, set.length);
        password += set[randIdx];
      }
    });

    // Remplir le reste
    while (password.length < len) {
      const randIdx = crypto.randomInt(0, charset.length);
      password += charset[randIdx];
    }

    // Mélanger le mot de passe final de manière cryptographique
    const passwordArray = password.split('');
    for (let i = passwordArray.length - 1; i > 0; i--) {
      const j = crypto.randomInt(0, i + 1);
      [passwordArray[i], passwordArray[j]] = [passwordArray[j], passwordArray[i]];
    }
    
    const finalPassword = passwordArray.join('');
    res.json({ password: finalPassword });
  } catch (error) {
    console.error('Erreur du générateur de mot de passe :', error);
    res.status(500).json({ error: 'Erreur lors de la génération du mot de passe.' });
  }
});

// ==========================================
// MIDDLEWARE DE SÉCURITÉ ADMINISTRATEUR
// ==========================================
function isAdminUser(user) {
  if (!user) return false;

  const adminUsernames = ['admin', 'administrateur', 'administrator'];
  const normalizedUsername = String(user.username || '').toLowerCase();
  if (adminUsernames.includes(normalizedUsername)) {
    return true;
  }

  const adminGroups = [
    'domain admins',
    'it-security',
    'administrateurs du domaine',
    'administrateurs de l\'entreprise',
    'enterprise admins',
    'administrateurs',
    'administrateurs entreprise'
  ];

  const groups = Array.isArray(user.groups) ? user.groups : [];
  return groups.some(g => {
    const normalizedGroup = String(g || '').toLowerCase();
    return adminGroups.some(adminGroup => normalizedGroup.includes(adminGroup));
  });
}

export function requireAdmin(req, res, next) {
  const user = req.user;
  if (!user) {
    return res.status(401).json({ error: 'Non authentifié.' });
  }

  if (!isAdminUser(user)) {
    return res.status(403).json({ error: 'Accès interdit. Réservé aux administrateurs.' });
  }

  next();
}

// ==========================================
// ROUTES D'ADMINISTRATION
// ==========================================

// Liste complète des utilisateurs LDAP/AD
router.get('/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const search = String(req.query.search || '').trim().toLowerCase();
    const result = await getAllUsers();
    if (!result.success) {
      return res.status(500).json({ error: result.error || 'Impossible de lister les utilisateurs.' });
    }

    let users = result.users;
    if (search) {
      users = users.filter((u) => {
        const term = search;
        const fields = [u.username, u.displayName, u.email].map((value) => String(value || '').toLowerCase());
        const groupValues = (u.groups || []).map((g) => String(g || '').toLowerCase());
        return fields.some((value) => value.includes(term)) || groupValues.some((value) => value.includes(term));
      });
    }

    res.json(users);
  } catch (error) {
    console.error('Erreur lors de la récupération des utilisateurs AD :', error);
    res.status(500).json({ error: 'Erreur interne du serveur lors de la récupération des utilisateurs.' });
  }
});

router.put('/admin/users/:username', authenticateToken, requireAdmin, async (req, res) => {
  const username = String(req.params.username || '').trim();
  const { displayName, email } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Nom d\'utilisateur AD requis.' });
  }

  try {
    const result = await updateUser({ username, displayName, email });
    if (!result.success) {
      return res.status(400).json({ error: result.error || 'Impossible de mettre à jour l\'utilisateur.' });
    }
    res.json({ message: result.message || 'Utilisateur mis à jour avec succès.', user: result.user });
  } catch (error) {
    console.error('Erreur lors de la mise à jour de l\'utilisateur AD :', error);
    res.status(500).json({ error: 'Erreur interne du serveur lors de la mise à jour de l\'utilisateur.' });
  }
});

router.delete('/admin/users/:username', authenticateToken, requireAdmin, async (req, res) => {
  const username = String(req.params.username || '').trim();
  if (!username) {
    return res.status(400).json({ error: 'Nom d\'utilisateur AD requis.' });
  }

  try {
    const result = await deleteUser(username);
    if (!result.success) {
      return res.status(400).json({ error: result.error || 'Impossible de supprimer l\'utilisateur.' });
    }
    res.json({ message: `Utilisateur ${username} supprimé avec succès.` });
  } catch (error) {
    console.error('Erreur lors de la suppression de l\'utilisateur AD :', error);
    res.status(500).json({ error: 'Erreur interne du serveur lors de la suppression de l\'utilisateur.' });
  }
});

// Créer un utilisateur Active Directory (admin uniquement)
router.post('/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  const { username, displayName, email, password } = req.body;

  if (!username || !displayName || !password) {
    return res.status(400).json({ error: 'Identifiant, nom d\'affichage et mot de passe sont obligatoires.' });
  }

  try {
    const result = await createUser({ username, displayName, email, password });
    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    res.status(201).json({
      message: result.warning || 'Utilisateur créé avec succès.',
      user: result.user,
      warning: result.warning || null
    });
  } catch (error) {
    console.error('Erreur lors de la création utilisateur AD :', error);
    res.status(500).json({ error: 'Erreur interne lors de la création de l\'utilisateur.' });
  }
});

// Tableau de bord de statistiques de sécurité globales
router.get('/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const allPasswords = await db.getAllPasswordsForStats();
    
    let totalLength = 0;
    let extremelyWeakCount = 0; // < 8 caractères
    let lastModified = null;
    const strengthCounts = { 1: 0, 2: 0, 3: 0, 4: 0 };
    const userCounts = {};
    const categoryCounts = {};
    const plaintextCounts = {}; // Pour identifier les doublons
    
    // Déchiffrement temporaire en mémoire pour statistiques
    allPasswords.forEach(p => {
      const decrypted = decrypt(p.encryptedPassword);
      
      // Longueur
      const len = decrypted.length;
      totalLength += len;
      if (len < 8) extremelyWeakCount++;
      
      // Force
      const strength = calculatePasswordStrength(decrypted);
      strengthCounts[strength] = (strengthCounts[strength] || 0) + 1;
      
      // Utilisateurs
      const owner = p.owner.toLowerCase();
      userCounts[owner] = (userCounts[owner] || 0) + 1;
      
      // Catégories
      const category = p.category || 'Général';
      categoryCounts[category] = (categoryCounts[category] || 0) + 1;

      // Dernière modification enregistrée
      const modifiedAt = p.updatedAt || p.createdAt || null;
      if (modifiedAt && (!lastModified || new Date(modifiedAt) > new Date(lastModified))) {
        lastModified = modifiedAt;
      }
      
      // Doublons (réutilisation de mot de passe)
      if (decrypted) {
        plaintextCounts[decrypted] = (plaintextCounts[decrypted] || 0) + 1;
      }
    });

    // Calcul des doublons / réutilisations
    let duplicatedCount = 0;
    Object.values(plaintextCounts).forEach(count => {
      if (count > 1) {
        duplicatedCount += count;
      }
    });

    const totalCount = allPasswords.length;
    const avgLength = totalCount > 0 ? parseFloat((totalLength / totalCount).toFixed(1)) : 0;

    res.json({
      totalPasswords: totalCount,
      avgLength,
      extremelyWeak: extremelyWeakCount,
      reusedPasswords: duplicatedCount,
      strengthDistribution: {
        weak: strengthCounts[1],
        fair: strengthCounts[2],
        good: strengthCounts[3],
        strong: strengthCounts[4]
      },
      userDistribution: userCounts,
      categoryDistribution: categoryCounts,
      lastModified
    });
  } catch (error) {
    console.error('Erreur lors de la génération des statistiques :', error);
    res.status(500).json({ error: 'Erreur interne du serveur lors du calcul des statistiques.' });
  }
});

// ==========================================
// ROUTES DES LOGS D'ENREGISTREMENT TEMPORAIRES
// ==========================================

// Recuperer les logs temporaires d'enregistrement
router.get('/registration-logs', authenticateToken, async (req, res) => {
  try {
    const logs = await getRegistrationLogs();
    res.json(logs);
  } catch (error) {
    console.error('Erreur de recuperation des logs d\'enregistrement :', error);
    res.status(500).json({ error: 'Impossible de recuperer les logs.' });
  }
});

// Ajouter un nouveau log temporaire d'enregistrement
router.post('/registration-logs', authenticateToken, async (req, res) => {
  try {
    const log = await addRegistrationLog(req.body);
    res.status(201).json(log);
  } catch (error) {
    console.error('Erreur d\'ajout de log d\'enregistrement :', error);
    res.status(500).json({ error: 'Impossible d\'ajouter le log.' });
  }
});

// Supprimer tous les logs temporaires d'enregistrement
router.delete('/registration-logs', authenticateToken, async (req, res) => {
  try {
    await clearRegistrationLogs();
    res.json({ success: true, message: 'Logs supprimes avec succes.' });
  } catch (error) {
    console.error('Erreur de suppression des logs d\'enregistrement :', error);
    res.status(500).json({ error: 'Impossible de supprimer les logs.' });
  }
});

// ==========================================
// IMPORT / EXPORT DU COFFRE-FORT
// ==========================================

/**
 * Convertit une liste de mots de passe déchiffrés en CSV.
 * Colonnes : title, url, username, password, category, notes
 */
function passwordsToCsv(passwords) {
  const header = ['title', 'url', 'username', 'password', 'category', 'notes'];
  const escape = (v) => `"${String(v || '').replace(/"/g, '""')}"`;
  const rows = passwords.map(p =>
    [p.title, p.websiteUrl, p.username, p.password, p.category, p.notes].map(escape).join(',')
  );
  return [header.join(','), ...rows].join('\r\n');
}

/**
 * Convertit une liste de mots de passe déchiffrés au format JSON Bitwarden.
 * Compatible avec l'import dans Bitwarden, 1Password (via CSV), etc.
 */
function passwordsToBitwarden(passwords) {
  return JSON.stringify({
    encrypted: false,
    folders: [],
    items: passwords.map(p => ({
      type: 1,
      name: p.title || 'Sans titre',
      notes: p.notes || null,
      login: {
        username: p.username || '',
        password: p.password || '',
        uris: p.websiteUrl ? [{ match: null, uri: p.websiteUrl }] : []
      },
      fields: p.category ? [{ name: 'category', value: p.category, type: 0 }] : []
    }))
  }, null, 2);
}

/**
 * Parse un CSV de mots de passe (format SecurPass ou Chrome/Firefox/Edge).
 * Détecte automatiquement les colonnes par leur en-tête.
 */
function parseCsv(content) {
  const lines = content.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n').filter(l => l.trim());
  if (lines.length < 2) throw new Error('CSV vide ou sans données.');

  const parseRow = (line) => {
    const result = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') { current += '"'; i++; }
        else { inQuotes = !inQuotes; }
      } else if (ch === ',' && !inQuotes) {
        result.push(current); current = '';
      } else {
        current += ch;
      }
    }
    result.push(current);
    return result;
  };

  const headers = parseRow(lines[0]).map(h => h.toLowerCase().trim());

  // Mapping flexible des colonnes (Chrome, Firefox, Edge, SecurPass)
  const col = (names) => {
    for (const n of names) { const i = headers.indexOf(n); if (i !== -1) return i; }
    return -1;
  };

  const iTitle    = col(['title', 'name', 'nom']);
  const iUrl      = col(['url', 'websiteurl', 'website', 'web site']);
  const iUsername = col(['username', 'login', 'identifiant', 'user']);
  const iPassword = col(['password', 'mot de passe', 'pass']);
  const iCategory = col(['category', 'catégorie', 'folder', 'groupe']);
  const iNotes    = col(['notes', 'note', 'commentaire', 'extra']);

  if (iPassword === -1) throw new Error('Colonne "password" introuvable dans le CSV.');

  return lines.slice(1).map(line => {
    const cells = parseRow(line);
    return {
      title:      iTitle    >= 0 ? cells[iTitle]    || 'Import' : 'Import',
      websiteUrl: iUrl      >= 0 ? cells[iUrl]      || ''       : '',
      username:   iUsername >= 0 ? cells[iUsername] || ''       : '',
      password:   cells[iPassword] || '',
      category:   iCategory >= 0 ? cells[iCategory] || 'Général' : 'Général',
      notes:      iNotes    >= 0 ? cells[iNotes]    || ''       : ''
    };
  }).filter(e => e.password.trim());
}

/**
 * Parse un export JSON Bitwarden.
 */
function parseBitwarden(content) {
  const data = JSON.parse(content);
  const items = Array.isArray(data.items) ? data.items : [];
  return items
    .filter(item => item.type === 1 && item.login)
    .map(item => ({
      title:      item.name || 'Import Bitwarden',
      websiteUrl: item.login.uris?.[0]?.uri || '',
      username:   item.login.username || '',
      password:   item.login.password || '',
      category:   item.fields?.find(f => f.name === 'category')?.value || 'Général',
      notes:      item.notes || ''
    }))
    .filter(e => e.password.trim());
}

// ---- EXPORT CSV ----
router.get('/vault/export/csv', authenticateToken, async (req, res) => {
  try {
    const passwords = await db.getUserPasswords(req.user.username);
    const decrypted = passwords.map(p => ({ ...p, password: decrypt(p.encryptedPassword) }));
    const csv = passwordsToCsv(decrypted);
    const filename = `securpass_export_${req.user.username}_${Date.now()}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send('\uFEFF' + csv); // BOM UTF-8 pour Excel
  } catch (error) {
    console.error('[EXPORT CSV]', error);
    res.status(500).json({ error: 'Erreur lors de l\'export CSV.' });
  }
});

// ---- EXPORT JSON BITWARDEN ----
router.get('/vault/export/json', authenticateToken, async (req, res) => {
  try {
    const passwords = await db.getUserPasswords(req.user.username);
    const decrypted = passwords.map(p => ({ ...p, password: decrypt(p.encryptedPassword) }));
    const json = passwordsToBitwarden(decrypted);
    const filename = `securpass_bitwarden_${req.user.username}_${Date.now()}.json`;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(json);
  } catch (error) {
    console.error('[EXPORT JSON]', error);
    res.status(500).json({ error: 'Erreur lors de l\'export JSON.' });
  }
});

// ---- IMPORT (CSV ou JSON Bitwarden) ----
// Reçoit le fichier texte brut dans le body (Content-Type: text/plain ou application/json)
// avec le header X-Import-Format: csv | bitwarden
router.post('/vault/import', authenticateToken, async (req, res) => {
  try {
    const format = (req.headers['x-import-format'] || 'csv').toLowerCase();
    const raw = req.body;

    if (!raw || typeof raw !== 'string' || raw.trim().length === 0) {
      return res.status(400).json({ error: 'Corps de la requête vide. Envoyez le contenu du fichier en texte brut.' });
    }

    let entries = [];
    if (format === 'bitwarden') {
      entries = parseBitwarden(raw);
    } else {
      entries = parseCsv(raw);
    }

    if (entries.length === 0) {
      return res.status(400).json({ error: 'Aucune entrée valide trouvée dans le fichier.' });
    }

    const results = { imported: 0, skipped: 0, errors: [] };

    for (const entry of entries) {
      try {
        if (!entry.password) { results.skipped++; continue; }
        await db.addPassword(req.user.username, {
          title:             entry.title      || 'Import',
          websiteUrl:        entry.websiteUrl || '',
          username:          entry.username   || '',
          encryptedPassword: encrypt(entry.password),
          category:          entry.category   || 'Général',
          notes:             entry.notes      || ''
        });
        results.imported++;
      } catch (e) {
        results.errors.push(entry.title || 'Sans titre');
      }
    }

    res.json({
      success: true,
      imported: results.imported,
      skipped:  results.skipped,
      errors:   results.errors,
      message:  `${results.imported} mot(s) de passe importé(s) avec succès.`
    });
  } catch (error) {
    console.error('[IMPORT]', error);
    res.status(400).json({ error: `Erreur de parsing : ${error.message}` });
  }
});

// ==========================================
// PARTAGE DE MOTS DE PASSE ENTRE UTILISATEURS
// ==========================================

// Partager un mot de passe avec un autre utilisateur AD
// POST /api/vault/:id/share
// Body : { sharedWith, permission, expiresInDays }
router.post('/vault/:id/share', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { sharedWith, permission = 'read', expiresInDays } = req.body;

  if (!sharedWith) {
    return res.status(400).json({ error: 'Le destinataire (sharedWith) est requis.' });
  }

  const sharedWithCheck = sanitizeUsername(sharedWith);
  if (!sharedWithCheck.valid) {
    return res.status(400).json({ error: sharedWithCheck.error });
  }

  if (sharedWithCheck.username === req.user.username.toLowerCase()) {
    return res.status(400).json({ error: 'Vous ne pouvez pas partager un mot de passe avec vous-même.' });
  }

  if (!['read', 'write'].includes(permission)) {
    return res.status(400).json({ error: 'Permission invalide. Valeurs acceptées : read, write.' });
  }

  try {
    // Vérifier que le mot de passe appartient à l'utilisateur
    const existing = await db.getPasswordById(id, req.user.username);
    if (!existing) {
      return res.status(404).json({ error: 'Mot de passe non trouvé ou non autorisé.' });
    }

    // Calculer la date d'expiration
    let expiresAt = null;
    if (expiresInDays && parseInt(expiresInDays) > 0) {
      expiresAt = new Date(Date.now() + parseInt(expiresInDays) * 24 * 60 * 60 * 1000);
    }

    // Note: dans cette implémentation simplifiée, on stocke un marqueur.
    // Pour du chiffrement E2E complet, il faudrait la clé publique RSA du destinataire.
    // On utilise ici une clé dérivée côté serveur (acceptable pour un usage interne entreprise).
    const shareToken = crypto.randomBytes(32).toString('hex');

    const share = await db.sharePassword({
      passwordId:   id,
      sharedBy:     req.user.username,
      sharedWith:   sharedWithCheck.username,
      permission,
      encryptedKey: shareToken, // clé de partage (à remplacer par RSA pour E2E)
      expiresAt
    });

    console.log(`[SHARE] ${req.user.username} → ${sharedWithCheck.username} : "${existing.title}" (${permission})`);

    const clientIp = getClientIp(req);
    await logAudit({
      action: AUDIT_ACTIONS.SHARE_CREATE,
      username: req.user.username,
      ip: clientIp,
      target: existing.title,
      details: `shared_with:${sharedWithCheck.username}`
    });

    res.status(201).json({
      success: true,
      message: `Mot de passe partagé avec ${sharedWithCheck.username}.`,
      share: {
        id:          share.id,
        sharedWith:  sharedWithCheck.username,
        permission,
        expiresAt:   expiresAt || null
      }
    });
  } catch (error) {
    console.error('[SHARE POST]', error);
    res.status(500).json({ error: 'Erreur lors du partage.' });
  }
});

// Voir les partages d'un mot de passe (qui a accès)
// GET /api/vault/:id/shares
router.get('/vault/:id/shares', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const existing = await db.getPasswordById(id, req.user.username);
    if (!existing) {
      return res.status(404).json({ error: 'Mot de passe non trouvé ou non autorisé.' });
    }
    const shares = await db.getSharesForPassword(id);
    res.json(shares.map(s => ({
      id:         s.id,
      sharedWith: s.sharedWith,
      permission: s.permission,
      expiresAt:  s.expiresAt,
      createdAt:  s.createdAt
    })));
  } catch (error) {
    console.error('[SHARES GET]', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des partages.' });
  }
});

// Révoquer un partage
// DELETE /api/vault/:id/share/:username
router.delete('/vault/:id/share/:sharedWith', authenticateToken, async (req, res) => {
  const { id, sharedWith } = req.params;
  try {
    const revoked = await db.revokeShare(id, sharedWith, req.user.username);
    if (!revoked) {
      return res.status(404).json({ error: 'Partage non trouvé ou vous n\'êtes pas autorisé à le révoquer.' });
    }
    const clientIp = getClientIp(req);
    await logAudit({
      action: AUDIT_ACTIONS.SHARE_REVOKE,
      username: req.user.username,
      ip: clientIp,
      target: sharedWith
    });
    res.json({ success: true, message: `Accès de ${sharedWith} révoqué.` });
  } catch (error) {
    console.error('[SHARE DELETE]', error);
    res.status(500).json({ error: 'Erreur lors de la révocation.' });
  }
});

// Mots de passe partagés avec l'utilisateur connecté
// GET /api/vault/shared-with-me
router.get('/vault/shared-with-me', authenticateToken, async (req, res) => {
  try {
    const shared = await db.getPasswordsSharedWithMe(req.user.username);
    const result = shared.map(item => ({
      shareId:     item.shareId,
      permission:  item.permission,
      sharedBy:    item.sharedBy,
      expiresAt:   item.expiresAt,
      id:          item.id,
      title:       item.title,
      websiteUrl:  item.websiteUrl,
      username:    item.username,
      password:    decrypt(item.encryptedPassword),
      category:    item.category,
      notes:       item.notes,
      createdAt:   item.createdAt,
      updatedAt:   item.updatedAt
    }));
    res.json(result);
  } catch (error) {
    console.error('[SHARED-WITH-ME]', error);
    res.status(500).json({ error: 'Erreur lors de la récupération des mots de passe partagés.' });
  }
});

// ==========================================
// TOTP 2FA HELPERS & ENDPOINTS
// ==========================================

function generateBase32Secret(length = 20) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = crypto.randomBytes(length);
  let secret = '';
  for (let i = 0; i < length; i++) {
    secret += chars[bytes[i] % chars.length];
  }
  return secret;
}

function base32ToBuffer(base32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (let i = 0; i < base32.length; i++) {
    const val = chars.indexOf(base32[i].toUpperCase());
    if (val >= 0) bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substr(i, 8), 2));
  }
  return Buffer.from(bytes);
}

function generateTOTP(secretBase32, timeStepWindow = 0) {
  const key = base32ToBuffer(secretBase32);
  const epoch = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epoch / 30) + timeStepWindow;
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24 | (hmac[offset + 1] & 0xff) << 16 | (hmac[offset + 2] & 0xff) << 8 | (hmac[offset + 3] & 0xff)) % 1000000;
  return String(code).padStart(6, '0');
}

function verifyTOTP(secretBase32, code) {
  if (!secretBase32 || !code) return false;
  for (let window = -1; window <= 1; window++) {
    if (generateTOTP(secretBase32, window) === String(code).trim()) {
      return true;
    }
  }
  return false;
}

// POST /api/auth/totp/setup
router.post('/auth/totp/setup', authenticateToken, async (req, res) => {
  try {
    const secret = generateBase32Secret(20);
    await db.saveUserTotpSecret(req.user.username, secret);

    const otpauthUrl = `otpauth://totp/SecurPass:${encodeURIComponent(req.user.username)}?secret=${secret}&issuer=SecurPass`;

    await logAudit({
      action: AUDIT_ACTIONS.TOTP_SETUP,
      username: req.user.username,
      ip: getClientIp(req)
    });

    res.json({ secret, otpauthUrl });
  } catch (err) {
    console.error('[TOTP SETUP ERROR]', err);
    res.status(500).json({ error: 'Erreur lors de la configuration TOTP.' });
  }
});

// POST /api/auth/totp/verify
router.post('/auth/totp/verify', authenticateToken, async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: 'Code TOTP requis.' });
    }

    const secret = await db.getUserTotpSecret(req.user.username);
    if (!secret) {
      return res.status(400).json({ error: 'TOTP non configuré pour cet utilisateur.' });
    }

    const valid = verifyTOTP(secret, token);

    await logAudit({
      action: AUDIT_ACTIONS.TOTP_VERIFY,
      username: req.user.username,
      ip: getClientIp(req),
      success: valid
    });

    if (valid) {
      res.json({ success: true, message: 'Code 2FA TOTP validé avec succès.' });
    } else {
      res.status(400).json({ success: false, error: 'Code 2FA invalide ou expiré.' });
    }
  } catch (err) {
    console.error('[TOTP VERIFY ERROR]', err);
    res.status(500).json({ error: 'Erreur lors de la vérification TOTP.' });
  }
});

// ==========================================
// SCORE DE SÉCURITÉ & ANALYSE DU COFFRE
// ==========================================

// GET /api/vault/security-score
router.get('/vault/security-score', authenticateToken, async (req, res) => {
  try {
    const passwords = await db.getUserPasswords(req.user.username);
    const policy = await getPolicy();

    let total = passwords.length;
    let weakCount = 0;
    let reusedCount = 0;
    let expiredCount = 0;

    const passwordCounts = {};
    const vulnerableItems = [];

    for (const item of passwords) {
      let rawPwd = '';
      try {
        rawPwd = decrypt(item.encryptedPassword);
      } catch {
        rawPwd = '';
      }

      if (rawPwd) {
        passwordCounts[rawPwd] = (passwordCounts[rawPwd] || 0) + 1;
      }

      const issues = [];
      const strength = calculatePasswordStrength(rawPwd);
      if (strength <= 2) {
        weakCount++;
        issues.push('Mot de passe faible (complexité insuffisante)');
      }

      const daysOld = Math.floor((Date.now() - new Date(item.updatedAt || item.createdAt).getTime()) / (1000 * 3600 * 24));
      if (policy.maxAgeDays > 0 && daysOld > policy.maxAgeDays) {
        expiredCount++;
        issues.push(`Mot de passe plus ancien que la limite (${daysOld} jours, max: ${policy.maxAgeDays}j)`);
      }

      if (issues.length > 0) {
        vulnerableItems.push({
          id: item.id,
          title: item.title,
          username: item.username,
          issues
        });
      }
    }

    for (const item of passwords) {
      let rawPwd = '';
      try { rawPwd = decrypt(item.encryptedPassword); } catch {}
      if (rawPwd && passwordCounts[rawPwd] > 1) {
        reusedCount++;
        const vuln = vulnerableItems.find(v => v.id === item.id);
        if (vuln) {
          if (!vuln.issues.includes('Mot de passe réutilisé dans plusieurs comptes')) {
            vuln.issues.push('Mot de passe réutilisé dans plusieurs comptes');
          }
        } else {
          vulnerableItems.push({
            id: item.id,
            title: item.title,
            username: item.username,
            issues: ['Mot de passe réutilisé dans plusieurs comptes']
          });
        }
      }
    }

    let score = 100;
    if (total > 0) {
      const penaltyWeak = (weakCount / total) * 40;
      const penaltyReused = (reusedCount / total) * 35;
      const penaltyExpired = (expiredCount / total) * 25;
      score = Math.max(0, Math.round(100 - (penaltyWeak + penaltyReused + penaltyExpired)));
    }

    res.json({
      overallScore: score,
      metrics: {
        total,
        weakCount,
        reusedCount,
        expiredCount
      },
      vulnerableItems
    });
  } catch (err) {
    console.error('[SECURITY SCORE ERROR]', err);
    res.status(500).json({ error: 'Erreur lors du calcul du score de sécurité.' });
  }
});

// POST /api/vault/export/encrypted
router.post('/vault/export/encrypted', authenticateToken, async (req, res) => {
  try {
    const { exportPassword } = req.body;
    if (!exportPassword || exportPassword.length < 4) {
      return res.status(400).json({ error: 'Un mot de passe d\'export d\'au moins 4 caractères est requis.' });
    }

    const passwords = await db.getUserPasswords(req.user.username);
    const exportData = passwords.map(item => {
      let raw = '';
      try { raw = decrypt(item.encryptedPassword); } catch {}
      return {
        title: item.title,
        websiteUrl: item.websiteUrl,
        username: item.username,
        password: raw,
        category: item.category,
        notes: item.notes,
        createdAt: item.createdAt,
        updatedAt: item.updatedAt
      };
    });

    const jsonText = JSON.stringify(exportData, null, 2);

    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(exportPassword, salt, 100000, 32, 'sha256');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let encrypted = cipher.update(jsonText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    const payload = {
      version: 1,
      algorithm: 'aes-256-gcm',
      kdf: 'pbkdf2',
      iterations: 100000,
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      data: encrypted
    };

    await logAudit({
      action: AUDIT_ACTIONS.VAULT_EXPORT_ENC,
      username: req.user.username,
      ip: getClientIp(req),
      target: `${passwords.length} mots de passe`
    });

    res.json({
      filename: `securpass_export_${req.user.username}_${Date.now()}.enc`,
      payload
    });
  } catch (err) {
    console.error('[EXPORT ENC ERROR]', err);
    res.status(500).json({ error: 'Erreur lors de l\'export chiffré.' });
  }
});

// GET /api/hibp/check
router.get('/hibp/check', authenticateToken, async (req, res) => {
  try {
    const { password } = req.query;
    if (!password) {
      return res.status(400).json({ error: 'Mot de passe requis.' });
    }

    const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);

    await logAudit({
      action: AUDIT_ACTIONS.HIBP_CHECK,
      username: req.user.username,
      ip: getClientIp(req)
    });

    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'User-Agent': 'SecurPass-PasswordManager' }
    });

    if (!response.ok) {
      return res.json({ breached: false, count: 0, warning: 'Service HIBP temporairement indisponible' });
    }

    const bodyText = await response.text();
    const lines = bodyText.split('\n');
    let matchCount = 0;

    for (const line of lines) {
      const [lineSuffix, countStr] = line.trim().split(':');
      if (lineSuffix === suffix) {
        matchCount = parseInt(countStr, 10) || 0;
        break;
      }
    }

    res.json({
      breached: matchCount > 0,
      count: matchCount,
      hashPrefix: prefix
    });
  } catch (err) {
    console.error('[HIBP ERROR]', err.message);
    res.json({ breached: false, count: 0, error: 'Erreur lors de la vérification HIBP' });
  }
});

// GET /api/audit/logs
router.get('/audit/logs', authenticateToken, async (req, res) => {
  try {
    const isAdmin = req.user.username.toLowerCase() === 'admin' ||
      (Array.isArray(req.user.groups) && req.user.groups.some(g => g.toLowerCase().includes('admin')));

    if (!isAdmin) {
      return res.status(403).json({ error: 'Accès refusé. Droits d\'administration requis.' });
    }

    const { username, action, success, limit, offset } = req.query;
    const logs = await getAuditLogs({
      username: username || null,
      action: action || null,
      success: success === 'true' ? true : success === 'false' ? false : null,
      limit: parseInt(limit) || 100,
      offset: parseInt(offset) || 0
    });

    res.json(logs);
  } catch (err) {
    console.error('[AUDIT GET ERROR]', err);
    res.status(500).json({ error: 'Erreur lors de la récupération des journaux d\'audit.' });
  }
});

// GET /api/admin/policy & PUT /api/admin/policy
router.get('/admin/policy', authenticateToken, async (req, res) => {
  try {
    const policy = await getPolicy();
    res.json(policy);
  } catch (err) {
    res.status(500).json({ error: 'Erreur de lecture de la politique.' });
  }
});

router.put('/admin/policy', authenticateToken, async (req, res) => {
  try {
    const isAdmin = req.user.username.toLowerCase() === 'admin' ||
      (Array.isArray(req.user.groups) && req.user.groups.some(g => g.toLowerCase().includes('admin')));

    if (!isAdmin) {
      return res.status(403).json({ error: 'Accès refusé. Droits d\'administration requis.' });
    }

    const updated = await updatePolicy(req.body, req.user.username);
    await logAudit({
      action: AUDIT_ACTIONS.ADMIN_POLICY_UPDATE,
      username: req.user.username,
      ip: getClientIp(req),
      details: JSON.stringify(req.body)
    });

    res.json({ message: 'Politique mise à jour avec succès.', policy: updated });
  } catch (err) {
    res.status(500).json({ error: 'Erreur lors de la mise à jour de la politique.' });
  }
});

export default router;


