import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

// ============================================================
// JOURNAL D'AUDIT — auditLog.js
// ============================================================
// Enregistre toutes les actions sensibles (connexion, export,
// partage, suppression, modification admin, etc.) avec horodatage,
// IP et utilisateur. Persisté dans data/audit_log.json.
// ============================================================

const LOG_FILE   = path.join(process.cwd(), 'data', 'audit_log.json');
const MAX_ENTRIES = 10000; // Garder les 10 000 dernières entrées

let logCache = null;

async function ensureDataDir() {
  await fs.mkdir(path.dirname(LOG_FILE), { recursive: true });
}

async function loadLog() {
  if (logCache !== null) return logCache;
  await ensureDataDir();
  try {
    const content = await fs.readFile(LOG_FILE, 'utf8');
    logCache = JSON.parse(content);
    if (!Array.isArray(logCache)) logCache = [];
  } catch {
    logCache = [];
  }
  return logCache;
}

async function saveLog() {
  try {
    await ensureDataDir();
    // Tronquer si on dépasse la limite
    if (logCache.length > MAX_ENTRIES) {
      logCache = logCache.slice(0, MAX_ENTRIES);
    }
    await fs.writeFile(LOG_FILE, JSON.stringify(logCache, null, 2), 'utf8');
  } catch (err) {
    console.error('[AUDIT] Erreur de sauvegarde :', err.message);
  }
}

// ============================================================
// TYPES D'ACTIONS DISPONIBLES
// ============================================================
export const AUDIT_ACTIONS = {
  // Authentification
  LOGIN_SUCCESS:     'auth.login.success',
  LOGIN_FAIL:        'auth.login.fail',
  LOGIN_LOCKED:      'auth.login.locked',
  LOGOUT:            'auth.logout',
  SSO_SUCCESS:       'auth.sso.success',
  SSO_FAIL:          'auth.sso.fail',

  // Coffre-fort
  VAULT_ADD:         'vault.add',
  VAULT_UPDATE:      'vault.update',
  VAULT_DELETE:      'vault.delete',
  VAULT_EXPORT_CSV:  'vault.export.csv',
  VAULT_EXPORT_JSON: 'vault.export.json',
  VAULT_EXPORT_ENC:  'vault.export.encrypted',
  VAULT_IMPORT:      'vault.import',

  // Partage
  SHARE_CREATE:      'share.create',
  SHARE_REVOKE:      'share.revoke',

  // Administration
  ADMIN_USER_CREATE: 'admin.user.create',
  ADMIN_USER_UPDATE: 'admin.user.update',
  ADMIN_USER_DELETE: 'admin.user.delete',
  ADMIN_POLICY_UPDATE: 'admin.policy.update',
  ADMIN_AUDIT_CLEAR: 'admin.audit.clear',

  // Sécurité
  HIBP_CHECK:        'security.hibp.check',
  TOTP_SETUP:        'security.totp.setup',
  TOTP_VERIFY:       'security.totp.verify',
};

// ============================================================
// API PUBLIQUE
// ============================================================

/**
 * Enregistre une action dans le journal d'audit.
 *
 * @param {Object} options
 * @param {string}  options.action   - Type d'action (utiliser AUDIT_ACTIONS)
 * @param {string}  options.username - Utilisateur ayant effectué l'action
 * @param {string}  [options.ip]     - Adresse IP du client
 * @param {string}  [options.target] - Ressource cible (titre du MDP, nom d'utilisateur, etc.)
 * @param {string}  [options.details]- Détails supplémentaires
 * @param {boolean} [options.success=true] - Succès ou échec de l'action
 * @returns {Promise<Object>} L'entrée créée
 */
export async function logAudit({ action, username, ip, target = null, details = null, success = true }) {
  await loadLog();

  const entry = {
    id:        crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    action,
    username:  (username || 'anonymous').toLowerCase(),
    ip:        ip || 'unknown',
    target,
    details,
    success
  };

  logCache.unshift(entry); // Plus récent en premier

  // Sauvegarde asynchrone sans bloquer la réponse
  saveLog().catch(err => console.error('[AUDIT] Erreur save:', err));

  return entry;
}

/**
 * Récupère les entrées du journal d'audit avec filtres et pagination.
 *
 * @param {Object} [options]
 * @param {string}  [options.username] - Filtrer par utilisateur
 * @param {string}  [options.action]   - Filtrer par préfixe d'action (ex: 'auth', 'vault')
 * @param {boolean} [options.success]  - Filtrer par succès (true/false/null)
 * @param {number}  [options.limit=100]  - Nombre max d'entrées
 * @param {number}  [options.offset=0]   - Décalage pour pagination
 * @returns {Promise<{entries: Array, total: number, limit: number, offset: number}>}
 */
export async function getAuditLogs({ username = null, action = null, success = null, limit = 100, offset = 0 } = {}) {
  await loadLog();

  let filtered = logCache;

  if (username) {
    filtered = filtered.filter(e => e.username === username.toLowerCase());
  }
  if (action) {
    filtered = filtered.filter(e => e.action.startsWith(action));
  }
  if (success !== null && success !== undefined) {
    filtered = filtered.filter(e => e.success === success);
  }

  const total = filtered.length;
  const entries = filtered.slice(offset, offset + limit);

  return { entries, total, limit, offset };
}

/**
 * Efface tout le journal d'audit (réservé aux admins).
 * @returns {Promise<number>} Nombre d'entrées supprimées
 */
export async function clearAuditLogs() {
  await loadLog();
  const count = logCache.length;
  logCache = [];
  await saveLog();
  return count;
}
