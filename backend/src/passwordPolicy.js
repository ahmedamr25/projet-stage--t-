import fs from 'fs/promises';
import path from 'path';

// ============================================================
// POLITIQUE DES MOTS DE PASSE — passwordPolicy.js
// ============================================================
// Définit et applique les règles de complexité et de rotation
// des mots de passe pour l'ensemble des utilisateurs.
// Persistée dans data/password_policy.json.
// ============================================================

const POLICY_FILE = path.join(process.cwd(), 'data', 'password_policy.json');

/** Politique par défaut appliquée si aucun fichier n'existe. */
export const DEFAULT_POLICY = {
  // Complexité
  minLength:        8,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers:   true,
  requireSymbols:   false,
  // Rotation
  maxAgeDays:       90,  // 0 = pas d'expiration
  // Réutilisation
  preventReuse:     5,   // 0 = pas de vérification
  // Métadonnées
  updatedAt:  new Date().toISOString(),
  updatedBy:  'system'
};

let policyCache = null;

async function ensureDataDir() {
  await fs.mkdir(path.dirname(POLICY_FILE), { recursive: true });
}

// ============================================================
// LECTURE / ÉCRITURE
// ============================================================

/**
 * Charge la politique depuis le fichier (ou retourne la valeur par défaut).
 * @returns {Promise<Object>}
 */
export async function getPolicy() {
  if (policyCache) return { ...policyCache };
  await ensureDataDir();
  try {
    const content = await fs.readFile(POLICY_FILE, 'utf8');
    policyCache = { ...DEFAULT_POLICY, ...JSON.parse(content) };
  } catch {
    policyCache = { ...DEFAULT_POLICY };
  }
  return { ...policyCache };
}

/**
 * Met à jour la politique et la persiste.
 * @param {Object} newPolicy - Champs à modifier (merge partiel)
 * @param {string} updatedBy  - Nom de l'utilisateur admin ayant modifié
 * @returns {Promise<Object>} La politique complète mise à jour
 */
export async function updatePolicy(newPolicy, updatedBy) {
  await getPolicy();

  // Valider les valeurs numériques
  const safePolicy = {};
  if (newPolicy.minLength      !== undefined) safePolicy.minLength      = Math.max(6, Math.min(128, parseInt(newPolicy.minLength) || 8));
  if (newPolicy.requireUppercase !== undefined) safePolicy.requireUppercase = Boolean(newPolicy.requireUppercase);
  if (newPolicy.requireLowercase !== undefined) safePolicy.requireLowercase = Boolean(newPolicy.requireLowercase);
  if (newPolicy.requireNumbers   !== undefined) safePolicy.requireNumbers   = Boolean(newPolicy.requireNumbers);
  if (newPolicy.requireSymbols   !== undefined) safePolicy.requireSymbols   = Boolean(newPolicy.requireSymbols);
  if (newPolicy.maxAgeDays       !== undefined) safePolicy.maxAgeDays       = Math.max(0, Math.min(3650, parseInt(newPolicy.maxAgeDays) || 0));
  if (newPolicy.preventReuse     !== undefined) safePolicy.preventReuse     = Math.max(0, Math.min(20,   parseInt(newPolicy.preventReuse) || 0));

  policyCache = {
    ...policyCache,
    ...safePolicy,
    updatedAt: new Date().toISOString(),
    updatedBy: updatedBy || 'admin'
  };

  await ensureDataDir();
  await fs.writeFile(POLICY_FILE, JSON.stringify(policyCache, null, 2), 'utf8');
  return { ...policyCache };
}

// ============================================================
// VALIDATION
// ============================================================

/**
 * Vérifie qu'un mot de passe respecte la politique en vigueur.
 *
 * @param {string} password - Le mot de passe à vérifier
 * @returns {Promise<{valid: boolean, errors: string[], score: number}>}
 *   - valid  : true si toutes les règles sont respectées
 *   - errors : liste des règles violées
 *   - score  : nombre de règles respectées (pour afficher une jauge)
 */
export async function validatePasswordPolicy(password) {
  const policy = await getPolicy();
  const errors = [];
  let passed = 0;
  const totalRules = 5;

  if (!password || password.length < policy.minLength) {
    errors.push(`Au moins ${policy.minLength} caractères requis (actuellement : ${(password || '').length}).`);
  } else {
    passed++;
  }

  if (policy.requireUppercase) {
    if (!/[A-Z]/.test(password || '')) {
      errors.push('Au moins une lettre majuscule requise (A-Z).');
    } else {
      passed++;
    }
  } else {
    passed++;
  }

  if (policy.requireLowercase) {
    if (!/[a-z]/.test(password || '')) {
      errors.push('Au moins une lettre minuscule requise (a-z).');
    } else {
      passed++;
    }
  } else {
    passed++;
  }

  if (policy.requireNumbers) {
    if (!/[0-9]/.test(password || '')) {
      errors.push('Au moins un chiffre requis (0-9).');
    } else {
      passed++;
    }
  } else {
    passed++;
  }

  if (policy.requireSymbols) {
    if (!/[^a-zA-Z0-9]/.test(password || '')) {
      errors.push('Au moins un caractère spécial requis (!@#$%^&*...).');
    } else {
      passed++;
    }
  } else {
    passed++;
  }

  return {
    valid: errors.length === 0,
    errors,
    score: passed,
    totalRules
  };
}

/**
 * Calcule si un mot de passe est "expiré" selon la politique de rotation.
 * @param {string|Date} changedAt - Date de la dernière modification
 * @returns {Promise<{expired: boolean, daysOld: number, maxAgeDays: number}>}
 */
export async function isPasswordExpired(changedAt) {
  const policy = await getPolicy();
  if (!policy.maxAgeDays) {
    return { expired: false, daysOld: 0, maxAgeDays: 0 };
  }

  const changedDate = changedAt instanceof Date ? changedAt : new Date(changedAt);
  const daysOld = Math.floor((Date.now() - changedDate.getTime()) / (1000 * 60 * 60 * 24));

  return {
    expired:    daysOld > policy.maxAgeDays,
    daysOld,
    maxAgeDays: policy.maxAgeDays
  };
}
