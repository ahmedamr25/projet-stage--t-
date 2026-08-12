import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { encrypt, decrypt } from './crypto.js';

// ==========================================
// HISTORIQUE DES MOTS DE PASSE (PASSWORD HISTORY)
// ==========================================
// Avant chaque modification de mot de passe, l'ancien mot de passe
// est sauvegardé ici (chiffré) pour permettre la récupération.
// Les entrées sont automatiquement purgées après TTL_DAYS jours.

const HISTORY_FILE = path.join(process.cwd(), 'data', 'password_history.json');
const TTL_DAYS = 30;
const TTL_MS = TTL_DAYS * 24 * 60 * 60 * 1000;

let historyCache = null; // Cache en mémoire

/**
 * Charge l'historique depuis le fichier JSON.
 * @returns {Promise<Array>} Liste des entrées d'historique
 */
async function loadHistory() {
  if (historyCache !== null) return historyCache;

  try {
    const dir = path.dirname(HISTORY_FILE);
    await fs.mkdir(dir, { recursive: true });
    const content = await fs.readFile(HISTORY_FILE, 'utf8');
    historyCache = JSON.parse(content);
    if (!Array.isArray(historyCache)) historyCache = [];
  } catch {
    historyCache = [];
  }

  // Purger les entrées expirées au chargement
  cleanExpired();
  return historyCache;
}

/**
 * Sauvegarde l'historique dans le fichier JSON.
 */
async function saveHistory() {
  try {
    const dir = path.dirname(HISTORY_FILE);
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(HISTORY_FILE, JSON.stringify(historyCache || [], null, 2), 'utf8');
  } catch (err) {
    console.error('[PASSWORD_HISTORY] Erreur de sauvegarde :', err.message);
  }
}

/**
 * Supprime les entrées expirées (plus anciennes que TTL_DAYS jours).
 */
function cleanExpired() {
  if (!historyCache) return;
  const now = Date.now();
  const before = historyCache.length;
  historyCache = historyCache.filter(entry => {
    const entryTime = new Date(entry.changedAt).getTime();
    return (now - entryTime) < TTL_MS;
  });
  if (historyCache.length < before) {
    console.log(`[PASSWORD_HISTORY] ${before - historyCache.length} entrée(s) expirée(s) purgée(s).`);
  }
}

/**
 * Enregistre l'ancien mot de passe avant une modification.
 * Le mot de passe est stocké chiffré (AES-256-GCM).
 *
 * @param {string} owner - Le propriétaire du mot de passe (username)
 * @param {string} entryId - L'ID de l'entrée du coffre-fort
 * @param {string} title - Le titre de l'entrée (pour affichage)
 * @param {string} oldPassword - L'ancien mot de passe en clair (sera chiffré)
 * @param {string} changedBy - Qui a fait le changement (username)
 * @returns {Promise<Object>} L'entrée d'historique créée
 */
export async function logPasswordChange(owner, entryId, title, oldPassword, changedBy) {
  await loadHistory();

  const entry = {
    id: crypto.randomUUID(),
    owner: (owner || '').toLowerCase(),
    entryId,
    title: title || 'Sans titre',
    encryptedOldPassword: encrypt(oldPassword),
    changedBy: changedBy || owner,
    changedAt: new Date().toISOString()
  };

  historyCache.unshift(entry); // Ajouter en tête (plus récent en premier)
  cleanExpired();
  await saveHistory();

  console.log(`[PASSWORD_HISTORY] Ancien mot de passe enregistré pour "${title}" (propriétaire: ${owner})`);
  return entry;
}

/**
 * Récupère l'historique des changements de mots de passe pour un utilisateur.
 * Les mots de passe sont retournés déchiffrés pour consultation.
 *
 * @param {string} owner - Le propriétaire (username)
 * @returns {Promise<Array>} Liste des changements avec les anciens mots de passe déchiffrés
 */
export async function getPasswordHistory(owner) {
  await loadHistory();
  cleanExpired();

  const lowerOwner = (owner || '').toLowerCase();
  return historyCache
    .filter(entry => entry.owner === lowerOwner)
    .map(entry => ({
      id: entry.id,
      entryId: entry.entryId,
      title: entry.title,
      oldPassword: decrypt(entry.encryptedOldPassword),
      changedBy: entry.changedBy,
      changedAt: entry.changedAt
    }));
}

/**
 * Efface tout l'historique d'un utilisateur.
 *
 * @param {string} owner - Le propriétaire (username)
 * @returns {Promise<number>} Nombre d'entrées supprimées
 */
export async function clearPasswordHistory(owner) {
  await loadHistory();

  const lowerOwner = (owner || '').toLowerCase();
  const before = historyCache.length;
  historyCache = historyCache.filter(entry => entry.owner !== lowerOwner);
  const deleted = before - historyCache.length;

  if (deleted > 0) {
    await saveHistory();
    console.log(`[PASSWORD_HISTORY] ${deleted} entrée(s) supprimée(s) pour ${owner}.`);
  }

  return deleted;
}
