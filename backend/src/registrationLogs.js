import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';

// ==========================================
// LOGS D'INSCRIPTION DE L'EXTENSION (PERSISTÉS)
// ==========================================
// Les logs sont maintenant sauvegardés sur disque pour survivre aux redémarrages.
// Purge automatique des entrées plus anciennes que TTL_MS.

const LOGS_FILE = path.join(process.cwd(), 'data', 'registration_logs.json');
const TTL_MS = 24 * 60 * 60 * 1000; // 24 heures

let logsCache = null; // Cache en mémoire

async function ensureDataDir() {
  await fs.mkdir(path.dirname(LOGS_FILE), { recursive: true });
}

async function loadLogs() {
  if (logsCache !== null) return logsCache;
  await ensureDataDir();
  try {
    const content = await fs.readFile(LOGS_FILE, 'utf8');
    logsCache = JSON.parse(content);
    if (!Array.isArray(logsCache)) logsCache = [];
  } catch {
    logsCache = [];
  }
  cleanExpired();
  return logsCache;
}

async function saveLogs() {
  try {
    await ensureDataDir();
    await fs.writeFile(LOGS_FILE, JSON.stringify(logsCache || [], null, 2), 'utf8');
  } catch (err) {
    console.error('[REG_LOGS] Erreur de sauvegarde :', err.message);
  }
}

function cleanExpired() {
  if (!logsCache) return;
  const now = Date.now();
  const before = logsCache.length;
  logsCache = logsCache.filter(log => {
    return (now - new Date(log.timestamp).getTime()) <= TTL_MS;
  });
  if (logsCache.length < before) {
    console.log(`[REG_LOGS] ${before - logsCache.length} log(s) expirés purgés.`);
  }
}

export async function addRegistrationLog(data) {
  await loadLogs();
  cleanExpired();
  const log = {
    id: crypto.randomUUID(),
    domain: data.domain || 'inconnu',
    url: data.url || '',
    passwordGenerated: data.passwordGenerated || '',
    fieldsFilled: data.fieldsFilled || 0,
    timestamp: new Date().toISOString()
  };
  logsCache.unshift(log);
  await saveLogs();
  return log;
}

export async function getRegistrationLogs() {
  await loadLogs();
  cleanExpired();
  return logsCache.slice();
}

export async function clearRegistrationLogs() {
  await loadLogs();
  logsCache = [];
  await saveLogs();
}

