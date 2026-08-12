// ============================================================
// db.js — Couche d'accès aux données (Prisma + fallback JSON)
// ============================================================
// Prisma est utilisé si DATABASE_URL est configuré dans le .env.
// Sinon, on bascule automatiquement sur le fichier data/db.json
// (comportement identique à l'ancienne implémentation).
// ============================================================

import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { encrypt } from './crypto.js';

dotenv.config();

// ---- Client Prisma (chargé dynamiquement pour éviter l'erreur si non installé) ----
let prisma = null;
let usePrisma = false;

async function initPrisma() {
  if (!process.env.DATABASE_URL) return false;
  try {
    const { PrismaClient } = await import('@prisma/client');
    prisma = new PrismaClient({
      log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error']
    });
    await prisma.$connect();
    console.log('[DB] Connecté à PostgreSQL via Prisma.');
    return true;
  } catch (err) {
    console.warn(`[DB] Prisma indisponible (${err.message}). Basculement vers JSON.`);
    return false;
  }
}

// ---- Fallback JSON ----
const DB_FILE = path.join(process.cwd(), 'data', 'db.json');

const SEED_DATA = [
  {
    id: '4e9d5696-98eb-4e60-93cb-3cd35d6423c1',
    owner: 'admin',
    title: 'GitHub Enterprise',
    websiteUrl: 'https://github.com',
    username: 'admin_ad',
    encryptedPassword: encrypt('SuperStrongGithubPassword2026!'),
    category: 'Professionnel',
    notes: 'Clé SSH de déploiement configurée.',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  {
    id: '8a8d5696-98eb-4e60-93cb-3cd35d6423c2',
    owner: 'admin',
    title: 'Intranet Tiznit (Démo DirectFill)',
    websiteUrl: 'https://localhost:5443/mock-target.html',
    username: 'ahmed.admin@tiznit.local',
    encryptedPassword: encrypt('Ahmed2026!'),
    category: 'Professionnel',
    notes: 'Compte de démonstration pour le remplissage automatique direct.',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  {
    id: '9f8d5696-98eb-4e60-93cb-3cd35d6423c3',
    owner: 'admin',
    title: 'Compte Bancaire Pro',
    websiteUrl: 'https://banque.entreprise.local',
    username: 'finance.admin',
    encryptedPassword: encrypt('BankSecureCapitalPassword2026'),
    category: 'Finance',
    notes: 'Double validation active sur le mobile.',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  {
    id: '0a8d5696-98eb-4e60-93cb-3cd35d6423c4',
    owner: 'user',
    title: 'Messagerie Outlook',
    websiteUrl: 'https://outlook.office.com',
    username: 'user@entreprise.local',
    encryptedPassword: encrypt('Office365PasswordUser!'),
    category: 'Général',
    notes: 'Boîte de messagerie professionnelle principale.',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  {
    id: '1a8d5696-98eb-4e60-93cb-3cd35d6423c5',
    owner: 'user',
    title: 'Intranet Tiznit (Démo DirectFill)',
    websiteUrl: 'https://localhost:5443/mock-target.html',
    username: 'user@tiznit.local',
    encryptedPassword: encrypt('User@2026!'),
    category: 'Général',
    notes: 'Accès portail intranet.',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  }
];

async function ensureDataDir() {
  await fs.mkdir(path.dirname(DB_FILE), { recursive: true });
}

async function readJsonDb() {
  await ensureDataDir();
  try {
    return JSON.parse(await fs.readFile(DB_FILE, 'utf8'));
  } catch {
    await fs.writeFile(DB_FILE, JSON.stringify(SEED_DATA, null, 2), 'utf8');
    return SEED_DATA;
  }
}

async function writeJsonDb(data) {
  await ensureDataDir();
  await fs.writeFile(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// Convertit une ligne Prisma vers le format utilisé partout dans le code
function prismaToRecord(row) {
  if (!row) return null;
  return {
    id: row.id,
    owner: row.owner,
    title: row.title,
    websiteUrl: row.websiteUrl || '',
    username: row.username || '',
    encryptedPassword: row.encryptedPassword,
    category: row.category || 'Général',
    notes: row.notes || '',
    createdAt: row.createdAt instanceof Date ? row.createdAt.toISOString() : row.createdAt,
    updatedAt: row.updatedAt instanceof Date ? row.updatedAt.toISOString() : row.updatedAt
  };
}

// ---- Initialisation ----
let dbReady = false;
let initPromise = null;

export async function ensureDbExists() {
  if (dbReady) return;
  if (!initPromise) {
    initPromise = (async () => {
      usePrisma = await initPrisma();
      if (!usePrisma) {
        await readJsonDb(); // crée le fichier seed si absent
        console.log('[DB] Mode JSON local actif (data/db.json).');
      }
      dbReady = true;
    })();
  }
  return initPromise;
}

ensureDbExists().catch(err => {
  console.warn('[DB] Erreur initialisation :', err.message);
  dbReady = true;
});

// ============================================================
// CRUD — MOTS DE PASSE
// ============================================================

export async function getUserPasswords(username) {
  await ensureDbExists();
  const owner = username.toLowerCase();

  if (usePrisma) {
    const rows = await prisma.password.findMany({
      where: { owner },
      orderBy: { title: 'asc' }
    });
    return rows.map(prismaToRecord);
  }

  const items = await readJsonDb();
  return items.filter(i => (i.owner || '').toLowerCase() === owner);
}

export async function getPasswordById(id, username) {
  await ensureDbExists();
  const owner = username.toLowerCase();

  if (usePrisma) {
    const row = await prisma.password.findFirst({ where: { id, owner } });
    return prismaToRecord(row);
  }

  const items = await readJsonDb();
  return items.find(i => i.id === id && (i.owner || '').toLowerCase() === owner) || null;
}

export async function addPassword(username, data) {
  await ensureDbExists();
  const owner = username.toLowerCase();
  const id = crypto.randomUUID();
  const now = new Date().toISOString();

  const record = {
    id,
    owner,
    title: data.title || 'Sans titre',
    websiteUrl: data.websiteUrl || '',
    username: data.username || '',
    encryptedPassword: data.encryptedPassword || '',
    category: data.category || 'Général',
    notes: data.notes || '',
    createdAt: now,
    updatedAt: now
  };

  if (usePrisma) {
    const row = await prisma.password.create({
      data: {
        id,
        owner,
        title: record.title,
        websiteUrl: record.websiteUrl || null,
        username: record.username || null,
        encryptedPassword: record.encryptedPassword,
        category: record.category,
        notes: record.notes || null
      }
    });
    return prismaToRecord(row);
  }

  const items = await readJsonDb();
  items.push(record);
  await writeJsonDb(items);
  return record;
}

export async function updatePassword(id, username, data) {
  await ensureDbExists();
  const existing = await getPasswordById(id, username);
  if (!existing) return null;

  const updatedRecord = {
    ...existing,
    title:             data.title             !== undefined ? data.title             : existing.title,
    websiteUrl:        data.websiteUrl        !== undefined ? data.websiteUrl        : existing.websiteUrl,
    username:          data.username          !== undefined ? data.username          : existing.username,
    encryptedPassword: data.encryptedPassword !== undefined ? data.encryptedPassword : existing.encryptedPassword,
    category:          data.category          !== undefined ? data.category          : existing.category,
    notes:             data.notes             !== undefined ? data.notes             : existing.notes,
    updatedAt: new Date().toISOString()
  };

  if (usePrisma) {
    const row = await prisma.password.update({
      where: { id },
      data: {
        title:             updatedRecord.title,
        websiteUrl:        updatedRecord.websiteUrl  || null,
        username:          updatedRecord.username    || null,
        encryptedPassword: updatedRecord.encryptedPassword,
        category:          updatedRecord.category,
        notes:             updatedRecord.notes       || null
      }
    });
    return prismaToRecord(row);
  }

  const items = await readJsonDb();
  const idx = items.findIndex(i => i.id === id);
  if (idx !== -1) { items[idx] = updatedRecord; await writeJsonDb(items); }
  return updatedRecord;
}

export async function deletePassword(id, username) {
  await ensureDbExists();
  const owner = username.toLowerCase();

  if (usePrisma) {
    const res = await prisma.password.deleteMany({ where: { id, owner } });
    return res.count > 0;
  }

  const items = await readJsonDb();
  const filtered = items.filter(i => !(i.id === id && (i.owner || '').toLowerCase() === owner));
  if (filtered.length === items.length) return false;
  await writeJsonDb(filtered);
  return true;
}

export async function getAllPasswordsForStats() {
  await ensureDbExists();

  if (usePrisma) {
    const rows = await prisma.password.findMany();
    return rows.map(prismaToRecord);
  }
  return readJsonDb();
}

// ============================================================
// PARTAGE DE MOTS DE PASSE
// ============================================================

export async function sharePassword({ passwordId, sharedBy, sharedWith, permission, encryptedKey, expiresAt }) {
  await ensureDbExists();

  if (usePrisma) {
    return prisma.sharedPassword.upsert({
      where: { passwordId_sharedWith: { passwordId, sharedWith } },
      create: { passwordId, sharedBy, sharedWith, permission, encryptedKey, expiresAt: expiresAt || null },
      update: { permission, encryptedKey, expiresAt: expiresAt || null }
    });
  }

  // Fallback JSON — stockage dans un fichier séparé
  const sharesFile = path.join(process.cwd(), 'data', 'shares.json');
  let shares = [];
  try { shares = JSON.parse(await fs.readFile(sharesFile, 'utf8')); } catch { shares = []; }

  const existing = shares.findIndex(s => s.passwordId === passwordId && s.sharedWith === sharedWith);
  const entry = { id: crypto.randomUUID(), passwordId, sharedBy, sharedWith, permission, encryptedKey, expiresAt: expiresAt || null, createdAt: new Date().toISOString() };
  if (existing !== -1) shares[existing] = entry; else shares.push(entry);
  await fs.writeFile(sharesFile, JSON.stringify(shares, null, 2), 'utf8');
  return entry;
}

export async function getSharesForPassword(passwordId) {
  await ensureDbExists();

  if (usePrisma) {
    return prisma.sharedPassword.findMany({ where: { passwordId } });
  }

  const sharesFile = path.join(process.cwd(), 'data', 'shares.json');
  try {
    const shares = JSON.parse(await fs.readFile(sharesFile, 'utf8'));
    return shares.filter(s => s.passwordId === passwordId);
  } catch { return []; }
}

export async function getPasswordsSharedWithMe(username) {
  await ensureDbExists();
  const sharedWith = username.toLowerCase();
  const now = new Date();

  if (usePrisma) {
    const shares = await prisma.sharedPassword.findMany({
      where: {
        sharedWith,
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }]
      },
      include: { password: true }
    });
    return shares.map(s => ({
      shareId:      s.id,
      permission:   s.permission,
      sharedBy:     s.sharedBy,
      expiresAt:    s.expiresAt,
      encryptedKey: s.encryptedKey,
      ...prismaToRecord(s.password)
    }));
  }

  const sharesFile = path.join(process.cwd(), 'data', 'shares.json');
  try {
    const shares = JSON.parse(await fs.readFile(sharesFile, 'utf8'));
    const active = shares.filter(s =>
      s.sharedWith === sharedWith &&
      (!s.expiresAt || new Date(s.expiresAt) > now)
    );
    const items = await readJsonDb();
    return active.map(s => {
      const pwd = items.find(i => i.id === s.passwordId);
      if (!pwd) return null;
      return { shareId: s.id, permission: s.permission, sharedBy: s.sharedBy, expiresAt: s.expiresAt, encryptedKey: s.encryptedKey, ...pwd };
    }).filter(Boolean);
  } catch { return []; }
}

export async function revokeShare(passwordId, sharedWith, requestingUser) {
  await ensureDbExists();

  if (usePrisma) {
    const share = await prisma.sharedPassword.findUnique({
      where: { passwordId_sharedWith: { passwordId, sharedWith } }
    });
    if (!share) return false;
    // Seul le propriétaire (sharedBy) ou l'admin peut révoquer
    if (share.sharedBy !== requestingUser) return false;
    await prisma.sharedPassword.delete({ where: { passwordId_sharedWith: { passwordId, sharedWith } } });
    return true;
  }

  const sharesFile = path.join(process.cwd(), 'data', 'shares.json');
  try {
    const shares = JSON.parse(await fs.readFile(sharesFile, 'utf8'));
    const share = shares.find(s => s.passwordId === passwordId && s.sharedWith === sharedWith);
    if (!share || share.sharedBy !== requestingUser) return false;
    const filtered = shares.filter(s => !(s.passwordId === passwordId && s.sharedWith === sharedWith));
    await fs.writeFile(sharesFile, JSON.stringify(filtered, null, 2), 'utf8');
    return true;
  } catch { return false; }
}

// ============================================================
// CLÉS RSA UTILISATEUR
// ============================================================

export async function getUserKey(username) {
  await ensureDbExists();

  if (usePrisma) {
    return prisma.userKey.findUnique({ where: { username } });
  }

  const keysFile = path.join(process.cwd(), 'data', 'user_keys.json');
  try {
    const keys = JSON.parse(await fs.readFile(keysFile, 'utf8'));
    return keys.find(k => k.username === username) || null;
  } catch { return null; }
}

export async function saveUserKey(username, publicKey, encryptedPrivKey) {
  await ensureDbExists();

  if (usePrisma) {
    return prisma.userKey.upsert({
      where: { username },
      create: { username, publicKey, encryptedPrivKey },
      update: { publicKey, encryptedPrivKey }
    });
  }

  const keysFile = path.join(process.cwd(), 'data', 'user_keys.json');
  let keys = [];
  try { keys = JSON.parse(await fs.readFile(keysFile, 'utf8')); } catch { keys = []; }
  const idx = keys.findIndex(k => k.username === username);
  const entry = { username, publicKey, encryptedPrivKey, createdAt: new Date().toISOString() };
  if (idx !== -1) keys[idx] = entry; else keys.push(entry);
  await fs.writeFile(keysFile, JSON.stringify(keys, null, 2), 'utf8');
  return entry;
}

// ============================================================
// TOTP 2FA SECRETS
// ============================================================

export async function saveUserTotpSecret(username, secret) {
  await ensureDbExists();
  const uname = username.toLowerCase();
  const file = path.join(process.cwd(), 'data', 'totp_secrets.json');
  let secrets = {};
  try { secrets = JSON.parse(await fs.readFile(file, 'utf8')); } catch { secrets = {}; }
  secrets[uname] = { secret, createdAt: new Date().toISOString() };
  await ensureDataDir();
  await fs.writeFile(file, JSON.stringify(secrets, null, 2), 'utf8');
  return true;
}

export async function getUserTotpSecret(username) {
  await ensureDbExists();
  const uname = username.toLowerCase();
  const file = path.join(process.cwd(), 'data', 'totp_secrets.json');
  try {
    const secrets = JSON.parse(await fs.readFile(file, 'utf8'));
    return secrets[uname]?.secret || null;
  } catch {
    return null;
  }
}
