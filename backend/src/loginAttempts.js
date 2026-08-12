const MAX_ATTEMPTS    = 3;
const LOCKOUT_MS      = 15 * 60 * 1000;
const USER_MAX_ATTEMPTS = 5;   // Plus permissif par utilisateur (protège contre IP multiples)
const USER_LOCKOUT_MS   = 30 * 60 * 1000; // 30 minutes si le compte est ciblé

// Cache par IP:username
const ipAttempts = new Map();
// Cache par username uniquement (protection contre attaques distribuées)
const userAttempts = new Map();

function getKey(ip, username) {
  return `${ip || 'unknown'}:${String(username || '').toLowerCase()}`;
}

function getUserKey(username) {
  return String(username || '').toLowerCase();
}

// ---- Helpers ----

function isLocked(record, maxAttempts) {
  if (!record) return false;
  if (record.lockedUntil && Date.now() < record.lockedUntil) return true;
  if (record.lockedUntil && Date.now() >= record.lockedUntil) return false; // déverrouillé
  return false;
}

function minutesLeft(record) {
  if (!record || !record.lockedUntil) return 0;
  return Math.ceil((record.lockedUntil - Date.now()) / 60000);
}

// ---- API publique ----

export function checkLoginAttempts(ip, username) {
  const ipKey   = getKey(ip, username);
  const userKey = getUserKey(username);

  const ipRecord   = ipAttempts.get(ipKey);
  const userRecord = userAttempts.get(userKey);

  // Vérifier le verrou IP:username
  if (ipRecord?.lockedUntil && Date.now() < ipRecord.lockedUntil) {
    return {
      allowed: false,
      remaining: 0,
      lockedUntil: ipRecord.lockedUntil,
      error: `Compte temporairement verrouillé après ${MAX_ATTEMPTS} tentatives échouées. Réessayez dans ${minutesLeft(ipRecord)} minute(s).`
    };
  }

  // Vérifier le verrou par compte (attaque distribuée)
  if (userRecord?.lockedUntil && Date.now() < userRecord.lockedUntil) {
    return {
      allowed: false,
      remaining: 0,
      lockedUntil: userRecord.lockedUntil,
      error: `Ce compte est temporairement verrouillé suite à des tentatives multiples. Réessayez dans ${minutesLeft(userRecord)} minute(s).`
    };
  }

  // Nettoyer les verrous expirés
  if (ipRecord?.lockedUntil && Date.now() >= ipRecord.lockedUntil) ipAttempts.delete(ipKey);
  if (userRecord?.lockedUntil && Date.now() >= userRecord.lockedUntil) userAttempts.delete(userKey);

  const remaining = MAX_ATTEMPTS - ((ipAttempts.get(ipKey)?.count) || 0);
  return { allowed: true, remaining: Math.max(0, remaining) };
}

export function recordFailedAttempt(ip, username) {
  const ipKey   = getKey(ip, username);
  const userKey = getUserKey(username);

  // Mettre à jour le compteur IP:username
  const ipRecord = ipAttempts.get(ipKey) || { count: 0, lockedUntil: null };
  ipRecord.count += 1;
  if (ipRecord.count >= MAX_ATTEMPTS) {
    ipRecord.lockedUntil = Date.now() + LOCKOUT_MS;
  }
  ipAttempts.set(ipKey, ipRecord);

  // Mettre à jour le compteur par compte (toutes IPs confondues)
  const userRecord = userAttempts.get(userKey) || { count: 0, lockedUntil: null };
  userRecord.count += 1;
  if (userRecord.count >= USER_MAX_ATTEMPTS) {
    userRecord.lockedUntil = Date.now() + USER_LOCKOUT_MS;
  }
  userAttempts.set(userKey, userRecord);

  const remaining = Math.max(0, MAX_ATTEMPTS - ipRecord.count);

  if (ipRecord.lockedUntil) {
    return {
      remaining: 0,
      locked: true,
      error: `Trop de tentatives échouées. Compte verrouillé pendant ${Math.ceil(LOCKOUT_MS / 60000)} minutes.`
    };
  }

  return {
    remaining,
    locked: false,
    error: remaining > 0
      ? `Identifiant ou mot de passe incorrect. ${remaining} tentative(s) restante(s).`
      : 'Identifiant ou mot de passe incorrect.'
  };
}

export function clearLoginAttempts(ip, username) {
  ipAttempts.delete(getKey(ip, username));
  // On garde le compteur par compte mais on réinitialise le count
  const userKey    = getUserKey(username);
  const userRecord = userAttempts.get(userKey);
  if (userRecord && !userRecord.lockedUntil) {
    userAttempts.delete(userKey); // nettoyer si pas verouillé
  }
}

/** Permet à un admin de débloquer manuellement un compte. */
export function unlockUser(username) {
  const userKey = getUserKey(username);
  userAttempts.delete(userKey);
  // Chercher et supprimer toutes les entrées IP pour cet utilisateur
  for (const [key] of ipAttempts.entries()) {
    if (key.endsWith(`:${userKey}`)) {
      ipAttempts.delete(key);
    }
  }
}

/** Retourne les comptes actuellement verrouillés (pour le dashboard admin). */
export function getLockedAccounts() {
  const now = Date.now();
  const locked = [];

  for (const [username, record] of userAttempts.entries()) {
    if (record.lockedUntil && now < record.lockedUntil) {
      locked.push({
        username,
        lockedUntil: new Date(record.lockedUntil).toISOString(),
        minutesLeft: Math.ceil((record.lockedUntil - now) / 60000)
      });
    }
  }

  return locked;
}

