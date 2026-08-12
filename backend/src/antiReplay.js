import crypto from 'crypto';

// ==========================================
// PROTECTION ANTI-REJEU (ANTI-REPLAY ATTACK)
// ==========================================
// Chaque requête de mutation (POST/PUT/DELETE) doit inclure :
//   - Header X-Request-Nonce : UUID unique par requête
//   - Header X-Request-Timestamp : epoch en millisecondes
// Le serveur rejette les requêtes avec :
//   - Un timestamp trop ancien (> WINDOW_MS)
//   - Un nonce déjà vu (rejeu détecté)

const WINDOW_MS = 5 * 60 * 1000; // Fenêtre de validité : 5 minutes
const CLEANUP_INTERVAL_MS = 60 * 1000; // Nettoyage toutes les 60 secondes

class NonceStore {
  constructor() {
    this._store = new Map(); // nonce → expiresAt (timestamp)
    this._cleanupTimer = setInterval(() => this._cleanup(), CLEANUP_INTERVAL_MS);
    // Permettre au processus de se terminer normalement
    if (this._cleanupTimer.unref) {
      this._cleanupTimer.unref();
    }
  }

  /**
   * Vérifie si un nonce a déjà été utilisé. Si non, l'enregistre.
   * @param {string} nonce - L'identifiant unique de la requête
   * @returns {boolean} true si le nonce est nouveau (requête valide), false si déjà vu (rejeu)
   */
  checkAndStore(nonce) {
    if (this._store.has(nonce)) {
      return false; // Nonce déjà vu → rejeu détecté
    }
    this._store.set(nonce, Date.now() + WINDOW_MS);
    return true;
  }

  /**
   * Supprime les nonces expirés pour libérer la mémoire.
   */
  _cleanup() {
    const now = Date.now();
    for (const [nonce, expiresAt] of this._store.entries()) {
      if (now >= expiresAt) {
        this._store.delete(nonce);
      }
    }
  }

  /**
   * Retourne le nombre de nonces actuellement stockés (pour monitoring).
   */
  get size() {
    return this._store.size;
  }
}

// Instance unique partagée par tout le serveur
const nonceStore = new NonceStore();

/**
 * Middleware Express de protection anti-rejeu.
 * Appliqué uniquement sur les méthodes de mutation (POST, PUT, DELETE).
 * Les requêtes GET/HEAD/OPTIONS passent sans vérification.
 */
export function antiReplayMiddleware(req, res, next) {
  // Ne pas vérifier les méthodes de lecture
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method.toUpperCase())) {
    return next();
  }

  const nonce = req.headers['x-request-nonce'];
  const timestampStr = req.headers['x-request-timestamp'];

  // Vérifier la présence des headers
  if (!nonce || !timestampStr) {
    return res.status(400).json({
      error: 'Headers de sécurité manquants. X-Request-Nonce et X-Request-Timestamp sont requis.'
    });
  }

  // Valider le format du nonce (doit ressembler à un UUID ou être alphanumérique)
  if (typeof nonce !== 'string' || nonce.length < 16 || nonce.length > 128) {
    return res.status(400).json({
      error: 'Nonce invalide. Format attendu : UUID ou identifiant alphanumérique (16-128 caractères).'
    });
  }

  // Valider le timestamp
  const timestamp = parseInt(timestampStr, 10);
  if (isNaN(timestamp) || timestamp <= 0) {
    return res.status(400).json({
      error: 'Timestamp invalide. Epoch en millisecondes attendu.'
    });
  }

  const now = Date.now();
  const age = now - timestamp;

  // Rejeter si le timestamp est dans le futur (tolérance de 30 secondes pour le décalage d'horloge)
  if (timestamp > now + 30000) {
    console.warn(`[ANTI-REPLAY] Requête avec timestamp futur rejetée. Décalage: ${age}ms`);
    return res.status(400).json({
      error: 'Requête rejetée : timestamp dans le futur.'
    });
  }

  // Rejeter si le timestamp est trop ancien
  if (age > WINDOW_MS) {
    console.warn(`[ANTI-REPLAY] Requête expirée rejetée. Âge: ${Math.round(age / 1000)}s`);
    return res.status(400).json({
      error: `Requête expirée. Les requêtes doivent être émises dans les ${WINDOW_MS / 60000} dernières minutes.`
    });
  }

  // Vérifier et stocker le nonce
  if (!nonceStore.checkAndStore(nonce)) {
    console.warn(`[ANTI-REPLAY]  REJEU DÉTECTÉ ! Nonce: ${nonce.substring(0, 8)}...`);
    return res.status(409).json({
      error: 'Requête rejetée : nonce déjà utilisé (rejeu détecté).'
    });
  }

  next();
}

export default antiReplayMiddleware;
