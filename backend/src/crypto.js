import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

// Récupération de la clé de chiffrement depuis les variables d'environnement
// La clé doit faire 32 octets (256 bits). Si elle est encodée en hex (64 caractères), on la convertit en buffer.
const hexKey = process.env.ENCRYPTION_KEY || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const ENCRYPTION_KEY = Buffer.from(hexKey, 'hex');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 12 octets est la taille standard recommandée pour le vecteur d'initialisation en GCM

/**
 * Chiffre un texte clair en utilisant AES-256-GCM.
 * Retourne une chaîne au format : iv_hex:auth_tag_hex:encrypted_text_hex
 * @param {string} text - Le texte à chiffrer (le mot de passe)
 * @returns {string} Le résultat chiffré formaté
 */
export function encrypt(text) {
  if (!text) return '';
  
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag().toString('hex');
  
  // Format : iv:tag:data
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Déchiffre un texte chiffré généré par la fonction `encrypt`.
 * @param {string} encryptedText - Le texte formaté iv:tag:data
 * @returns {string} Le texte d'origine déchiffré
 */
export function decrypt(encryptedText) {
  if (!encryptedText) return '';
  
  try {
    const parts = encryptedText.split(':');
    if (parts.length !== 3) {
      throw new Error('Format de texte chiffré invalide');
    }
    
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];
    
    const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Erreur lors du déchiffrement :', error.message);
    return '🔑 [Erreur de déchiffrement - Clé incorrecte]';
  }
}
