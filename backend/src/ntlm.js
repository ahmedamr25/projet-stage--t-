import crypto from 'crypto';

/**
 * Génère un message challenge NTLM de Type 2.
 * @returns {Buffer} Le buffer contenant le message de Type 2.
 */
export function createType2Message() {
  const buf = Buffer.alloc(40);
  
  // 1. Signature 'NTLMSSP\0' (8 octets)
  buf.write('NTLMSSP\0', 0, 8, 'ascii');
  
  // 2. Type de message (2 = Challenge, 4 octets)
  buf.writeUInt32LE(2, 8);
  
  // 3. Target Name Security Buffer (Longueur 0, Offset 40)
  buf.writeUInt16LE(0, 12); // Longueur
  buf.writeUInt16LE(0, 14); // Longueur max
  buf.writeUInt32LE(40, 16); // Offset
  
  // 4. Flags (4 octets)
  // Negotiate Unicode (0x00000001) | Negotiate NTLM (0x00000200) | Request Target (0x00000004)
  buf.writeUInt32LE(0x00000201, 20);
  
  // 5. Server Challenge (8 octets de données aléatoires)
  crypto.randomBytes(8).copy(buf, 24);
  
  // 6. Context (8 octets à 0) - déjà à 0 via Buffer.alloc
  
  return buf;
}

/**
 * Décode et parse un message NTLM de Type 3 pour en extraire le nom d'utilisateur et le domaine.
 * @param {Buffer} buf Le buffer du message de Type 3.
 * @returns {Object|null} Les informations extraites { domain, username, workstation } ou null.
 */
export function parseType3Message(buf) {
  if (buf.length < 52) return null;

  const signature = buf.toString('ascii', 0, 8);
  if (signature !== 'NTLMSSP\0') return null;

  const type = buf.readUInt32LE(8);
  if (type !== 3) return null;

  const readString = (lenOffset, valOffset) => {
    const length = buf.readUInt16LE(lenOffset);
    const offset = buf.readUInt32LE(valOffset);
    
    if (offset + length > buf.length) return '';
    
    // Les navigateurs modernes négocient généralement Unicode (UTF-16LE).
    let str = buf.toString('utf16le', offset, offset + length);
    
    // Si la chaîne contient des caractères invalides (remplacement Unicode)
    // ou semble corrompue, on tente un décodage ASCII.
    if (str.includes('\uFFFD') || /[\u0000-\u0008\u000B-\u000C\u000E-\u001F]/.test(str.replace(/\0/g, ''))) {
      str = buf.toString('ascii', offset, offset + length);
    }
    
    // Nettoyer les caractères null terminaux
    return str.replace(/\0/g, '').trim();
  };

  const domain = readString(28, 32);
  const username = readString(36, 40);
  const workstation = readString(44, 48);

  return { domain, username, workstation };
}
