# 📊 Prompt d'Analyse Complète — SecurPass v2.0 pour DeepSeek

**Objectif:** Comprendre l'architecture du projet SecurPass, ses fonctionnalités, et générer des diagrammes UML complets.

---

## 🎯 Contexte du Projet

### Présentation Générale

**SecurPass** est un gestionnaire de mots de passe d'entreprise développé pour un environnement Active Directory / LDAP. Le projet combine une application web full-stack avec des extensions navigateur (Chrome/Firefox).

**Technologies utilisées:**
- **Backend:** Node.js + Express.js
- **Base de données:** JSON (dev) / PostgreSQL + Prisma ORM (prod)
- **Frontend:** HTML5 + CSS3 + JavaScript Vanilla
- **Authentification:** JWT + LDAP/Active Directory
- **Chiffrement:** AES-256-GCM (Node.js crypto)
- **Extensions:** Chrome/Firefox Web Extensions API

**Architecture:** Client-serveur avec SPA (Single Page Application)

---

## 📂 Structure du Projet

```
projet_stage/
├── backend/
│   ├── src/
│   │   ├── server.js              # Point d'entrée Express
│   │   ├── routes.js              # Tous les endpoints API
│   │   ├── db.js                  # Couche d'accès données (Prisma + JSON)
│   │   ├── crypto.js              # Chiffrement AES-256-GCM
│   │   ├── ldap.js                # Connexion Active Directory
│   │   ├── ntlm.js                # Authentification NTLM/SSO
│   │   ├── antiReplay.js          # Middleware anti-rejeu (nonce + timestamp)
│   │   ├── loginAttempts.js       # Limitation tentatives connexion
│   │   ├── passwordHistory.js     # Historique modifications mots de passe
│   │   └── registrationLogs.js    # Logs formulaires détectés par extension
│   ├── prisma/
│   │   └── schema.prisma          # Schéma base de données Prisma
│   ├── data/
│   │   └── db.json               # Base de données JSON (fallback dev)
│   ├── package.json
│   └── .env                      # Configuration (DATABASE_URL, JWT_SECRET)
├── frontend/
│   ├── index.html                # SPA principale
│   ├── app.js                    # Logique application (1800+ lignes)
│   └── style.css                 # Styles personnalisés
├── chrome-extension/
│   ├── manifest.json
│   ├── background.js             # Service worker
│   ├── content.js                # Injection dans pages web
│   └── popup.js                  # Interface popup
├── firefox-extension/
│   └── (même structure)
├── NOUVELLES_FONCTIONNALITES.md  # Guide utilisateur
├── IMPLEMENTATION_SUMMARY.md      # Documentation technique
└── README.md
```

---

## 🔧 Fonctionnalités Principales

### 1. Authentification Active Directory

**Fichiers:** `backend/src/ldap.js`, `backend/src/ntlm.js`, `backend/src/routes.js`

**Méthodes supportées:**

1. **Connexion LDAP classique** (`POST /api/auth/login`)
   - Username + Password
   - Vérification contre annuaire AD
   - Retourne JWT + informations utilisateur (displayName, groups)

2. **SSO (Single Sign-On) NTLM** (`GET /api/auth/sso`)
   - Lecture automatique des credentials Windows
   - Mock mode: lit `process.env.USERNAME`
   - Production: authentification transparente

**Justification:**
- Intégration native avec infrastructure Microsoft existante
- Évite aux utilisateurs de mémoriser un mot de passe supplémentaire
- Groupes AD utilisés pour contrôle d'accès (administrateurs vs utilisateurs standard)

**Flux d'authentification:**
```
1. User clique "Se connecter" ou "SSO"
2. Backend vérifie credentials via LDAP bind
3. Si succès: génère JWT (expire 24h)
4. Frontend stocke JWT dans sessionStorage
5. Toutes les requêtes API incluent header Authorization: Bearer <token>
```

---

### 2. Gestion du Coffre-fort (CRUD Mots de Passe)

**Fichiers:** `backend/src/routes.js`, `backend/src/db.js`, `backend/src/crypto.js`, `frontend/app.js`

**Endpoints API:**

| Méthode | Endpoint | Description | Auth |
|---------|----------|-------------|------|
| `GET` | `/api/vault` | Liste tous les mots de passe de l'utilisateur | JWT |
| `POST` | `/api/vault` | Crée un nouveau mot de passe | JWT + Anti-replay |
| `PUT` | `/api/vault/:id` | Modifie un mot de passe existant | JWT + Anti-replay |
| `DELETE` | `/api/vault/:id` | Supprime un mot de passe | JWT + Anti-replay |
| `GET` | `/api/vault/history` | Historique des modifications | JWT |
| `DELETE` | `/api/vault/history` | Efface l'historique | JWT + Anti-replay |

**Chiffrement AES-256-GCM:**

```javascript
// backend/src/crypto.js
const MASTER_KEY = crypto.scryptSync(process.env.MASTER_PASSWORD, 'salt', 32);

function encrypt(plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('hex'), encrypted: encrypted.toString('hex'), tag: tag.toString('hex') };
}
```

**Justification:**
- **AES-256-GCM:** Standard militaire, authentification intégrée (protection contre modification)
- **IV aléatoire:** Chaque mot de passe chiffré différemment même avec même valeur
- **Master key dérivée:** ScryptSync contre attaques par force brute
- **Tag d'authentification:** Détecte toute altération des données chiffrées

**Structure données stockées:**
```json
{
  "id": "uuid-v4",
  "title": "GitHub",
  "category": "Professionnel",
  "websiteUrl": "https://github.com",
  "username": "john.doe",
  "password": "chiffré-base64",  // AES-256-GCM
  "notes": "Clé SSH stockée ailleurs",
  "owner": "john.doe",
  "createdAt": "2026-07-28T10:30:00Z",
  "updatedAt": "2026-07-28T10:30:00Z"
}
```

---

### 3. Générateur de Mots de Passe

**Fichiers:** `frontend/app.js` (fonctions `generatePasswordString`, `calculateStrength`)

**Paramètres configurables:**

- Longueur: 8-64 caractères (slider)
- Majuscules (A-Z)
- Minuscules (a-z)
- Chiffres (0-9)
- Symboles (!@#$%^&*)
- Exclure caractères similaires (O/0, I/l/1)

**Algorithme:**
```javascript
1. Construire charset selon options cochées
2. Garantir au moins 1 caractère de chaque type sélectionné
3. Remplir le reste aléatoirement (crypto.getRandomValues ou Math.random fallback)
4. Mélanger avec Fisher-Yates shuffle
5. Calculer force (entropie basée sur longueur + diversité)
```

**Calcul de force:**
- Faible (1): < 8 caractères ou 1 seul type
- Moyen (2): 8-11 caractères, 2-3 types
- Fort (3): 12-15 caractères, 3-4 types
- Très Sécurisé (4): 16+ caractères, 4 types

**Justification:**
- **crypto.getRandomValues:** CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
- **Diversité forcée:** Évite mots de passe faibles (ex: "aaaaaaaaaa")
- **Exclusion caractères similaires:** Réduit erreurs de saisie manuelle

---

### 4. Extensions Navigateur (Auto-fill)

**Fichiers:** `chrome-extension/`, `firefox-extension/`

**Architecture:**

```
background.js (Service Worker)
    ↓
content.js (Injecté dans toutes les pages)
    ↓ détecte formulaires
    ↓ écoute événements submit
    ↓
popup.js (Interface utilisateur)
    ↓ communique avec backend via fetch()
    ↓
API Backend (/api/vault)
```

**Fonctionnalités:**

1. **Détection formulaires:**
   - Content script scanne DOM pour `<input type="password">`
   - Identifie champs username/email associés
   - Affiche badge sur icône extension

2. **Auto-fill:**
   - Utilisateur clique sur extension
   - Popup affiche mots de passe correspondant au domaine actuel
   - Clic sur mot de passe → injection dans formulaire via `document.querySelector().value = ...`

3. **Capture inscriptions:**
   - Détecte soumission formulaire avec nouveau mot de passe
   - Envoie à `/api/registration-logs` pour historique temporaire (24h)
   - Propose de sauvegarder dans coffre-fort

**Justification:**
- **Content script isolé:** Sécurité (pas d'accès direct aux credentials)
- **Communication message passing:** Chrome/Firefox standard
- **Logs temporaires:** Évite perte de nouveaux comptes créés

---

### 5. PostgreSQL + Prisma ORM (Migration v2.0)

**Fichiers:** `backend/prisma/schema.prisma`, `backend/src/db.js`

**Schéma Prisma:**

```prisma
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model Password {
  id          String   @id @default(uuid())
  title       String
  category    String   @default("Général")
  websiteUrl  String?
  username    String?
  password    String   // Chiffré AES-256-GCM
  notes       String?
  owner       String   // username LDAP
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  
  shares      SharedPassword[]
  history     PasswordHistory[]
}

model SharedPassword {
  id           String    @id @default(uuid())
  passwordId   String
  owner        String    // Propriétaire original
  sharedWith   String    // Username LDAP destinataire
  permission   String    // "read" | "write"
  expiresAt    DateTime?
  encryptedKey String?   // Token serveur pour déchiffrement
  sharedAt     DateTime  @default(now())
  
  password     Password  @relation(fields: [passwordId], references: [id], onDelete: Cascade)
  
  @@unique([passwordId, sharedWith])
}

model UserKey {
  id                   String   @id @default(uuid())
  username             String   @unique
  publicKey            String?  // Pour chiffrement E2E futur (RSA)
  privateKeyEncrypted  String?  // Clé privée chiffrée avec mot de passe utilisateur
  createdAt            DateTime @default(now())
}

model PasswordHistory {
  id              String   @id @default(uuid())
  passwordId      String
  oldPasswordHash String   // Hash SHA-256 (pas clair)
  changedBy       String   // Username LDAP
  changedAt       DateTime @default(now())
  
  password        Password @relation(fields: [passwordId], references: [id], onDelete: Cascade)
}
```

**Double mode db.js:**

```javascript
const prisma = process.env.DATABASE_URL ? new PrismaClient() : null;

async function getAllPasswords(username) {
  if (prisma) {
    // Mode Prisma (PostgreSQL)
    return await prisma.password.findMany({
      where: { owner: username }
    });
  } else {
    // Mode JSON fallback
    const db = JSON.parse(fs.readFileSync('data/db.json'));
    return db.passwords.filter(p => p.owner === username);
  }
}
```

**Justification:**

- **Prisma ORM:** Type-safe, migrations versionnées, requêtes optimisées
- **PostgreSQL:** ACID, transactions, concurrence, relations complexes
- **Double mode:** Développement simple (JSON) + Production robuste (PostgreSQL)
- **Auto-détection:** Aucun changement code selon environnement
- **Relations Prisma:** Cascade delete (suppression mot de passe → supprime partages/historique)

**Avantages PostgreSQL vs JSON:**
| Critère | JSON | PostgreSQL |
|---------|------|------------|
| Concurrence | ❌ Race conditions | ✅ Locks transactionnels |
| Intégrité | ❌ Corruption fichier | ✅ ACID |
| Performance | ❌ O(n) recherche | ✅ Index B-tree |
| Relations | ❌ Jointures manuelles | ✅ Foreign keys |
| Migrations | ❌ Manuelles | ✅ Prisma Migrate |
| Backup | ⚠️ Copie fichier | ✅ pg_dump + PITR |

---

### 6. Import/Export de Mots de Passe

**Fichiers:** `backend/src/routes.js`, `frontend/app.js`, `frontend/index.html`

**Endpoints:**

1. **Export CSV** (`GET /api/vault/export/csv`)
   - Format: `title,url,username,password,category,notes`
   - Compatible: Excel, Google Sheets, LibreOffice
   - Mots de passe en clair (⚠️ suppression fichier obligatoire après usage)

2. **Export JSON Bitwarden** (`GET /api/vault/export/json`)
   - Format standard Bitwarden: `{ "items": [{ "name": "...", "login": {...} }] }`
   - Compatible: Bitwarden, 1Password (via import CSV)

3. **Import** (`POST /api/vault/import`)
   - Header `X-Import-Format: csv|bitwarden`
   - Body: texte brut (text/plain)
   - Détection colonnes CSV flexible:
     - `title`/`name`/`nom`
     - `url`/`websiteurl`/`website`
     - `username`/`login`/`identifiant`
     - `password`/`mot de passe` *(obligatoire)*
     - `category`/`catégorie`/`folder`
     - `notes`/`note`/`commentaire`

**Parser CSV (csv-parse):**
```javascript
const { parse } = require('csv-parse/sync');

const records = parse(csvText, {
  columns: true,        // Première ligne = headers
  skip_empty_lines: true,
  trim: true,
  relax_column_count: true  // Tolère colonnes variables
});
```

**Justification:**
- **Formats multiples:** Migration depuis Chrome/Firefox/Bitwarden/Edge
- **Détection flexible:** Gère variations noms colonnes entre navigateurs
- **Text/plain body:** Évite complexité multipart/form-data
- **Validation stricte:** Refuse import si colonne `password` manquante
- **Chiffrement automatique:** Mots de passe importés chiffrés immédiatement

**Cas d'usage:**
- Migration depuis ancien gestionnaire (LastPass, Dashlane)
- Backup régulier du coffre-fort
- Export pour audit sécurité (hors ligne)

---

### 7. Partage de Mots de Passe entre Utilisateurs

**Fichiers:** `backend/src/routes.js`, `backend/src/db.js`, `frontend/app.js`

**Endpoints:**

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/api/vault/:id/share` | Crée un partage |
| `GET` | `/api/vault/:id/shares` | Liste partages d'un mot de passe |
| `DELETE` | `/api/vault/:id/share/:username` | Révoque un partage |
| `GET` | `/api/vault/shared-with-me` | Mots de passe partagés avec moi |

**Structure SharedPassword:**
```json
{
  "id": "uuid",
  "passwordId": "uuid-du-mot-de-passe",
  "owner": "john.doe",           // Propriétaire original
  "sharedWith": "ahmed",         // Destinataire (username LDAP)
  "permission": "read",          // "read" | "write"
  "expiresAt": "2026-08-04T10:30:00Z",  // null = permanent
  "encryptedKey": "token-serveur",      // Pour déchiffrement
  "sharedAt": "2026-07-28T10:30:00Z"
}
```

**Permissions:**
- **read:** Consultation uniquement (copier username/password)
- **write:** Consultation + Modification (mais pas suppression)
- **Propriétaire seul:** Suppression, révocation partages

**Expiration automatique:**
- Backend vérifie `expiresAt` à chaque requête `/vault/shared-with-me`
- Si expiré: partage invisible (mais pas supprimé, pour audit)

**UI Frontend:**

- Bouton **"Partager"** sur chaque carte de mot de passe
- Modal avec:
  - Input username LDAP
  - Radio buttons permissions (👁️ Lecture / ✏️ Écriture)
  - Select expiration (Jamais, 24h, 7j, 30j, 90j)
- Bouton **"Gérer les accès"** → Modal liste utilisateurs + bouton "Révoquer"
- Onglet **"Partagés avec moi"** → Grille séparée avec badges propriétaire/permission/expiration

**Justification:**
- **Collaboration équipe:** Compte serveur partagé DevOps, compte client support
- **Permissions granulaires:** Consultation vs modification
- **Expiration automatique:** Partages temporaires (stagiaires, consultants)
- **Token serveur:** Simplicité (E2E RSA possible en v3.0 via modèle UserKey)
- **Révocation instantanée:** Propriétaire garde contrôle total

**Sécurité:**
- Vérification existence destinataire dans AD (requête LDAP)
- Propriétaire seul peut révoquer
- Expiration côté serveur (client ne peut pas bypasser)
- Logs audit via `sharedAt` timestamp

---

### 8. Anti-Replay Protection

**Fichiers:** `backend/src/antiReplay.js`, `frontend/app.js`

**Middleware:**
```javascript
const recentNonces = new Set();  // In-memory cache (Redis en prod)

function antiReplayMiddleware(req, res, next) {
  const nonce = req.headers['x-request-nonce'];
  const timestamp = req.headers['x-request-timestamp'];
  
  // Vérifications:
  // 1. Nonce + timestamp présents
  // 2. Timestamp < 5 minutes (300 000 ms)
  // 3. Nonce jamais vu (pas de replay)
  
  if (!nonce || !timestamp) return res.status(400).json({ error: 'Headers anti-replay manquants' });
  
  const age = Date.now() - parseInt(timestamp);
  if (age > 300000 || age < 0) return res.status(400).json({ error: 'Timestamp invalide' });
  
  if (recentNonces.has(nonce)) return res.status(400).json({ error: 'Nonce déjà utilisé (replay attack)' });
  
  recentNonces.add(nonce);
  setTimeout(() => recentNonces.delete(nonce), 300000);  // Nettoyage après 5 min
  
  next();
}
```

**Frontend (app.js):**
```javascript
function getAntiReplayHeaders() {
  return {
    'X-Request-Nonce': crypto.randomUUID(),      // UUID v4 aléatoire
    'X-Request-Timestamp': Date.now().toString() // Epoch milliseconds
  };
}

// Utilisation:
fetch('/api/vault', {
  method: 'POST',
  headers: { ...getAntiReplayHeaders(), 'Authorization': `Bearer ${token}` },
  body: JSON.stringify(data)
});
```

**Justification:**
- **Replay attacks:** Attaquant intercepte requête et la rejoue (ex: suppression)
- **Nonce UUID:** Probabilité collision négligeable (2^122)
- **Fenêtre 5 minutes:** Tolère décalages horloges client/serveur
- **Set mémoire:** Performance (Redis en production pour scalabilité)
- **Nettoyage automatique:** Évite fuite mémoire

**Endpoints protégés:**
- Toutes les mutations (POST, PUT, DELETE)
- Pas sur GET (lecture seule, idempotent)

---

### 9. Console d'Administration

**Fichiers:** `backend/src/routes.js`, `frontend/app.js`

**Endpoints:**

| Endpoint | Description |
|----------|-------------|
| `GET /api/admin/stats` | Statistiques coffre-fort global |
| `GET /api/admin/users?search=...` | Liste utilisateurs AD/LDAP |
| `POST /api/admin/users` | Crée utilisateur AD |
| `PUT /api/admin/users/:username` | Modifie utilisateur AD |
| `DELETE /api/admin/users/:username` | Supprime utilisateur AD |

**Statistiques retournées:**
```json
{
  "totalPasswords": 142,
  "avgLength": 14,
  "reusedPasswords": 3,        // Doublons (hash identique)
  "extremelyWeak": 2,          // < 8 caractères
  "lastModified": "2026-07-28T10:30:00Z",
  "strengthDistribution": {
    "weak": 12,
    "fair": 45,
    "good": 60,
    "strong": 25
  },
  "userDistribution": {
    "john.doe": 15,
    "ahmed": 8,
    "marie.dupont": 12
  }
}
```

**Contrôle d'accès:**
```javascript
function isAdminUser(user) {
  const adminUsernames = ['admin', 'administrateur'];
  if (adminUsernames.includes(user.username.toLowerCase())) return true;
  
  const adminGroups = [
    'domain admins',
    'enterprise admins',
    'it-security',
    'administrateurs du domaine'
  ];
  
  return user.groups.some(g => 
    adminGroups.some(ag => g.toLowerCase().includes(ag))
  );
}
```

**Justification:**

- **Audit sécurité:** Identifier mots de passe faibles/réutilisés
- **Gestion utilisateurs:** CRUD via interface (évite CLI LDAP)
- **Visibilité:** Distribution par collaborateur, force globale
- **Contrôle accès:** Basé sur groupes AD (principle of least privilege)
- **KPIs visuels:** Cartes avec alertes visuelles (rouge si mots de passe faibles)

---

## 🔐 Sécurité et Conformité

### Mesures Implémentées

1. **Chiffrement au repos:**
   - AES-256-GCM pour tous les mots de passe en base
   - Master key dérivée de `MASTER_PASSWORD` (environment variable)
   - IV unique par entrée

2. **Chiffrement en transit:**
   - HTTPS obligatoire en production (TLS 1.2+)
   - HSTS headers recommandés

3. **Authentification:**
   - JWT avec expiration 24h
   - LDAP bind pour vérification credentials
   - Pas de stockage mot de passe en clair

4. **Anti-rejeu:**
   - Nonce unique + timestamp sur toutes mutations
   - Fenêtre temporelle 5 minutes

5. **Validation inputs:**
   - Regex strict usernames (anti-injection LDAP)
   - Sanitization displayName (interdiction `\0`, `(`, `)`, `*`, `<`, `>`, `;`)
   - Taille maximale champs (username 64, password 128)

6. **Rate limiting:**
   - `loginAttempts.js`: 5 tentatives max par IP/15 min
   - Reset automatique après succès

7. **Logs audit:**
   - `PasswordHistory`: hash ancien mot de passe + timestamp + auteur
   - `SharedPassword.sharedAt`: traçabilité partages

8. **Principe least privilege:**
   - Utilisateurs voient uniquement leurs mots de passe (`WHERE owner = username`)
   - Administrateurs accès stats globales (pas aux mots de passe d'autrui)
   - Permissions partage (read vs write)

### Recommandations Futures (v3.0)

1. **Chiffrement E2E (RSA):**
   - Générer paire clés RSA par utilisateur (modèle `UserKey` prêt)
   - Chiffrer clé symétrique du mot de passe avec clé publique destinataire
   - Serveur ne peut jamais déchiffrer

2. **2FA (Two-Factor Authentication):**
   - TOTP (Google Authenticator)
   - WebAuthn (clés sécurité Yubikey)

3. **Audit logs centralisés:**
   - Enregistrer tous accès (consultation, modification, partage)
   - Export SIEM (Splunk, ELK)

4. **Password policy:**
   - Complexité minimale forcée (12+ caractères, 3+ types)
   - Rotation obligatoire 90 jours
   - Vérification contre leaked passwords (Have I Been Pwned API)

5. **Vault sealing:**
   - Déchiffrement master key uniquement après connexion utilisateur
   - Timeout inactivité (lock après 15 min)

---

## 📊 Diagrammes UML à Générer

### 1. Diagramme de Cas d'Utilisation (Use Case Diagram)

**Acteurs:**
- Utilisateur Standard
- Administrateur
- Extension Navigateur
- Système Active Directory

**Cas d'utilisation principaux:**
- Se connecter (LDAP/SSO)
- Gérer mots de passe (CRUD)
- Générer mot de passe
- Importer/Exporter coffre-fort
- Partager mot de passe
- Révoquer partage
- Consulter partages
- Administrer utilisateurs AD
- Consulter statistiques sécurité
- Auto-fill formulaire (extension)

**Relations:**
- `<<include>>` : Login → Vérifier JWT
- `<<extend>>` : Partager → Définir expiration
- `<<generalization>>` : Administrateur hérite Utilisateur

---

### 2. Diagramme de Classes (Class Diagram)

**Classes principales:**

```
┌─────────────────┐
│   User          │
├─────────────────┤
│ -username       │
│ -displayName    │
│ -email          │
│ -groups[]       │
│ -isAdmin        │
├─────────────────┤
│ +authenticate() │
│ +getGroups()    │
└─────────────────┘
       ↓ owns
┌─────────────────┐
│   Password      │
├─────────────────┤
│ -id (UUID)      │
│ -title          │
│ -category       │
│ -websiteUrl     │
│ -username       │
│ -password (enc) │
│ -notes          │
│ -owner          │
│ -createdAt      │
│ -updatedAt      │
├─────────────────┤
│ +encrypt()      │
│ +decrypt()      │
│ +share()        │
│ +revoke()       │
└─────────────────┘
       ↓ has many
┌─────────────────┐
│ SharedPassword  │
├─────────────────┤
│ -id             │
│ -passwordId     │
│ -owner          │
│ -sharedWith     │
│ -permission     │
│ -expiresAt      │
│ -sharedAt       │
├─────────────────┤
│ +isExpired()    │
│ +canWrite()     │
└─────────────────┘

┌─────────────────┐
│PasswordHistory  │
├─────────────────┤
│ -id             │
│ -passwordId     │
│ -oldHash        │
│ -changedBy      │
│ -changedAt      │
└─────────────────┘

┌─────────────────┐
│    UserKey      │
├─────────────────┤
│ -username       │
│ -publicKey      │
│ -privateKeyEnc  │
└─────────────────┘
```

**Relations:**
- User `1 ────< *` Password (owns)
- Password `1 ────< *` SharedPassword
- Password `1 ────< *` PasswordHistory
- User `1 ──── 1` UserKey
- SharedPassword `* ────> 1` User (sharedWith)

---

### 3. Diagramme de Séquence — Authentification LDAP

```
┌──────┐          ┌──────────┐          ┌─────────┐          ┌──────┐
│Client│          │ Backend  │          │  LDAP   │          │  DB  │
└──┬───┘          └────┬─────┘          └────┬────┘          └──┬───┘
   │                   │                     │                  │
   │ POST /auth/login  │                     │                  │
   ├──────────────────>│                     │                  │
   │ {username,pwd}    │                     │                  │
   │                   │                     │                  │
   │                   │  LDAP bind(user)    │                  │
   │                   ├────────────────────>│                  │
   │                   │                     │                  │
   │                   │   bind success      │                  │
   │                   │<────────────────────┤                  │
   │                   │                     │                  │
   │                   │  search groups      │                  │
   │                   ├────────────────────>│                  │
   │                   │                     │                  │
   │                   │  groups[]           │                  │
   │                   │<────────────────────┤                  │
   │                   │                                        │
   │                   │  generate JWT(user, groups, exp=24h)   │
   │                   │──────────────────────────────────────┐ │
   │                   │                                      │ │
   │                   │<─────────────────────────────────────┘ │
   │                   │                                        │
   │  200 OK           │                                        │
   │  {token, user}    │                                        │
   │<──────────────────┤                                        │
   │                   │                                        │
   │  Store JWT        │                                        │
   │  sessionStorage   │                                        │
   │─────────────────┐ │                                        │
   │                 │ │                                        │
   │<────────────────┘ │                                        │
```

---

### 4. Diagramme de Séquence — Création Mot de Passe Chiffré

```
┌──────┐     ┌──────────┐     ┌────────┐     ┌──────┐
│Client│     │ Backend  │     │ Crypto │     │  DB  │
└──┬───┘     └────┬─────┘     └───┬────┘     └──┬───┘
   │              │               │              │
   │ POST /vault  │               │              │
   ├─────────────>│               │              │
   │ +anti-replay │               │              │
   │              │               │              │
   │              │ verify JWT    │              │
   │              │──────────┐    │              │
   │              │          │    │              │
   │              │<─────────┘    │              │
   │              │               │              │
   │              │ encrypt(pwd)  │              │
   │              ├──────────────>│              │
   │              │               │              │
   │              │   generate IV │              │
   │              │   AES-256-GCM │              │
   │              │   return      │              │
   │              │   {iv,enc,tag}│              │
   │              │<──────────────┤              │
   │              │                              │
   │              │  INSERT INTO passwords       │
   │              ├─────────────────────────────>│
   │              │  VALUES(id,title,...,owner)  │
   │              │                              │
   │              │  created row                 │
   │              │<─────────────────────────────┤
   │              │                              │
   │  201 Created │                              │
   │  {password}  │                              │
   │<─────────────┤                              │
```

---

### 5. Diagramme de Séquence — Partage de Mot de Passe

```
┌──────┐     ┌──────────┐     ┌──────┐     ┌──────┐
│Owner │     │ Backend  │     │ LDAP │     │  DB  │
└──┬───┘     └────┬─────┘     └──┬───┘     └──┬───┘
   │              │              │             │
   │ POST /vault/:id/share       │             │
   ├─────────────>│              │             │
   │ {sharedWith, │              │             │
   │  permission, │              │             │
   │  expiresAt}  │              │             │
   │              │              │             │
   │              │ verify owner │             │
   │              │ SELECT owner │             │
   │              ├─────────────────────────────>│
   │              │              │             │
   │              │<────────────────────────────┤
   │              │              │             │
   │              │ check user   │             │
   │              │ exists in AD │             │
   │              ├─────────────>│             │
   │              │              │             │
   │              │ user found   │             │
   │              │<─────────────┤             │
   │              │                            │
   │              │ INSERT SharedPassword      │
   │              ├───────────────────────────>│
   │              │                            │
   │              │ share created              │
   │              │<───────────────────────────┤
   │              │                            │
   │  200 OK      │                            │
   │<─────────────┤                            │
```

---

### 6. Diagramme d'État — Cycle de Vie Mot de Passe

```
        [*]
         │
         ↓
    ┌─────────┐
    │ Created │
    └────┬────┘
         │
         ↓
    ┌─────────┐
    │ Active  │←──────────┐
    └────┬────┘           │
         │                │
    ┌────┴────┬───────┐   │
    │         │       │   │
    ↓         ↓       ↓   │
┌────────┐ ┌──────┐ ┌──────────┐
│ Shared │ │Modified│ │Consulted │
└────┬───┘ └──┬───┘ └──────────┘
     │        │
     │        │
     └────┬───┘
          │
          ↓
     ┌─────────┐
     │ Expired │ (si partage avec expiresAt)
     └────┬────┘
          │
          ↓
     ┌─────────┐
     │ Deleted │
     └─────────┘
          │
          ↓
        [*]
```

---

### 7. Diagramme de Composants (Component Diagram)

```
┌────────────────────────────────────────────┐
│           Frontend (SPA)                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ index.   │  │  app.js  │  │ style.   │ │
│  │  html    │  │  (1800   │  │  css     │ │
│  │          │  │  lines)  │  │          │ │
│  └──────────┘  └──────────┘  └──────────┘ │
└───────────────────┬────────────────────────┘
                    │ HTTPS + JWT
                    │
┌───────────────────┴────────────────────────┐
│          Backend (Node.js/Express)         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ server.js│  │ routes.js│  │antiReplay│ │
│  └──────────┘  └──────────┘  └──────────┘ │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │   db.js  │  │ crypto.js│  │  ldap.js │ │
│  └────┬─────┘  └──────────┘  └────┬─────┘ │
└───────┼─────────────────────────────┼──────┘
        │                             │
        ↓                             ↓
┌──────────────┐            ┌──────────────┐
│  PostgreSQL  │            │Active        │
│  + Prisma    │            │Directory     │
│              │            │(LDAP)        │
└──────────────┘            └──────────────┘

┌────────────────────────────────────────────┐
│      Extensions (Chrome/Firefox)           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │background│  │ content. │  │  popup.  │ │
│  │   .js    │  │   js     │  │   js     │ │
│  └──────────┘  └──────────┘  └──────────┘ │
└────────────────────┬───────────────────────┘
                     │ fetch() API
                     │
                     └──────> Backend
```

---

### 8. Diagramme d'Architecture Globale

```
┌─────────────────────────────────────────────┐
│             Couche Présentation             │
│                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Web     │  │  Chrome  │  │ Firefox  │  │
│  │  App     │  │Extension │  │Extension │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
└───────┼─────────────┼─────────────┼─────────┘
        │             │             │
        └─────────────┼─────────────┘
                      │ HTTPS/TLS
        ┌─────────────┴─────────────┐
        │                           │
┌───────▼────────────────────────────────────┐
│          Couche Application                │
│                                            │
│  ┌──────────────────────────────────────┐ │
│  │  Express.js API Server               │ │
│  │  - Routes (CRUD, Auth, Admin)        │ │
│  │  - Middlewares (JWT, Anti-replay)    │ │
│  └──────────────────────────────────────┘ │
│                                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │  LDAP    │  │  Crypto  │  │  ORM     │ │
│  │  Client  │  │  Service │  │ (Prisma) │ │
│  └──────────┘  └──────────┘  └────┬─────┘ │
└───────────────────────────────────┼───────┘
                                    │
┌───────────────────────────────────┼───────┐
│           Couche Données          │       │
│                                   │       │
│  ┌──────────────┐      ┌──────────▼─────┐│
│  │Active        │      │  PostgreSQL    ││
│  │Directory     │      │  (passwords,   ││
│  │(LDAP)        │      │   shares, ...)  ││
│  └──────────────┘      └────────────────┘│
└───────────────────────────────────────────┘
```

---

## 🎯 Questions pour DeepSeek

Après analyse de cette architecture, réponds aux questions suivantes:

### Questions Architecturales

1. **Analyse la séparation des responsabilités:**
   - Les couches sont-elles bien séparées (Présentation / Logique / Données) ?
   - Y a-t-il des violations du principe Single Responsibility ?

2. **Sécurité:**
   - Identifie les vecteurs d'attaque possibles
   - Le chiffrement AES-256-GCM est-il correctement implémenté ?
   - L'anti-replay protection est-elle suffisante ?

3. **Scalabilité:**
   - Le Set mémoire pour nonces est-il scalable ?
   - Quelle serait la meilleure architecture pour 10 000+ utilisateurs ?

4. **Base de données:**
   - Les relations Prisma sont-elles optimales ?
   - Manque-t-il des index pour performance ?
   - Le double mode (JSON/Prisma) est-il une bonne pratique ?

5. **Améliorations:**
   - Quelles sont les 5 fonctionnalités prioritaires pour v3.0 ?
   - Comment implémenter le chiffrement E2E (RSA) ?

### Tâches UML

Génère les diagrammes suivants en **format PlantUML** ou **Mermaid**:

1. ✅ Diagramme de cas d'utilisation complet
2. ✅ Diagramme de classes avec toutes les relations
3. ✅ Diagramme de séquence: Authentification LDAP
4. ✅ Diagramme de séquence: Création mot de passe chiffré
5. ✅ Diagramme de séquence: Partage de mot de passe
6. ✅ Diagramme de séquence: Import CSV
7. ✅ Diagramme d'état: Cycle de vie mot de passe
8. ✅ Diagramme de composants
9. ✅ Diagramme de déploiement (serveurs, réseau)
10. ✅ Diagramme d'architecture N-tiers

---

## 📝 Format de Sortie Souhaité

Pour chaque diagramme, fournis:

1. **Code PlantUML/Mermaid** (copier-coller ready)
2. **Explication textuelle** des éléments clés
3. **Justification** des choix de design
4. **Points d'amélioration** identifiés

Exemple format:
```
### Diagramme de Cas d'Utilisation

#### Code PlantUML:
@startuml
...
@enduml

#### Explication:
...

#### Justification:
...

#### Améliorations possibles:
...
```

---

**Merci d'analyser ce projet en profondeur et de générer tous les diagrammes UML demandés !**
