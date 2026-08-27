# 🛡️ Guide de Démarrage, Recommandations Architecturales & Durcissement de la Sécurité

Ce document constitue la référence officielle pour :
1. **Démarrer et tester le projet SecurPass** (Serveur Backend, Application Desktop et Extensions Navigateur).
2. **Identifier les choix architecturaux et les axes d'amélioration de la sécurité** nécessaires pour transformer le prototype de stage en une solution sécurisée prête pour un environnement de production d'entreprise (ex: passage de **LDAP** à **LDAPS**, gestion des clés, chiffrement, base de données, etc.).

---

## 📑 Sommaire

- [1. Présentation de l'Architecture](#1-présentation-de-larchitecture)
- [2. Guide de Démarrage Rapide](#2-guide-de-démarrage-rapide)
  - [2.1. Prérequis Système](#21-prérequis-système)
  - [2.2. Installation des Dépendances](#22-installation-des-dépendances)
  - [2.3. Lancement du Serveur Backend & Web](#23-lancement-du-serveur-backend--web)
  - [2.4. Lancement de l'Application Desktop Native](#24-lancement-de-lapplication-desktop-native)
  - [2.5. Installation de l'Extension Navigateur (DirectFill)](#25-installation-de-lextension-navigateur-directfill)
  - [2.6. Comptes de Démonstration (Mode Mock)](#26-comptes-de-démonstration-mode-mock)
- [3. Choix & Recommandations de Sécurité pour la Production](#3-choix--recommandations-de-sécurité-pour-la-production)
  - [🔒 3.1. Migration Critique : LDAP Simple (389) ➔ LDAPS Sécurisé (636 / StartTLS)](#-31-migration-critique--ldap-simple-389--ldaps-sécurisé-636--starttls)
  - [🌐 3.2. Chiffrement du Transit Réseau : Forcer HTTPS / TLS & HSTS](#-32-chiffrement-du-transit-réseau--forcer-https--tls--hsts)
  - [🔑 3.3. Gestion et Protection des Secrets & Clés de Chiffrement](#-33-gestion-et-protection-des-secrets--clés-de-chiffrement)
  - [🗄️ 3.4. Durcissement de la Persistance : Abandon du JSON vers PostgreSQL Durci](#️-34-durcissement-de-la-persistance--abandon-du-json-vers-postgresql-durci)
  - [🛡️ 3.5. Renforcement de l'Authentification & Gestion des Sessions](#️-35-renforcement-de-lauthentification--gestion-des-sessions)
  - [💻 3.6. Sécurité du Client Desktop & Extension Navigateur](#-36-sécurité-du-client-desktop--extension-navigateur)
  - [📊 3.7. Journalisation d'Audit, SIEM & Conformité (RGPD / NIS 2)](#-37-journalisation-daudit-siem--conformité-rgpd--nis-2)
- [4. Matrice Comparative : Développement vs Production](#4-matrice-comparative--développement-vs-production)
- [5. Checklist de Recette & Mise en Production (Production Readiness)](#5-checklist-de-recette--mise-en-production-production-readiness)

---

## 1. Présentation de l'Architecture

SecurPass est un gestionnaire de mots de passe d'entreprise hybride comprenant :
- **Un Backend Node.js / Express** : API REST, intégration Active Directory/LDAP, chiffrement AES-256-GCM, protection anti-rejeu, politiques de mots de passe et gestion des droits.
- **Une Application Frontend Web (SPA)** : Interface utilisateur responsive en Glassmorphism moderne (Coffre-fort, Générateur, TOTP/MFA, Import/Export, Logs d'audit).
- **Une Application Desktop Native Python (CustomTkinter + Playwright)** : Client bureau avec coffre-fort hors-ligne chiffré, déverrouillage biométrique / Windows Hello, et auto-remplissage via navigateur ou injection clavier.
- **Une Extension Navigateur (Chrome / Firefox Manifest V3)** : Remplissage automatique direct des formulaires web d'authentification.

```mermaid
graph TB
    subgraph Clients [Clients Utilisateur]
        Desktop["🖥️ Desktop App (Python CustomTkinter)"]
        Browser["🌐 Navigateur Web (SPA Glassmorphism)"]
        Extension["🧩 Extension Navigateur (Chrome / Firefox)"]
    end

    subgraph SecurityLayer [Couche Sécurité & Réseau]
        WAF["🛡️ Reverse Proxy / WAF (HTTPS / TLS 1.3)"]
        AntiReplay["⏱️ Middleware Anti-Rejeu & Rate Limiter"]
    end

    subgraph BackendAPI [Backend SecurPass API]
        Router["Express API Router (/api)"]
        AuthModule["Module Auth (JWT + RBAC + TOTP)"]
        CryptoModule["Module Chiffrement (AES-256-GCM)"]
    end

    subgraph DirectoryAndData [Annuaire & Persistance]
        AD["🏢 Active Directory / LDAPS (TLS Port 636)"]
        Postgres[("🗄️ PostgreSQL (Chiffrement SSL + TDE)")]
    end

    Desktop -->|API REST / HTTPS| WAF
    Browser -->|HTTPS / WSS| WAF
    Extension -->|API REST / Local Token| WAF

    WAF --> AntiReplay
    AntiReplay --> Router
    Router --> AuthModule
    Router --> CryptoModule

    AuthModule -->|LDAPS sécurisé| AD
    CryptoModule -->|Données Chiffrées| Postgres
```

---

## 2. Guide de Démarrage Rapide

### 2.1. Prérequis Système

| Composant | Version Minimale | Rôle |
| :--- | :--- | :--- |
| **Node.js** | `>= 18.x` (LTS recommandée) | Exécution du serveur Backend API |
| **npm** | `>= 9.x` | Gestionnaire de paquets Node.js |
| **Python** | `>= 3.10` | Exécution de l'application Desktop native |
| **PostgreSQL** | `>= 14.x` *(Optionnel en dev)* | Base de données de production (le mode dev utilise le fallback JSON) |
| **Google Chrome / Mozilla Firefox** | Récent | Test des extensions et du remplissage automatique |

---

### 2.2. Installation des Dépendances

Ouvrez un terminal PowerShell ou CMD à la racine du projet :

#### Étape 1 : Dépendances du Backend Node.js
```bash
cd backend
npm install
cd ..
```

#### Étape 2 : Dépendances de l'Application Desktop Python
```bash
pip install -r requirements.txt
python -m playwright install firefox chromium
```

---

### 2.3. Lancement du Serveur Backend & Web

Vous avez deux méthodes pour lancer le serveur :

#### Option A : Via le script batch (Recommandé sous Windows)
Double-cliquez sur `start-server.bat` à la racine du projet.

#### Option B : En ligne de commande
```bash
cd backend
node src/server.js
```

Le serveur démarre immédiatement sur :
- **HTTP** : [http://localhost:5000](http://localhost:5000)
- **HTTPS** *(si certificats générés)* : [https://localhost:5443](https://localhost:5443)

Accédez à [http://localhost:5000](http://localhost:5000) dans votre navigateur pour utiliser l'interface Web SPA.

---

### 2.4. Lancement de l'Application Desktop Native

#### Option A : Via le script batch
Double-cliquez sur `start-desktop.bat`. Ce script vérifie automatiquement l'environnement Python et démarre l'application.

#### Option B : En ligne de commande
```bash
python app.py
```

> **Note** : L'application Desktop démarre automatiquement le serveur backend en arrière-plan s'il n'est pas déjà actif.

---

### 2.5. Installation de l'Extension Navigateur (DirectFill)

#### Pour Google Chrome / Microsoft Edge / Brave :
1. Ouvrez votre navigateur et accédez à `chrome://extensions/`.
2. Activez le commutateur **"Mode développeur"** (en haut à droite).
3. Cliquez sur le bouton **"Charger l'extension non empaquetée"**.
4. Sélectionnez le dossier `chrome-extension/` de votre projet.
5. L'icône SecurPass apparaît dans votre barre d'extensions.

#### Pour Mozilla Firefox :
1. Accédez à `about:debugging#/runtime/this-firefox`.
2. Cliquez sur **"Charger un module temporaire..."**.
3. Sélectionnez le fichier `firefox-extension/manifest.json` ou le package `securpass-firefox.xpi`.

---

### 2.6. Comptes de Démonstration (Mode Mock)

Lorsque `LDAP_MOCK=true` est activé dans `backend/.env`, utilisez les identifiants préconfigurés suivants :

| Rôle | Identifiant | Mot de passe | Permissions |
| :--- | :--- | :--- | :--- |
| **Administrateur** | `admin` | `Admin@2026!` | Gestion complète, logs d'audit, utilisateurs, coffre |
| **Administrateur AD** | `administrateur` | `Admin@2026!` | Administration domaine |
| **Utilisateur Standard** | `user` | `User@2026!` | Gestion personnelle du coffre-fort |
| **Connexion SSO** | Bouton *"Connexion SSO"* | *(Automatique)* | Authentification basée sur le compte Windows local |

---

## 3. Choix & Recommandations de Sécurité pour la Production

> [!WARNING]
> En environnement de développement ou de stage, certaines simplifications ont été mises en place pour faciliter les tests (mode Mock, fallback JSON, clés par défaut, liaison LDAP non chiffrée). **Ces choix doivent impérativement être modifiés avant toute mise en production.**

---

### 🔒 3.1. Migration Critique : LDAP Simple (389) ➔ LDAPS Sécurisé (636 / StartTLS)

#### Le Problème du LDAP Simple (`ldap://` port 389) :
- En LDAP classique non chiffré, **toutes les requêtes circulent en texte clair sur le réseau d'entreprise**.
- Les identifiants des utilisateurs ainsi que le mot de passe du compte de service (`LDAP_BIND_PASSWORD`) peuvent être capturés par une simple écoute réseau (Wireshark, attaques ARP Spoofing / Man-in-the-Middle).

```
❌ FLUX NON SÉCURISÉ (LDAP) :
[SecurPass Backend] ──── Mot de passe en clair (Port 389) ────> [Active Directory]
                                ▲ (Vulnérable à l'interception réseau)
```

#### La Solution : LDAPS (`ldaps://` port 636 ou StartTLS port 389) :
- Établissement d'un tunnel TLS 1.3 / 1.2 chiffré avant toute transmission d'identifiants.
- Authentification mutuelle ou validation du certificat du contrôleur de domaine via l'autorité de certification (CA) d'entreprise.

```
✅ FLUX SÉCURISÉ (LDAPS) :
[SecurPass Backend] ═══ Tunnel TLS Chiffré AES-256 (Port 636) ═══> [Active Directory]
```

#### Comment configurer LDAPS dans SecurPass (`backend/.env`) :

```properties
# ==========================================
# CONFIGURATION ACTIVE DIRECTORY SÉCURISÉE (LDAPS)
# ==========================================
LDAP_MOCK=false
LDAPS_ENABLED=true

# Utiliser l'URL sécurisée en LDAPS (Port 636)
LDAP_URL=ldaps://dc01.tiznit.local:636
LDAPS_URL=ldaps://dc01.tiznit.local:636

LDAP_BASE_DN=dc=tiznit,dc=local
LDAP_USER_SUFFIX=@tiznit.local

# Compte de service dédié aux privilèges minimaux (Lecture seule de l'annuaire)
LDAP_BIND_DN=cn=svc-securpass,ou=ServiceAccounts,dc=tiznit,dc=local
LDAP_BIND_PASSWORD=V0treMotDePasseComplexeSvc2026!

# Validation stricte du certificat du contrôleur de domaine
LDAPS_REJECT_UNAUTHORIZED=true
LDAPS_CA_CERT_PATH=./certs/ca-enterprise-root.crt
```

#### Bonnes pratiques AD / LDAPS :
1. **Ne jamais utiliser le compte Administrateur du domaine** comme compte de liaison (`BIND_DN`). Créer un compte de service dédié `svc-securpass` avec des droits limités en lecture seule sur l'OU des utilisateurs.
2. **Installer un certificat serveur valide sur le contrôleur de domaine** émis par la PKI (Public Key Infrastructure) de l'organisation.
3. **Refuser les connexions avec certificats non validés** (`LDAPS_REJECT_UNAUTHORIZED=true`).

---

### 🌐 3.2. Chiffrement du Transit Réseau : Forcer HTTPS / TLS & HSTS

#### Risques liés au HTTP standard :
- Vol de jetons JWT de session dans les en-têtes HTTP `Authorization: Bearer <token>`.
- Interception des mots de passe déchiffrés transitant entre l'application et le client.

#### Recommandations & Mise en œuvre :
1. **Activer HTTPS dans le Backend Node.js** :
   Placer les certificats SSL/TLS valides dans `backend/certs/` ou configurer les variables :
   ```properties
   HTTPS_PORT=5443
   TLS_CERT_PATH=/etc/ssl/certs/securpass.crt
   TLS_KEY_PATH=/etc/ssl/private/securpass.key
   ```
2. **Utiliser un Reverse Proxy durci (Nginx / HAProxy / Traefik)** :
   Déléguer la terminaison TLS au reverse proxy avec TLS 1.3 uniquement et des suites de chiffrement modernes (Forward Secrecy).
3. **En-têtes de Sécurité HTTP (Déjà intégrés dans `server.js`)** :
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` (Force le HTTPS).
   - `X-Frame-Options: DENY` (Empêche les attaques de Clickjacking).
   - `X-Content-Type-Options: nosniff` (Empêche le reniflage de type MIME).
   - `Content-Security-Policy` (CSP stricte pour neutraliser les failles XSS).

---

### 🔑 3.3. Gestion et Protection des Secrets & Clés de Chiffrement

#### Risques des configurations par défaut :
- Le fichier `.env` actuel contient des clés d'exemple (`JWT_SECRET` et `ENCRYPTION_KEY`). Si ces clés sont conservées en production ou fuitent sur GitHub, un attaquant peut forger des tokens administrateur et déchiffrer tous les coffres-forts de la base de données.

#### Actions obligatoires :
1. **Génération de clés cryptographiquement fortes** :
   Générez des clés aléatoires à haute entropie via Node.js :
   ```bash
   # Clé AES-256 (32 octets = 64 caractères hexadécimaux)
   node -e "console.log('ENCRYPTION_KEY=' + require('crypto').randomBytes(32).toString('hex'))"

   # Secret JWT (64 octets = 128 caractères hexadécimaux)
   node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(64).toString('hex'))"
   ```
2. **Utilisation d'un Gestionnaire de Secrets d'Entreprise** :
   - Plutôt que de stocker les clés dans des fichiers texte `.env` sur le disque du serveur, intégrer :
     * **HashiCorp Vault**
     * **AWS Secrets Manager / Azure Key Vault**
     * **Windows DPAPI / Credential Manager** (pour le client desktop)
3. **Exclusion stricte des dépôts Git** :
   - Vérifier que `.env` et les clés `.key` / `.crt` sont bien présents dans `.gitignore`.
   - Fournir uniquement un fichier `.env.example` anonymisé.

---

### 🗄️ 3.4. Durcissement de la Persistance : Abandon du JSON vers PostgreSQL Durci

#### Risques du fichier `data/db.json` :
- Absence d'isolation multi-processus, risques de corruption de données en cas d'accès concurrents élevés.
- Fichier non chiffré nativement sur le disque (les mots de passe sont chiffrés en AES-GCM mais les métadonnées/noms d'utilisateurs restent lisibles).

#### Architecture Recommandée (PostgreSQL + Prisma) :

```properties
# backend/.env (Mode Production)
DATABASE_URL="postgresql://securpass_app:MotDePasseDbUltraSecurise2026@db-prod.tiznit.local:5432/securpass_db?sslmode=require"
```

#### Mesures de durcissement PostgreSQL :
1. **Principe du Moindre Privilège** : Ne jamais exécuter l'application avec l'utilisateur `postgres` (Superadmin). Créer un rôle applicatif dédié `securpass_app` avec des droits restreints aux tables nécessaires (`SELECT`, `INSERT`, `UPDATE`, `DELETE`).
2. **Chiffrement en Transit SSL (`sslmode=verify-full`)** : Forcer le chiffrement SSL entre le backend Node.js et le serveur PostgreSQL.
3. **Chiffrement au Repos (TDE - Transparent Data Encryption)** : Activer le chiffrement du volume de stockage de la base de données (LUKS sous Linux ou BitLocker sous Windows Server).
4. **Sauvegardes Automatiques Chiffrées** : Mettre en place des sauvegardes périodiques automatiques (`pg_dump`) chiffrées avec GPG/AES avant externalisation.

---

### 🛡️ 3.5. Renforcement de l'Authentification & Gestion des Sessions

#### 1. Double Facteur d'Authentification (2FA / TOTP RFC 6238)
- Rendre le 2FA **obligatoire** pour tous les comptes ayant des privilèges administrateur.
- Stocker les secrets TOTP chiffrés avec la clé AES-256 dans la base de données.

#### 2. Durée de Vie des Jetons JWT & Révocation
- **En développement** : Tokens à longue durée de vie pour la commodité.
- **En production** :
  * Access Token JWT : Durée de vie courte (**15 à 30 minutes maximum**).
  * Refresh Token : Stocké en base de données avec empreinte, associable à une session révocable à distance par l'administrateur.
  * Invalidation immédiate des tokens lors d'un changement de mot de passe ou d'une déconnexion (Blacklist de tokens via Redis).

#### 3. Politique Anti-Brute Force et Verrouillage (`loginAttempts.js`)
- Limiter les tentatives de connexion à **5 échecs consécutifs**.
- Verrouillage progressif temporaire (15 minutes), puis notification d'alerte à l'administrateur de sécurité.
- Détection et blocage des attaques par force brute distribuées via Rate Limiting par adresse IP.

#### 4. Intégration SSO Entreprise Avancée (Kerberos / SPNEGO)
- En production dans un domaine Active Directory Windows, remplacer la simulation NTLM/Headers par une négociation **SPNEGO / Kerberos native** via ticket de service Active Directory (`HTTP/securpass.domaine.local`).

---

### 💻 3.6. Sécurité du Client Desktop & Extension Navigateur

#### Client Desktop Python (`app.py`) :
1. **Protection du Coffre Hors-Ligne (`offline_vault.json.enc`)** :
   - Le cache local est déjà chiffré en AES-GCM dérivé par PBKDF2 (100 000 itérations).
   - *Amélioration recommandée* : Lier la clé de déchiffrement locale au **TPM (Trusted Platform Module)** de la machine ou à **Windows Hello / DPAPI** (`CryptProtectData`) pour empêcher la copie du fichier de cache sur un autre ordinateur.
2. **Nettoyage de la Mémoire Vive (Memory Zeroing)** :
   - Écraser les chaînes de caractères contenant des mots de passe en mémoire dès la fin de leur utilisation (éviter les fuites lors d'un dump mémoire du processus).
3. **Verrouillage Automatique par Inactivité** :
   - Verrouiller automatiquement la session bureau après **5 à 10 minutes d'inactivité** de l'utilisateur.

#### Extension Navigateur (Chrome / Firefox) :
1. **Validation Stricte des Domaines (Anti-Phishing)** :
   - Avant de procéder au remplissage automatique, vérifier la concordance exacte de l'origine (`window.location.origin` et nom de domaine pleinement qualifié).
   - Refuser le remplissage sur les pages HTTP non sécurisées ou dans des iframes non autorisées.
2. **Communication Inter-Processus Sécurisée** :
   - Utiliser des messages internes chiffrés ou signés entre les `content-scripts` et le `background service worker`.

---

### 📊 3.7. Journalisation d'Audit, SIEM & Conformité (RGPD / NIS 2)

Le module `auditLog.js` trace actuellement les événements critiques. Pour une conformité d'entreprise :
1. **Exportation vers un SIEM Centralisé** :
   - Transmettre les logs d'audit en temps réel vers une plateforme SIEM (Splunk, Elastic SIEM, Wazuh, Graylog) via Syslog sécurisé (TLS/TCP).
2. **Immutabilité des Logs (Append-Only)** :
   - Empêcher toute modification ou suppression des journaux, même par un administrateur système.
3. **Événements critiques à tracer obligatoirement** :
   - Tentatives de connexion réussies et échouées.
   - Création, modification, consultation et suppression de mots de passe.
   - Exports de données (CSV / JSON) avec identité de l'auteur et adresse IP source.
   - Modifications des droits administrateur ou des politiques de sécurité.

---

## 4. Matrice Comparative : Développement vs Production

| Critère / Composant | 🧪 Configuration Développement / Stage | 🚀 Configuration Production Recommandée |
| :--- | :--- | :--- |
| **Protocole Annuaire** | `ldap://` (Port 389 - non chiffré) ou Mock | `ldaps://` (Port 636 - TLS 1.3 chiffré) avec validation CA |
| **Protocole Web/API** | `http://localhost:5000` | `https://securpass.domaine.com` (TLS 1.3 / HSTS) |
| **Base de Données** | JSON local (`data/db.json`) | **PostgreSQL** avec chiffrement SSL et sauvegardes auto |
| **Gestion des Clés** | Fichier `.env` en local | **Gestionnaire de Secrets** (Vault, Azure Key Vault, AWS KMS) |
| **Clé AES-256 & JWT** | Clés par défaut du dépôt | Clés aléatoires cryptographiques uniques générées |
| **Authentification** | Mot de passe simple / Mock SSO | **LDAPS + 2FA / TOTP obligatoire** + SSO Kerberos SPNEGO |
| **Durée Token JWT** | 24 heures | **15 - 30 minutes** + Refresh Token révocable |
| **Politique CORS** | `localhost:5000`, `localhost:5443` | Domaines stricts d'entreprise (ex: `https://*.monentreprise.com`) |
| **Logs d'Audit** | Fichier local / Base locale | Envoi sécurisé vers **SIEM d'entreprise (Wazuh, Splunk)** |
| **Stockage Cache Desktop** | PBKDF2 + AES-GCM local | **DPAPI Windows / TPM** + Verrouillage inactivité (5 min) |

---

## 5. Checklist de Recette & Mise en Production (Production Readiness)

Avant de déployer SecurPass sur l'infrastructure de production de votre organisation, validez l'ensemble des points suivants :

### 🔐 1. Cryptographie & Secrets
- [ ] La variable `ENCRYPTION_KEY` a été générée de manière aléatoire (64 caractères hex).
- [ ] La variable `JWT_SECRET` a été renouvelée et possède une entropie suffisante (> 64 octets).
- [ ] Aucun fichier `.env` contenant de véritables secrets n'est archivé dans le système de contrôle de version Git.

### 🏢 2. Annuaire & Authentification
- [ ] `LDAP_MOCK` est positionné à `false`.
- [ ] `LDAPS_ENABLED=true` avec le port `636` et l'URL `ldaps://`.
- [ ] Le certificat racine d'entreprise est renseigné dans `LDAPS_CA_CERT_PATH`.
- [ ] `LDAPS_REJECT_UNAUTHORIZED=true` est actif.
- [ ] Le compte de liaison LDAP est un compte de service dédié non-administrateur.
- [ ] Le second facteur d'authentification (TOTP / 2FA) est activé pour les comptes sensibles.

### 🌐 3. Réseau & Serveur
- [ ] Un certificat TLS valide est installé (fourni par une autorité de certification reconnue ou PKI interne).
- [ ] Le port HTTP 80 / 5000 redirige automatiquement vers le port HTTPS sécurisé.
- [ ] Les en-têtes de sécurité (`HSTS`, `X-Frame-Options`, `CSP`, `X-Content-Type-Options`) sont validés.
- [ ] La politique CORS est restreinte aux seuls domaines autorisés de l'entreprise.

### 🗄️ 4. Base de Données
- [ ] PostgreSQL est installé et configuré en tant que source de données primaire.
- [ ] L'utilisateur de la base de données possède des privilèges limités à la seule base `securpass`.
- [ ] La connexion PostgreSQL force le mode SSL (`sslmode=require`).
- [ ] Un plan de sauvegarde quotidienne automatique et chiffrée de la base de données est opérationnel.

### 📊 5. Audit & Exploitation
- [ ] Les journaux d'événements sont archivés et protégés contre toute altération.
- [ ] Le système de limitation de débit (Rate Limiting) et de protection anti-rejeu est actif.
- [ ] Les alertes de sécurité en cas de tentatives d'intrusion répétées sont configurées.

---

> 💡 **Besoin d'aide supplémentaire ?**
> Consultez également les documents associés du projet :
> - [README.md](file:///c:/Users/Dell/Desktop/projet_stage/README.md) : Vue d'ensemble du projet et commandes rapides.
> - [NOUVELLES_FONCTIONNALITES.md](file:///c:/Users/Dell/Desktop/projet_stage/NOUVELLES_FONCTIONNALITES.md) : Détails sur PostgreSQL, Prisma et les imports/exports.
> - [LDAP_MIGRATION_V3.md](file:///c:/Users/Dell/Desktop/projet_stage/backend/LDAP_MIGRATION_V3.md) : Détails techniques sur l'intégration de la bibliothèque `ldapjs` v3.
