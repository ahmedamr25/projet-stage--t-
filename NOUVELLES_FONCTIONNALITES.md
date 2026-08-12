# 🚀 Nouvelles Fonctionnalités — SecurPass

Ce document décrit les 3 nouvelles fonctionnalités ajoutées au gestionnaire de mots de passe SecurPass.

---

## 1. 📊 Migration PostgreSQL + Prisma

### Qu'est-ce que c'est ?
Le système de stockage a été modernisé :
- **Avant** : Fichier JSON local (`data/db.json`)
- **Après** : Base de données PostgreSQL (production) + JSON (développement)

### Avantages
- ✅ Transactions atomiques
- ✅ Gestion de la concurrence
- ✅ Migrations versionnées
- ✅ Requêtes optimisées (indexes)
- ✅ Relations entre tables (partages, historique)

### Configuration

#### Mode JSON (par défaut — sans configuration)
Aucune configuration requise. Le système utilise automatiquement `data/db.json`.

#### Mode PostgreSQL
Ajoutez cette ligne dans `backend/.env` :

```
DATABASE_URL="postgresql://user:password@localhost:5432/securpass"
```

Puis exécutez la migration :

```bash
cd backend
npx prisma migrate dev --name init
```

---

## 2. 📦 Import / Export

### Export CSV

**Bouton** : "Exporter en CSV" dans la section coffre-fort

**Format** :
```csv
title,url,username,password,category,notes
GitHub,https://github.com,john,SuperPass2026!,Professionnel,Clé SSH
Gmail,https://gmail.com,john@gmail.com,MonPass!,Personnel,
```

**Compatible avec** : Excel, Google Sheets, LibreOffice

⚠️ **Attention** : Le fichier contient vos mots de passe **en clair**. Supprimez-le après usage.

---

### Export JSON Bitwarden

**Bouton** : "Exporter en JSON Bitwarden"

**Format** : Compatible avec Bitwarden, 1Password (via import CSV), et autres gestionnaires.

```json
{
  "items": [
    {
      "name": "GitHub",
      "login": {
        "username": "john",
        "password": "SuperPass2026!",
        "uris": [{ "uri": "https://github.com" }]
      }
    }
  ]
}
```

---

### Import

**Formats acceptés** :
- CSV (Chrome, Firefox, Edge, SecurPass)
- JSON Bitwarden

**Comment importer** :
1. Ouvrez la section **Coffre-fort**
2. Cliquez sur **"Importer"**
3. Sélectionnez le format (CSV ou JSON)
4. Choisissez le fichier
5. Cliquez sur **"Importer maintenant"**

**Colonnes CSV détectées automatiquement** :
- `title` / `name` / `nom`
- `url` / `websiteurl` / `website`
- `username` / `login` / `identifiant`
- `password` / `mot de passe` *(obligatoire)*
- `category` / `catégorie` / `folder`
- `notes` / `note` / `commentaire`

**Exemple d'import depuis Chrome** :
1. Chrome → Paramètres → Gestionnaire de mots de passe
2. ⋮ (trois points) → Exporter les mots de passe
3. Fichier CSV téléchargé
4. Importez-le dans SecurPass

---

## 3. 🔗 Partage de Mots de Passe

### Qu'est-ce que c'est ?
Partagez un mot de passe avec un collègue de votre Active Directory.

### Cas d'usage
- Compte serveur partagé entre l'équipe DevOps
- Compte client à partager avec le service support
- Accès temporaire pour un stagiaire

---

### Comment partager ?

1. Ouvrez un mot de passe dans votre coffre-fort
2. Cliquez sur **"Partager"** (icône de partage)
3. Remplissez le formulaire :

```
┌────────────────────────────────────┐
│ Partager avec :                    │
│  [ahmed          ▼] (recherche AD) │
│                                    │
│ Permission :                       │
│  ● Lecture seule                   │
│  ○ Lecture + Modification          │
│                                    │
│ Expiration :                       │
│  [7 jours ▼] ou [Jamais]          │
│                                    │
│  [Partager]  [Annuler]            │
└────────────────────────────────────┘
```

4. Le destinataire verra le mot de passe dans **"Partagés avec moi"**

---

### Permissions

| Permission | Peut voir | Peut modifier | Peut supprimer |
|------------|-----------|---------------|----------------|
| **Lecture** | ✅ | ❌ | ❌ |
| **Lecture + Écriture** | ✅ | ✅ | ❌ |

**Note** : Seul le propriétaire peut supprimer un mot de passe ou révoquer un partage.

---

### Voir les partages actifs

**Bouton** : "Gérer les accès" sur une carte de mot de passe

Vous verrez :
- Qui a accès
- Permission accordée
- Date d'expiration
- Bouton "Révoquer"

---

### Mots de passe partagés avec moi

**Onglet** : "Partagés avec moi" dans la navigation

Affiche tous les mots de passe que vos collègues ont partagés avec vous.

**Icônes** :
- 👁️ Lecture seule
- ✏️ Lecture + Modification
- ⏰ Expire le [date]

---

## 🔧 Configuration requise

### Partage entre utilisateurs
Nécessite :
- Active Directory / LDAP configuré
- Les utilisateurs doivent exister dans l'annuaire AD

### Base de données
Recommandé pour la production :
- PostgreSQL 12+
- Prisma installé : `npm install @prisma/client prisma`

---

## 📝 Notes de sécurité

### Chiffrement
- Les mots de passe sont **toujours** chiffrés en base (AES-256-GCM)
- Les exports CSV/JSON contiennent des mots de passe **en clair**
- Le partage utilise un token serveur (pour E2E complet, RSA recommandé)

### Recommandations
1. Supprimez les fichiers d'export après usage
2. Révoquez les partages expirés régulièrement
3. Utilisez PostgreSQL en production (pas JSON)
4. Activez HTTPS obligatoire (TLS)

---

## 🐛 Résolution de problèmes

### Import échoue
- Vérifiez que la colonne `password` existe
- Encodage UTF-8 requis (pas ISO-8859-1)
- Guillemets CSV doublés : `""` pas `\"`

### Partage invisible
- Vérifiez que le destinataire existe dans l'AD
- Vérifiez la date d'expiration
- Rechargez la page

### Prisma ne démarre pas
```bash
cd backend
npx prisma generate
npx prisma migrate dev
```

---

## 📚 API Endpoints

### Import/Export
```
GET  /api/vault/export/csv              → Télécharger CSV
GET  /api/vault/export/json             → Télécharger JSON Bitwarden
POST /api/vault/import                  → Importer (body: texte brut)
     Header: X-Import-Format: csv|bitwarden
```

### Partage
```
POST   /api/vault/:id/share             → Partager avec un utilisateur
GET    /api/vault/:id/shares            → Voir les partages d'un mot de passe
DELETE /api/vault/:id/share/:username   → Révoquer un partage
GET    /api/vault/shared-with-me        → Mots de passe partagés avec moi
```

---

## ✅ Checklist de déploiement

- [ ] PostgreSQL installé et configuré
- [ ] `DATABASE_URL` dans le `.env`
- [ ] Migration Prisma exécutée
- [ ] Dépendances npm installées (`@prisma/client`, `multer`, `csv-parse`)
- [ ] Tests d'import avec un fichier Chrome
- [ ] Test de partage entre 2 utilisateurs AD
- [ ] HTTPS activé en production

---

**Version** : 2.0.0  
**Date** : 28 juillet 2026  
**Auteur** : Projet Stage SecurPass
