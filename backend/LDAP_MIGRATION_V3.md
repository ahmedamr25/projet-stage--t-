# Guide de Migration LDAP - Passage à `ldapjs` v3.x

Ce document explique les incompatibilités majeures introduites par la mise à jour de la bibliothèque `ldapjs` vers la version **3.x** dans le backend de l'application de gestion de mots de passe, ainsi que les solutions apportées pour y remédier.

---

## Sommaire
1. [Contexte](#contexte)
2. [Problème 1 : `stringToWrite must be a string`](#problème-1-stringtowrite-must-be-a-string)
3. [Problème 2 : Disparition de la propriété `.object` (Erreur `sAMAccountName`)](#problème-2-disparition-de-la-propriété-object-erreur-samaccountname)
4. [Solution implémentée : Le Helper `getEntryObject`](#solution-implémentée--le-helper-getentryobject)
5. [Structure comparative (v1/v2 vs v3)](#structure-comparative-v1v2-vs-v3)

---

## Contexte
La dépendance `ldapjs` du projet a été déclarée en version `^3.0.7` dans le fichier `package.json`. Les versions 3.x de `ldapjs` introduisent des modifications majeures de structure (Breaking Changes) qui cassent la compatibilité avec le code initialement écrit pour les versions 1.x ou 2.x.

---

## Problème 1 : `stringToWrite must be a string`

### Symptôme
Lors de la tentative d'authentification de l'utilisateur, l'erreur suivante survenait après la recherche réussie :
```text
[LDAP] Tentative de bind pour: CN=ahmed,CN=Users,DC=tiznit,DC=local
[LDAP] Échec bind utilisateur: ahmed - stringToWrite must be a string
```

### Cause
Dans la méthode `client.bind(dn, password, callback)`, le paramètre `dn` (Distinguished Name) doit être une **chaîne de caractères** (`string`).
* En version 1.x/2.x, `userEntry.dn` pouvait être directement converti ou était accepté tel quel.
* En version 3.x, `userEntry.dn` est un objet d'instance de la classe interne `DN`. Lors du passage de cet objet à la fonction `bind()`, le sérialiseur interne (`@ldapjs/asn1`) échoue car il attend une chaîne brute et lève l'exception `stringToWrite must be a string`.

### Solution
Convertir explicitement l'objet `DN` en chaîne de caractères en appelant sa méthode `.toString()` avant l'opération de liaison :
```javascript
// Avant
const userDN = userEntry.dn;

// Après (Correction)
const userDN = userEntry.dn.toString();
```

---

## Problème 2 : Disparition de la propriété `.object` (Erreur `sAMAccountName`)

### Symptôme
Une fois le problème du format de DN résolu, le serveur plantait avec l'erreur :
```text
TypeError: Cannot read properties of undefined (reading 'sAMAccountName')
    at file:///C:/Users/Dell/Desktop/projet_stage/backend/src/ldap.js:250:27
```

### Cause
Dans les anciennes versions de `ldapjs`, l'objet retourné lors de l'événement `searchEntry` disposait d'un accesseur `.object` très pratique. Cet accesseur convertissait automatiquement les attributs LDAP en un objet JavaScript plat (ex: `entry.object.sAMAccountName`, `entry.object.mail`).
Dans **`ldapjs` v3**, la propriété `.object` a été **supprimée**. Les attributs doivent désormais être récupérés via le tableau brut `entry.attributes` ou la propriété `.pojo` (Plain Old JavaScript Object).

### Solution
Nous avons implémenté une fonction helper personnalisée `getEntryObject(entry)` dans `src/ldap.js` pour recréer dynamiquement un objet plat similaire à l'ancienne propriété `.object` à partir du tableau d'attributs de la v3.

---

## Solution implémentée : Le Helper `getEntryObject`

Pour éviter de réécrire l'ensemble du code de récupération des attributs à travers l'application, nous avons introduit la fonction suivante dans [ldap.js](file:///c:/Users/Dell/Desktop/projet_stage/backend/src/ldap.js) :

```javascript
function getEntryObject(entry) {
  if (!entry) return {};
  
  // Rétrocompatibilité avec les mocks ou les anciens objets
  if (entry.object && !entry.attributes) {
    return entry.object;
  }
  
  const obj = {};
  // Récupération des attributs depuis le tableau d'attributs de la v3
  const attributes = entry.attributes || (entry.pojo && entry.pojo.attributes) || [];
  
  for (const attr of attributes) {
    const type = attr.type;
    const values = attr.values || [];
    
    let val;
    // Si l'attribut possède une seule valeur, on extrait la valeur brute
    if (values.length === 1) {
      val = values[0];
    } else if (values.length > 1) {
      val = values; // Tableau pour les attributs multi-valeurs (ex: memberOf)
    } else {
      val = null;
    }
    
    obj[type] = val;
    // Ajout d'une clé en minuscules pour assurer une tolérance à la casse
    obj[type.toLowerCase()] = val;
  }
  
  // Récupération sécurisée du DN
  if (entry.dn) {
    obj.dn = entry.dn.toString();
  } else if (entry.pojo && entry.pojo.objectName) {
    obj.dn = entry.pojo.objectName;
  }
  
  return obj;
}
```

### Application dans le code
Cette fonction est maintenant appelée dans :
* **La liaison par compte de service (`performServiceAccountBind`)** :
  ```javascript
  const obj = getEntryObject(userEntry);
  const userInfo = {
    username: obj.sAMAccountName || obj.samaccountname || username,
    displayName: obj.displayName || obj.displayname || obj.cn || username,
    email: obj.mail || `${username}${userSuffix}`,
    groups: extractGroups(obj.memberOf || obj.memberof)
  };
  ```
* **La liaison directe (`performDirectBind`)** :
  ```javascript
  res.on('searchEntry', (entry) => {
    const obj = getEntryObject(entry);
    userInfo.displayName = obj.displayName || obj.displayname || username;
    userInfo.email = obj.mail || userPrincipalName;
    userInfo.groups = extractGroups(obj.memberOf || obj.memberof);
  });
  ```

---

## Structure comparative (v1/v2 vs v3)

Voici une vue d'ensemble du format de l'entrée retournée par la recherche dans les deux versions de la bibliothèque :

### Ancien format (`ldapjs` v1/v2)
```json
{
  "dn": "CN=ahmed,CN=Users,DC=tiznit,DC=local",
  "object": {
    "dn": "CN=ahmed,CN=Users,DC=tiznit,DC=local",
    "sAMAccountName": "ahmed",
    "displayName": "Ahmed Utilisateur",
    "mail": "ahmed@tiznit.local",
    "memberOf": "CN=Domain Users,CN=Users,DC=tiznit,DC=local"
  }
}
```

### Nouveau format (`ldapjs` v3.x)
```json
{
  "dn": {}, // Objet de type DN (nécessite .toString())
  "attributes": [
    { "type": "sAMAccountName", "values": ["ahmed"] },
    { "type": "displayName", "values": ["Ahmed Utilisateur"] },
    { "type": "mail", "values": ["ahmed@tiznit.local"] },
    { "type": "memberOf", "values": ["CN=Domain Users,CN=Users,DC=tiznit,DC=local"] }
  ]
}
```

Grâce à notre helper, le code existant continue de consommer l'ancien format sans risque de régression.
