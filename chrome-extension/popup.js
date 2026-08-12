const API_URL = 'https://localhost:5443/api';

// Génère les headers anti-rejeu requis par le backend pour toutes les
// requêtes de mutation (POST / PUT / DELETE).
function getAntiReplayHeaders() {
  return {
    'X-Request-Nonce': crypto.randomUUID(),
    'X-Request-Timestamp': Date.now().toString()
  };
}

// Références DOM
const screenLoggedOut = document.getElementById('screen-logged-out');
const screenLoggedIn = document.getElementById('screen-logged-in');
const btnImportSession = document.getElementById('btn-import-session');
const btnLogout = document.getElementById('btn-logout');
const importError = document.getElementById('import-error');
const activeDomainText = document.getElementById('active-domain-text');
const suggestionsList = document.getElementById('suggestions-list');
const suggestionsEmpty = document.getElementById('suggestions-empty');
const searchInput = document.getElementById('search-input');
const allVaultContainer = document.getElementById('all-vault-container');
const allVaultList = document.getElementById('all-vault-list');
const toggleAllVault = document.getElementById('toggle-all-vault');
const userBadge = document.getElementById('logged-user');
const userDisplay = document.getElementById('user-display');

// Références - logs d'inscription
const toggleRegistrationLogs = document.getElementById('toggle-registration-logs');
const registrationLogsContainer = document.getElementById('registration-logs-container');
const registrationLogsList = document.getElementById('registration-logs-list');
const registrationLogsEmpty = document.getElementById('registration-logs-empty');
const btnClearLogs = document.getElementById('btn-clear-logs');

// Références - ajout de compte
const btnOpenAdd = document.getElementById('btn-open-add');
const btnCloseAdd = document.getElementById('btn-close-add');
const modalAddEntry = document.getElementById('modal-add-entry');
const formAddEntry = document.getElementById('form-add-entry');
const inputTitle = document.getElementById('input-title');
const inputUrl = document.getElementById('input-url');
const inputUsername = document.getElementById('input-username');
const inputPassword = document.getElementById('input-password');
const btnTogglePwdVisibility = document.getElementById('btn-toggle-pwd-visibility');
const btnGeneratePwd = document.getElementById('btn-generate-pwd');
const rangePwdLength = document.getElementById('range-pwd-length');
const pwdLengthValue = document.getElementById('pwd-length-value');
const optUpper = document.getElementById('opt-upper');
const optDigits = document.getElementById('opt-digits');
const optSymbols = document.getElementById('opt-symbols');
const addEntryError = document.getElementById('add-entry-error');

let activeTab = null;
let activeDomain = '';
let vaultItems = [];

// Initialisation
document.addEventListener('DOMContentLoaded', async () => {
  // Récupérer l'onglet actif et son domaine
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs[0]) {
      activeTab = tabs[0];
      activeDomain = getDomain(activeTab.url);
      activeDomainText.textContent = activeDomain || 'Page locale / non HTTP';
    }
  } catch (e) {
    console.error("Impossible d'obtenir l'onglet actif:", e);
  }

  // Écouteurs d'événements
  btnImportSession.addEventListener('click', importSession);
  btnLogout.addEventListener('click', logout);
  searchInput.addEventListener('input', handleSearch);
  toggleAllVault.addEventListener('click', () => {
    allVaultContainer.classList.toggle('hidden');
    toggleAllVault.classList.toggle('active');
  });
  toggleRegistrationLogs.addEventListener('click', async () => {
    registrationLogsContainer.classList.toggle('hidden');
    toggleRegistrationLogs.classList.toggle('active');
    if (!registrationLogsContainer.classList.contains('hidden')) {
      await loadRegistrationLogs();
    }
  });
  btnClearLogs.addEventListener('click', async () => {
    const token = localStorage.getItem('securpass_token');
    if (!token) return;
    try {
      const res = await fetch(`${API_URL}/registration-logs`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}`, ...getAntiReplayHeaders() }
      });
      if (res.ok) {
        renderRegistrationLogs([]);
      }
    } catch (e) {
      console.warn('Impossible de supprimer les logs :', e);
    }
  });
  chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.active) {
      await fillCurrentPageAutomatically();
    }
  });

  btnOpenAdd.addEventListener('click', openAddEntry);
  btnCloseAdd.addEventListener('click', closeAddEntry);
  modalAddEntry.addEventListener('click', (e) => {
    if (e.target === modalAddEntry) closeAddEntry();
  });
  formAddEntry.addEventListener('submit', handleAddEntry);
  btnTogglePwdVisibility.addEventListener('click', () => {
    inputPassword.type = inputPassword.type === 'password' ? 'text' : 'password';
  });
  btnGeneratePwd.addEventListener('click', () => {
    inputPassword.type = 'text';
    inputPassword.value = generatePassword({
      length: parseInt(rangePwdLength.value, 10),
      upper: optUpper.checked,
      digits: optDigits.checked,
      symbols: optSymbols.checked
    });
  });
  rangePwdLength.addEventListener('input', () => {
    pwdLengthValue.textContent = rangePwdLength.value;
  });

  // Vérifier si un token existe déjà dans l'extension
  const savedToken = localStorage.getItem('securpass_token');
  const savedUser = localStorage.getItem('securpass_user');
  
  if (savedToken && savedUser) {
    try {
      showLoggedInState(savedToken, JSON.parse(savedUser));
    } catch {
      showLoggedOutState();
    }
  } else {
    showLoggedOutState();
  }
});

// Extraire l'hôte de l'URL
function getDomain(urlStr) {
  if (!urlStr) return '';
  try {
    const url = new URL(urlStr);
    return url.hostname.replace('www.', '');
  } catch (e) {
    return '';
  }
}

// État Déconnecté
function showLoggedOutState() {
  screenLoggedOut.classList.remove('hidden');
  screenLoggedIn.classList.add('hidden');
  userBadge.classList.add('hidden');
  btnLogout.classList.add('hidden');
  btnOpenAdd.classList.add('hidden');
}

// État Connecté
async function showLoggedInState(token, user) {
  screenLoggedOut.classList.add('hidden');
  screenLoggedIn.classList.remove('hidden');
  userBadge.classList.remove('hidden');
  btnLogout.classList.remove('hidden');
  btnOpenAdd.classList.remove('hidden');
  userDisplay.textContent = user.displayName || user.username;

  try {
    // Charger le coffre-fort
    vaultItems = await fetchVault(token);
    await saveVaultCache(vaultItems);
    renderVault();
    await autoFillSuggestedAccount();
    await checkHibpForSuggestions();
  } catch (e) {
    console.error(e);
    // Si le token a expiré, on déconnecte
    logout();
  }
}

async function saveVaultCache(items) {
  try {
    const token = localStorage.getItem('securpass_token');
    await chrome.storage.local.set({ securpass_vault: items, securpass_token: token });
  } catch (e) {
    console.warn('Impossible de sauvegarder le coffre dans le stockage de l\'extension :', e);
  }
}

// Récupérer le coffre-fort depuis l'API SecurPass
async function fetchVault(token) {
  const res = await fetch(`${API_URL}/vault`, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  if (!res.ok) {
    throw new Error('Jeton de session expiré ou invalide.');
  }
  return await res.json();
}

// Tenter d'importer la session de l'onglet SecurPass ouvert
async function importSession() {
  importError.classList.add('hidden');
  
  try {
    // Chercher un onglet avec SecurPass ouvert
    const tabs = await chrome.tabs.query({ url: "https://localhost:5443/*" });
    if (!tabs || tabs.length === 0) {
      throw new Error("Veuillez d'abord ouvrir SecurPass sur https://localhost:5443");
    }

    const targetTab = tabs[0];
    
    // Exécuter un script pour lire le localStorage de la page
    const results = await chrome.scripting.executeScript({
      target: { tabId: targetTab.id },
      func: () => {
        return {
          token: localStorage.getItem('securpass_token'),
          user: localStorage.getItem('securpass_user')
        };
      }
    });

    if (results && results[0] && results[0].result) {
      const { token, user } = results[0].result;
      if (token && user) {
        localStorage.setItem('securpass_token', token);
        localStorage.setItem('securpass_user', user);
        showLoggedInState(token, JSON.parse(user));
      } else {
        throw new Error("Session inactive sur https://localhost:5443. Veuillez vous y connecter.");
      }
    } else {
      throw new Error("Impossible de lire la session. Connectez-vous sur la plateforme web.");
    }
  } catch (e) {
    console.warn(e);
    importError.textContent = e.message;
    importError.classList.remove('hidden');
  }
}

// Déconnexion de l'extension
function logout() {
  localStorage.removeItem('securpass_token');
  localStorage.removeItem('securpass_user');
  vaultItems = [];
  showLoggedOutState();
}

// Vérifie l'extension HIBP pour les mots de passe suggérés
async function checkHibpForSuggestions() {
  if (!vaultItems.length) return;
  const token = localStorage.getItem('securpass_token');
  if (!token) return;

  const suggestions = vaultItems.filter(item => {
    if (!activeDomain || !item.websiteUrl) return false;
    const itemDomain = getDomain(item.websiteUrl);
    return itemDomain && (activeDomain.includes(itemDomain) || itemDomain.includes(activeDomain));
  });

  if (!suggestions.length) return;

  for (const item of suggestions) {
    if (item.breachCount !== undefined) continue; // Déjà vérifié
    try {
      const res = await fetch(`${API_URL}/hibp/check?password=${encodeURIComponent(item.password)}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        if (data.breached) {
          item.breachCount = data.count;
        } else {
          item.breachCount = 0;
        }
      }
    } catch (e) {
      console.warn('HIBP check failed:', e);
    }
  }
  renderVault();
}

// Rendu des comptes suggérés et de tous les comptes
function renderVault(filterQuery = '') {
  suggestionsList.innerHTML = '';
  allVaultList.innerHTML = '';

  const query = filterQuery.toLowerCase().trim();

  // Filtrer les suggestions par domaine
  const suggestions = vaultItems.filter(item => {
    if (!activeDomain || !item.websiteUrl) return false;
    const itemDomain = getDomain(item.websiteUrl);
    return itemDomain && (activeDomain.includes(itemDomain) || itemDomain.includes(activeDomain));
  });

  // Rendu des suggestions
  if (suggestions.length > 0) {
    suggestionsEmpty.classList.add('hidden');
    suggestionsList.classList.remove('hidden');
    suggestions.forEach(item => {
      suggestionsList.appendChild(createItemEl(item, true));
    });
  } else {
    suggestionsEmpty.classList.remove('hidden');
    suggestionsList.classList.add('hidden');
  }

  // Filtrer la liste globale
  const filteredAll = vaultItems.filter(item => {
    if (!query) return true;
    return (
      (item.title || '').toLowerCase().includes(query) ||
      (item.username || '').toLowerCase().includes(query) ||
      (item.websiteUrl || '').toLowerCase().includes(query)
    );
  });

  // Rendu de la liste complète
  if (filteredAll.length > 0) {
    filteredAll.forEach(item => {
      allVaultList.appendChild(createItemEl(item, false));
    });
  } else {
    allVaultList.innerHTML = `<div class="empty-state">Aucun compte trouvé pour "${escapeHTML(query)}"</div>`;
  }
}

// Charger les logs d'inscription temporaires
async function loadRegistrationLogs() {
  const token = localStorage.getItem('securpass_token');
  if (!token) return;
  try {
    const res = await fetch(`${API_URL}/registration-logs`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (res.ok) {
      const logs = await res.json();
      renderRegistrationLogs(logs);
    }
  } catch (e) {
    console.warn('Impossible de charger les logs d\'inscription :', e);
  }
}

// Afficher les logs d'inscription dans le popup
function renderRegistrationLogs(logs) {
  registrationLogsList.innerHTML = '';
  if (logs.length === 0) {
    registrationLogsEmpty.classList.remove('hidden');
    return;
  }
  registrationLogsEmpty.classList.add('hidden');

  logs.forEach(log => {
    const div = document.createElement('div');
    div.className = 'log-item';
    const date = new Date(log.timestamp);
    div.innerHTML = `
      <div class="log-domain" title="${escapeHTML(log.domain)}">${escapeHTML(log.domain)}</div>
      <div class="log-meta">
        <span>${date.toLocaleString('fr-FR')}</span>
        <span>${log.fieldsFilled} champ(s)</span>
      </div>
      <div class="log-pwd" title="${escapeHTML(log.passwordGenerated)}">${escapeHTML(log.passwordGenerated)}</div>
    `;
    registrationLogsList.appendChild(div);
  });
}

// Créer un élément de liste HTML
function createItemEl(item, isSuggestion) {
  const div = document.createElement('div');
  div.className = 'pwd-item';
  div.dataset.itemId = item.id || '';
  
  const usernameDisp = item.username || 'Sans identifiant';
  
  div.innerHTML = `
    <div class="pwd-info">
      <div class="pwd-title" title="${escapeHTML(item.title)}">${escapeHTML(item.title)}</div>
      <div class="pwd-user" title="${escapeHTML(usernameDisp)}">${escapeHTML(usernameDisp)}</div>
    </div>
    <div class="pwd-actions">
      <button class="btn-fill" title="Remplir automatiquement">
        <svg class="icon-fill" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="20 6 9 17 4 12"></polyline>
        </svg>
        <span>Remplir</span>
      </button>
    </div>
  `;

  // Badge HIBP (brèche détectée)
  if (item.breachCount && item.breachCount > 0) {
    const hibpBadge = document.createElement('span');
    hibpBadge.className = 'hibp-badge breached';
    hibpBadge.title = `Mot de passe compromis dans ${item.breachCount} base(s) de données piratées`;
    hibpBadge.innerHTML = `⚠️ ${item.breachCount}`;
    div.querySelector('.pwd-info').appendChild(hibpBadge);
  }

  // Badge d'expiration pour les mots de passe partagés
  if (item.shared && item.expiresAt) {
    const expBadge = document.createElement('span');
    const expDate = new Date(item.expiresAt);
    const now = new Date();
    const diffDays = Math.ceil((expDate - now) / (1000 * 60 * 60 * 24));
    expBadge.className = 'expiration-badge ' + (diffDays <= 2 ? 'expiring' : 'normal');
    if (diffDays <= 0) {
      expBadge.textContent = 'Expiré';
    } else {
      expBadge.textContent = `Expire dans ${diffDays}j`;
    }
    expBadge.title = `Partage expire le ${expDate.toLocaleDateString('fr-FR')}`;
    div.querySelector('.pwd-info').appendChild(expBadge);
  }

  div.querySelector('.btn-fill').addEventListener('click', (e) => {
    e.stopPropagation();
    fillInPage(item);
  });

  div.addEventListener('click', () => {
    fillInPage(item);
  });

  return div;
}

// Ajouter le protocole si absent
function normalizeUrl(urlStr) {
  if (!urlStr) return '';
  const trimmed = urlStr.trim();
  if (!/^https?:\/\//i.test(trimmed)) {
    return `https://${trimmed}`;
  }
  return trimmed;
}

// Envoyer le message de remplissage au script de contenu d'un onglet donné
async function sendFillMessage(tabId, item) {
  const response = await chrome.tabs.sendMessage(tabId, {
    action: "fill_credentials",
    username: item.username || "",
    password: item.password || "",
    autoSubmit: false // Remplir les champs sans soumettre automatiquement
  });

  if (response && response.success) {
    window.close(); // Fermer le popup de l'extension après succès
  } else {
    alert("Erreur de remplissage : Assurez-vous que des champs de saisie d'identifiants sont visibles à l'écran.");
  }
}

// Naviguer vers l'URL du compte puis remplir une fois la page chargée
function navigateAndFill(item) {
  return new Promise((resolve, reject) => {
    const targetUrl = normalizeUrl(item.websiteUrl);

    chrome.tabs.update(activeTab.id, { url: targetUrl }, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }

      const listener = (tabId, changeInfo) => {
        if (tabId === activeTab.id && changeInfo.status === 'complete') {
          chrome.tabs.onUpdated.removeListener(listener);
          // Petit délai pour laisser le temps au site (SPA) de finir de s'initialiser
          setTimeout(async () => {
            try {
              await sendFillMessage(activeTab.id, item);
              resolve();
            } catch (e) {
              reject(e);
            }
          }, 800);
        }
      };
      chrome.tabs.onUpdated.addListener(listener);
    });
  });
}

// Retrouve les identifiants pour l'onglet actif si l'URL correspond à un compte enregistré
async function fillCurrentPageAutomatically() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs || !tabs[0]) return;
    const tab = tabs[0];
    const currentDomain = getDomain(tab.url);
    if (!currentDomain) return;

    const cached = await chrome.storage.local.get('securpass_vault');
    const items = cached.securpass_vault || [];
    const matches = items.filter((item) => {
      const itemDomain = getDomain(normalizeUrl(item.websiteUrl));
      return itemDomain && (currentDomain === itemDomain || currentDomain.endsWith(`.${itemDomain}`) || itemDomain.endsWith(`.${currentDomain}`));
    });

    if (matches.length === 1) {
      await sendFillMessage(tab.id, matches[0]);
    }
  } catch (e) {
    console.warn('Autofill automatique impossible :', e);
  }
}

async function autoFillSuggestedAccount() {
  if (!activeDomain || !vaultItems.length) return;
  const suggestions = vaultItems.filter((item) => {
    const itemDomain = getDomain(normalizeUrl(item.websiteUrl));
    return itemDomain && (activeDomain === itemDomain || activeDomain.endsWith(`.${itemDomain}`) || itemDomain.endsWith(`.${activeDomain}`));
  });

  if (suggestions.length === 1) {
    await fillInPage(suggestions[0]);
  }
}

// Communiquer avec le script de contenu pour naviguer (si besoin) et injecter les identifiants
async function fillInPage(item) {
  if (!activeTab) return;

  const targetDomain = getDomain(normalizeUrl(item.websiteUrl));

  try {
    if (item.websiteUrl && targetDomain && targetDomain !== activeDomain) {
      // Le compte correspond à un autre site : on y navigue d'abord
      await navigateAndFill(item);
    } else {
      // Déjà sur le bon site : on remplit directement
      await sendFillMessage(activeTab.id, item);
    }
  } catch (err) {
    console.error("Erreur de transmission au script de contenu:", err);
    alert("Impossible d'injecter les identifiants. Rafraîchissez la page cible et réessayez.");
  }
}

// Générer un mot de passe aléatoire sécurisé
function generatePassword({ length = 16, upper = true, digits = true, symbols = true } = {}) {
  const sets = {
    lower: 'abcdefghijklmnopqrstuvwxyz',
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    digits: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}?'
  };

  let chars = sets.lower;
  if (upper) chars += sets.upper;
  if (digits) chars += sets.digits;
  if (symbols) chars += sets.symbols;

  // Génération cryptographiquement sûre
  const randomValues = new Uint32Array(length);
  crypto.getRandomValues(randomValues);

  let password = '';
  for (let i = 0; i < length; i++) {
    password += chars[randomValues[i] % chars.length];
  }
  return password;
}

// Ouvrir la modale d'ajout de compte
function openAddEntry() {
  formAddEntry.reset();
  addEntryError.classList.add('hidden');
  inputPassword.type = 'password';
  pwdLengthValue.textContent = rangePwdLength.value;
  // Pré-remplir l'URL avec le site actif pour aller plus vite
  if (activeDomain) {
    inputUrl.value = activeDomain;
  }
  modalAddEntry.classList.remove('hidden');
  inputTitle.focus();
}

// Fermer la modale d'ajout de compte
function closeAddEntry() {
  modalAddEntry.classList.add('hidden');
}

// Enregistrer un nouveau compte dans le coffre-fort SecurPass
async function handleAddEntry(e) {
  e.preventDefault();
  addEntryError.classList.add('hidden');

  const title = inputTitle.value.trim();
  const websiteUrl = normalizeUrl(inputUrl.value.trim());
  const username = inputUsername.value.trim();
  const password = inputPassword.value;

  if (!title || !password) {
    addEntryError.textContent = "Le titre et le mot de passe sont requis.";
    addEntryError.classList.remove('hidden');
    return;
  }

  const token = localStorage.getItem('securpass_token');
  if (!token) {
    addEntryError.textContent = "Session expirée, veuillez vous reconnecter.";
    addEntryError.classList.remove('hidden');
    return;
  }

  try {
    const res = await fetch(`${API_URL}/vault`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
        ...getAntiReplayHeaders()
      },
      body: JSON.stringify({ title, websiteUrl, username, password })
    });

    if (!res.ok) {
      throw new Error("Échec de l'enregistrement du compte sur le serveur.");
    }

    const newItem = await res.json();
    vaultItems.push(newItem);
    renderVault(searchInput.value);
    closeAddEntry();
  } catch (err) {
    console.error(err);
    addEntryError.textContent = err.message || "Erreur lors de l'enregistrement.";
    addEntryError.classList.remove('hidden');
  }
}

// Gérer la recherche dynamique
function handleSearch(e) {
  const query = e.target.value;
  if (query) {
    // Ouvrir automatiquement la liste complète si on recherche
    allVaultContainer.classList.remove('hidden');
    toggleAllVault.classList.add('active');
  }
  renderVault(query);
}

// Sécurisation HTML XSS
function escapeHTML(str) {
  if (!str) return '';
  return str.replace(/[&<>'"]/g, tag => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  }[tag] || tag));
}
