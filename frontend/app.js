// ==========================================
// CONFIGURATION ET CONSTANTES
// ==========================================
// Used only when the page is opened directly from a file. When served by the
// backend, API_URL below automatically keeps the current HTTPS origin.
const DEFAULT_API_URL = 'https://localhost:5443/api';
const API_URL = (function() {
  const origin = window.location.origin;
  if (!origin || origin === 'null' || origin.startsWith('file://')) {
    return DEFAULT_API_URL;
  }
  return origin + '/api';
})();

// ==========================================
// HEADERS ANTI-REJEU (ANTI-REPLAY)
// ==========================================
// Génère un nonce UUID unique et un timestamp epoch pour chaque requête de mutation.
// Requis par le middleware antiReplayMiddleware du backend sur toutes les
// requêtes POST / PUT / DELETE.
function getAntiReplayHeaders() {
  return {
    'X-Request-Nonce': crypto.randomUUID(),
    'X-Request-Timestamp': Date.now().toString()
  };
}

// État global de l'application
const state = {
  token: sessionStorage.getItem('securpass_token') || null,
  user: (() => {
    try {
      const raw = sessionStorage.getItem('securpass_user');
      return raw ? JSON.parse(raw) : null;
    } catch {
      sessionStorage.removeItem('securpass_user');
      return null;
    }
  })(),
  passwords: [],
  activeTab: 'vault',
  adminActiveTab: 'stats',
  history: [],
  pendingDeleteId: null
};

// ==========================================
// INITIALISATION DE L'APPLICATION
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
  initDOM();
  setupEventListeners();
  checkAuth();
});

// Références aux éléments du DOM
let DOM = {};
function initDOM() {
  DOM = {
    // Écrans principaux
    loginContainer: document.getElementById('login-container'),
    dashboardContainer: document.getElementById('dashboard-container'),
    
    // Login
    loginForm: document.getElementById('login-form'),
    usernameInput: document.getElementById('login-username'),
    passwordInput: document.getElementById('login-password'),
    loginError: document.getElementById('login-error'),
    btnLogin: document.getElementById('btn-login'),
    btnSSO: document.getElementById('btn-sso'),
    authModeBadge: document.getElementById('auth-mode-badge'),
    
    // Header & Navigation
    userDisplayName: document.getElementById('user-display-name'),
    userUsername: document.getElementById('user-username'),
    btnLogout: document.getElementById('btn-logout'),
    btnMobileMenu: document.getElementById('btn-mobile-menu'),
    navVault: document.getElementById('nav-vault'),
    navGenerator: document.getElementById('nav-generator'),
    navExtension: document.getElementById('nav-extension'),
    navLogs: document.getElementById('nav-logs'),
    navAdmin: document.getElementById('nav-admin'),
    sidebar: document.querySelector('.sidebar'),
    
    // Sections
    sectionVault: document.getElementById('section-vault'),
    sectionGenerator: document.getElementById('section-generator'),
    sectionExtension: document.getElementById('section-extension'),
    sectionLogs: document.getElementById('section-logs'),
    sectionAdmin: document.getElementById('section-admin'),
    
    // Logs d'inscription
    logsList: document.getElementById('logs-list'),
    logsEmpty: document.getElementById('logs-empty'),
    logsLoader: document.getElementById('logs-loader'),
    btnRefreshLogs: document.getElementById('btn-refresh-logs'),
    
    // Coffre-fort (Vault)
    vaultGrid: document.getElementById('vault-grid'),
    vaultSearch: document.getElementById('vault-search'),
    filterCategory: document.getElementById('filter-category'),
    vaultEmptyState: document.getElementById('vault-empty-state'),
    vaultLoader: document.getElementById('vault-loader'),
    btnAddPassword: document.getElementById('btn-add-password'),
    btnEmptyAdd: document.getElementById('btn-empty-add'),
    
    // Import/Export
    btnImport: document.getElementById('btn-import'),
    btnExportCSV: document.getElementById('btn-export-csv'),
    btnExportJSON: document.getElementById('btn-export-json'),
    importModal: document.getElementById('import-modal'),
    btnCloseImportModal: document.getElementById('btn-close-import-modal'),
    btnCancelImportModal: document.getElementById('btn-cancel-import-modal'),
    importForm: document.getElementById('import-form'),
    importFileInput: document.getElementById('import-file-input'),
    importFormatSelect: document.getElementById('import-format-select'),
    btnSubmitImport: document.getElementById('btn-submit-import'),
    importError: document.getElementById('import-error'),
    importSuccess: document.getElementById('import-success'),
    
    // Partage
    shareModal: document.getElementById('share-modal'),
    btnCloseShareModal: document.getElementById('btn-close-share-modal'),
    btnCancelShareModal: document.getElementById('btn-cancel-share-modal'),
    shareForm: document.getElementById('share-form'),
    sharePasswordId: document.getElementById('share-password-id'),
    sharePasswordTitleDisplay: document.getElementById('share-password-title-display'),
    shareUsername: document.getElementById('share-username'),
    shareExpiration: document.getElementById('share-expiration'),
    btnSubmitShare: document.getElementById('btn-submit-share'),
    shareError: document.getElementById('share-error'),
    
    // Partages avec moi
    navSharedWithMe: document.getElementById('nav-shared-with-me'),
    sectionSharedWithMe: document.getElementById('section-shared-with-me'),
    btnRefreshShared: document.getElementById('btn-refresh-shared'),
    sharedWithMeGrid: document.getElementById('shared-with-me-grid'),
    sharedWithMeEmpty: document.getElementById('shared-with-me-empty'),
    sharedLoader: document.getElementById('shared-loader'),
    
    // Gestion des partages
    manageSharesModal: document.getElementById('manage-shares-modal'),
    btnCloseManageSharesModal: document.getElementById('btn-close-manage-shares-modal'),
    btnCloseManageSharesOnly: document.getElementById('btn-close-manage-shares-only'),
    manageSharesPasswordTitle: document.getElementById('manage-shares-password-title'),
    manageSharesLoader: document.getElementById('manage-shares-loader'),
    manageSharesList: document.getElementById('manage-shares-list'),
    manageSharesEmpty: document.getElementById('manage-shares-empty'),
    
    // Générateur
    genOutput: document.getElementById('gen-output'),
    btnCopyGen: document.getElementById('btn-copy-gen'),
    btnRefreshGen: document.getElementById('btn-refresh-gen'),
    btnGenGenerate: document.getElementById('btn-gen-generate'),
    btnGenSaveVault: document.getElementById('btn-gen-save-vault'),
    genStrengthBar: document.getElementById('gen-strength-bar'),
    genStrengthText: document.getElementById('gen-strength-text'),
    genLength: document.getElementById('gen-length'),
    lengthVal: document.getElementById('length-val'),
    genOptUpper: document.getElementById('gen-opt-upper'),
    genOptLower: document.getElementById('gen-opt-lower'),
    genOptNumbers: document.getElementById('gen-opt-numbers'),
    genOptSymbols: document.getElementById('gen-opt-symbols'),
    genOptSimilar: document.getElementById('gen-opt-similar'),
    genHistoryList: document.getElementById('gen-history-list'),
    
    // Modal
    passwordModal: document.getElementById('password-modal'),
    modalTitle: document.getElementById('modal-title'),
    modalError: document.getElementById('modal-error'),
    passwordForm: document.getElementById('password-form'),
    entryId: document.getElementById('entry-id'),
    entryTitle: document.getElementById('entry-title'),
    entryCategory: document.getElementById('entry-category'),
    entryWebsite: document.getElementById('entry-website'),
    entryUsername: document.getElementById('entry-username'),
    entryPassword: document.getElementById('entry-password'),
    entryNotes: document.getElementById('entry-notes'),
    btnCloseModal: document.getElementById('btn-close-modal'),
    btnCancelModal: document.getElementById('btn-cancel-modal'),
    btnModalGenerate: document.getElementById('btn-modal-generate'),
    btnToggleModalPwd: document.getElementById('btn-toggle-modal-pwd'),
    
    // Confirmation Modal
    confirmModal: document.getElementById('confirm-modal'),
    confirmTitle: document.getElementById('confirm-title'),
    confirmMessage: document.getElementById('confirm-message'),
    btnConfirmCancel: document.getElementById('btn-confirm-cancel'),
    btnConfirmOk: document.getElementById('btn-confirm-ok'),
    
    // Admin Tabs & Views
    adminTabStats: document.getElementById('admin-tab-stats'),
    adminTabUsers: document.getElementById('admin-tab-users'),
    adminViewStats: document.getElementById('admin-view-stats'),
    adminViewUsers: document.getElementById('admin-view-users'),
    adminUserSearch: document.getElementById('admin-user-search'),

    // Admin KPI Elements
    statTotalPasswords: document.getElementById('stat-total-passwords'),
    statAvgLength: document.getElementById('stat-avg-length'),
    statReusedPasswords: document.getElementById('stat-reused-passwords'),
    statExtremelyWeak: document.getElementById('stat-extremely-weak'),
    statLastModified: document.getElementById('stat-last-modified'),
    
    // Admin Charts Elements
    labelStrengthStrong: document.getElementById('label-strength-strong'),
    barStrengthStrong: document.getElementById('bar-strength-strong'),
    labelStrengthGood: document.getElementById('label-strength-good'),
    barStrengthGood: document.getElementById('bar-strength-good'),
    labelStrengthFair: document.getElementById('label-strength-fair'),
    barStrengthFair: document.getElementById('bar-strength-fair'),
    labelStrengthWeak: document.getElementById('label-strength-weak'),
    barStrengthWeak: document.getElementById('bar-strength-weak'),
    
    statsUsersList: document.getElementById('stats-users-list'),
    adminUsersList: document.getElementById('admin-users-list'),
    adminUsersCount: document.getElementById('admin-users-count'),
    
    // Add User Form
    addUserForm: document.getElementById('add-user-form'),
    addUserUsername: document.getElementById('add-user-username'),
    addUserDisplayname: document.getElementById('add-user-displayname'),
    addUserEmail: document.getElementById('add-user-email'),
    addUserPassword: document.getElementById('add-user-password'),
    addUserError: document.getElementById('add-user-error'),
    btnAddUser: document.getElementById('btn-add-user'),
    
    // Toast
    toast: document.getElementById('toast-notification'),
    toastMessage: document.getElementById('toast-message'),

     // Nouveaux éléments (Sécurité, TOTP, Export Chiffré, Edit User Modal)
    navSecurity: document.getElementById('nav-security'),
    sectionSecurity: document.getElementById('section-security'),
    btnRefreshSecurity: document.getElementById('btn-refresh-security'),
    btnExportEncrypted: document.getElementById('btn-export-encrypted'),
    securityScoreNumber: document.getElementById('security-score-number'),
    securityScoreStatus: document.getElementById('security-score-status'),
    securityScoreDesc: document.getElementById('security-score-desc'),
    scoreCircleBar: document.getElementById('score-circle-bar'),
    metricWeakCount: document.getElementById('metric-weak-count'),
    metricReusedCount: document.getElementById('metric-reused-count'),
    metricExpiredCount: document.getElementById('metric-expired-count'),
    securityVulnerabilitiesList: document.getElementById('security-vulnerabilities-list'),
    btnSetupTotpWeb: document.getElementById('btn-setup-totp-web'),
    totpSetupDisplay: document.getElementById('totp-setup-display'),
    totpSecretCode: document.getElementById('totp-secret-code'),
    totpVerifyInput: document.getElementById('totp-verify-input'),
    btnVerifyTotpWeb: document.getElementById('btn-verify-totp-web'),
    modalStrengthText: document.getElementById('modal-strength-text'),
    modalStrengthBar: document.getElementById('modal-strength-bar'),
    exportEncryptedModal: document.getElementById('export-encrypted-modal'),
    exportPasswordInput: document.getElementById('export-password'),
    exportPasswordConfirm: document.getElementById('export-password-confirm'),
    exportStrengthBar: document.getElementById('export-strength-bar'),
    exportStrengthText: document.getElementById('export-strength-text'),
    exportError: document.getElementById('export-error'),
    btnCloseExportModal: document.getElementById('btn-close-export-modal'),
    btnCancelExportModal: document.getElementById('btn-cancel-export-modal'),
    exportEncryptedForm: document.getElementById('export-encrypted-form'),
    btnSubmitExportModal: document.getElementById('btn-submit-export-modal'),
    btnToggleExportPwd: document.getElementById('btn-toggle-export-pwd'),
    editUserModal: document.getElementById('edit-user-modal'),
    editUserForm: document.getElementById('edit-user-form'),
    editUserTargetUsername: document.getElementById('edit-user-target-username'),
    editUserDisplayname: document.getElementById('edit-user-displayname'),
    editUserEmail: document.getElementById('edit-user-email'),
    editUserNewPassword: document.getElementById('edit-user-new-password'),
    btnCloseEditUserModal: document.getElementById('btn-close-edit-user-modal'),
    btnCancelEditUser: document.getElementById('btn-cancel-edit-user')
  };
}

// Configuration des écouteurs d'événements
function setupEventListeners() {
  // Authentification
  DOM.loginForm.addEventListener('submit', handleLogin);
  if (DOM.btnSSO) {
    DOM.btnSSO.addEventListener('click', handleSSOLogin);
  }
  DOM.btnLogout.addEventListener('click', handleLogout);
  
  // Navigation
  DOM.navVault.addEventListener('click', () => switchTab('vault'));
  DOM.navSharedWithMe.addEventListener('click', () => switchTab('shared-with-me'));
  DOM.navGenerator.addEventListener('click', () => switchTab('generator'));
  if (DOM.navExtension) {
    DOM.navExtension.addEventListener('click', () => switchTab('extension'));
  }
  if (DOM.navLogs) {
    DOM.navLogs.addEventListener('click', () => switchTab('logs'));
  }
  if (DOM.navAdmin) {
    DOM.navAdmin.addEventListener('click', () => switchTab('admin'));
  }
  
  // Mobile menu
  if (DOM.btnMobileMenu) {
    DOM.btnMobileMenu.addEventListener('click', toggleMobileMenu);
  }
  
  // Coffre-fort (Recherche & Filtres)
  DOM.vaultSearch.addEventListener('input', renderVault);
  DOM.filterCategory.addEventListener('change', renderVault);
  DOM.btnAddPassword.addEventListener('click', () => openModal());
  DOM.btnEmptyAdd.addEventListener('click', () => openModal());
  
  // Modal de gestion
  DOM.btnCloseModal.addEventListener('click', closeModal);
  DOM.btnCancelModal.addEventListener('click', closeModal);
  DOM.passwordForm.addEventListener('submit', handleSavePassword);
  DOM.btnModalGenerate.addEventListener('click', handleModalGenerate);
  
  // Toggle visibilité mot de passe dans le modal
  if (DOM.btnToggleModalPwd) {
    DOM.btnToggleModalPwd.addEventListener('click', toggleModalPasswordVisibility);
  }
  
  // Fermeture modal au clic sur overlay
  DOM.passwordModal.addEventListener('click', (e) => {
    if (e.target === DOM.passwordModal) closeModal();
  });
  
  // Modal de confirmation
  if (DOM.confirmModal) {
    DOM.btnConfirmCancel.addEventListener('click', closeConfirmModal);
    DOM.btnConfirmOk.addEventListener('click', handleConfirmDelete);
    DOM.confirmModal.addEventListener('click', (e) => {
      if (e.target === DOM.confirmModal) closeConfirmModal();
    });
  }
  
  // Admin Subnavigation
  if (DOM.adminTabStats) {
    DOM.adminTabStats.addEventListener('click', () => switchAdminTab('stats'));
  }
  if (DOM.adminTabUsers) {
    DOM.adminTabUsers.addEventListener('click', () => switchAdminTab('users'));
  }
  if (DOM.adminUserSearch) {
    DOM.adminUserSearch.addEventListener('input', handleAdminUserSearch);
  }
  if (DOM.addUserForm) {
    DOM.addUserForm.addEventListener('submit', handleAddUser);
  }
  
  // Générateur Interactif
  DOM.genLength.addEventListener('input', (e) => {
    DOM.lengthVal.textContent = e.target.value;
    generateLocalPassword();
  });
  
  [DOM.genOptUpper, DOM.genOptLower, DOM.genOptNumbers, DOM.genOptSymbols, DOM.genOptSimilar].forEach(opt => {
    opt.addEventListener('change', generateLocalPassword);
  });
  
  DOM.btnRefreshGen.addEventListener('click', handleGenerateBtnClick);
  DOM.btnCopyGen.addEventListener('click', copyGenPassword);
  
  // Bouton "Générer" principal dans la carte de sortie
  if (DOM.btnGenGenerate) {
    DOM.btnGenGenerate.addEventListener('click', handleGenerateBtnClick);
  }
  
  // Bouton "Sauvegarder dans le coffre" depuis le générateur
  if (DOM.btnGenSaveVault) {
    DOM.btnGenSaveVault.addEventListener('click', handleSaveFromGenerator);
  }

  // Bouton actualiser logs
  if (DOM.btnRefreshLogs) {
    DOM.btnRefreshLogs.addEventListener('click', loadRegistrationLogs);
  }
  
  // Import/Export
  if (DOM.btnImport) {
    DOM.btnImport.addEventListener('click', openImportModal);
  }
  if (DOM.btnExportCSV) {
    DOM.btnExportCSV.addEventListener('click', handleExportCSV);
  }
  if (DOM.btnExportJSON) {
    DOM.btnExportJSON.addEventListener('click', handleExportJSON);
  }
  if (DOM.btnCloseImportModal) {
    DOM.btnCloseImportModal.addEventListener('click', closeImportModal);
  }
  if (DOM.btnCancelImportModal) {
    DOM.btnCancelImportModal.addEventListener('click', closeImportModal);
  }
  if (DOM.importModal) {
    DOM.importModal.addEventListener('click', (e) => {
      if (e.target === DOM.importModal) closeImportModal();
    });
  }
  if (DOM.importForm) {
    DOM.importForm.addEventListener('submit', handleImportSubmit);
  }
  
  // Partage
  if (DOM.btnCloseShareModal) {
    DOM.btnCloseShareModal.addEventListener('click', closeShareModal);
  }
  if (DOM.btnCancelShareModal) {
    DOM.btnCancelShareModal.addEventListener('click', closeShareModal);
  }
  if (DOM.shareModal) {
    DOM.shareModal.addEventListener('click', (e) => {
      if (e.target === DOM.shareModal) closeShareModal();
    });
  }
  if (DOM.shareForm) {
    DOM.shareForm.addEventListener('submit', handleShareSubmit);
  }
  
  // Gestion des partages
  if (DOM.btnCloseManageSharesModal) {
    DOM.btnCloseManageSharesModal.addEventListener('click', closeManageSharesModal);
  }
  if (DOM.btnCloseManageSharesOnly) {
    DOM.btnCloseManageSharesOnly.addEventListener('click', closeManageSharesModal);
  }
  if (DOM.manageSharesModal) {
    DOM.manageSharesModal.addEventListener('click', (e) => {
      if (e.target === DOM.manageSharesModal) closeManageSharesModal();
    });
  }
  
  // Mots de passe partagés avec moi
  if (DOM.btnRefreshShared) {
    DOM.btnRefreshShared.addEventListener('click', loadSharedWithMe);
  }

  // Onglet Sécurité & Actions associées
  if (DOM.navSecurity) {
    DOM.navSecurity.addEventListener('click', () => switchTab('security'));
  }
  if (DOM.btnRefreshSecurity) {
    DOM.btnRefreshSecurity.addEventListener('click', loadSecurityScore);
  }
  if (DOM.btnExportEncrypted) {
    DOM.btnExportEncrypted.addEventListener('click', handleExportEncrypted);
  }
  if (DOM.entryPassword) {
    DOM.entryPassword.addEventListener('input', updateModalStrength);
  }
  if (DOM.btnSetupTotpWeb) {
    DOM.btnSetupTotpWeb.addEventListener('click', handleTotpSetup);
  }
  if (DOM.btnVerifyTotpWeb) {
    DOM.btnVerifyTotpWeb.addEventListener('click', handleTotpVerify);
  }
  if (DOM.editUserForm) {
    DOM.editUserForm.addEventListener('submit', handleEditUserSubmit);
  }
   if (DOM.btnCloseEditUserModal) {
    DOM.btnCloseEditUserModal.addEventListener('click', closeEditUserModal);
  }
  if (DOM.btnCancelEditUser) {
    DOM.btnCancelEditUser.addEventListener('click', closeEditUserModal);
  }

  // Export chiffré modal
  if (DOM.exportEncryptedModal) {
    DOM.exportEncryptedModal.addEventListener('click', (e) => {
      if (e.target === DOM.exportEncryptedModal) closeExportEncryptedModal();
    });
  }
  if (DOM.btnCloseExportModal) {
    DOM.btnCloseExportModal.addEventListener('click', closeExportEncryptedModal);
  }
  if (DOM.btnCancelExportModal) {
    DOM.btnCancelExportModal.addEventListener('click', closeExportEncryptedModal);
  }
  if (DOM.exportEncryptedForm) {
    DOM.exportEncryptedForm.addEventListener('submit', handleSubmitExportEncrypted);
  }
  if (DOM.exportPasswordInput) {
    DOM.exportPasswordInput.addEventListener('input', updateExportStrength);
  }
  if (DOM.exportPasswordConfirm) {
    DOM.exportPasswordConfirm.addEventListener('input', updateExportStrength);
  }
  if (DOM.btnToggleExportPwd) {
    DOM.btnToggleExportPwd.addEventListener('click', toggleExportPwdVisibility);
  }
}

// ==========================================
// LOGIQUE D'AUTHENTIFICATION (JWT + LDAP)
// ==========================================

// Vérification de la session au démarrage
async function checkAuth() {
  if (state.token && state.user) {
    // Tente de récupérer les données utilisateur
    setupDashboard();
    showDashboardScreen();
    loadVaultData();
    
    // Vérifier la validité du token
    try {
      const res = await fetch(`${API_URL}/auth/me`, {
        headers: { 'Authorization': `Bearer ${state.token}` }
      });
      if (!res.ok) {
        if (res.status === 401 || res.status === 403) {
          handleLogout();
        }
      }
    } catch (error) {
      console.warn('Le serveur backend ne répond pas. Vérification locale uniquement.');
    }
  } else {
    // Tentative de SSO silencieux si l'utilisateur ne s'est pas déconnecté manuellement
    if (!localStorage.getItem('securpass_logout')) {
      console.log('Tentative de connexion SSO silencieuse...');
      try {
        const res = await fetch(`${API_URL}/auth/sso?mock=true`);
        if (res.ok) {
          const data = await res.json();
          state.token = data.token;
          state.user = data.user;
          sessionStorage.setItem('securpass_token', data.token);
          sessionStorage.setItem('securpass_user', JSON.stringify(data.user));

          setupDashboard();
          await loadVaultData();
          showDashboardScreen();
          showToast(`Connexion automatique SSO : ${data.user.displayName}`);
          return;
        }
      } catch (e) {
        console.warn('Échec de la connexion SSO silencieuse:', e);
      }
    }
    showLoginScreen();
  }
}

// Soumission du formulaire de connexion
async function handleLogin(e) {
  e.preventDefault();
  
  const username = DOM.usernameInput.value.trim();
  const password = DOM.passwordInput.value;
  
  const usernameCheck = validateUsernameInput(username);
  if (!usernameCheck.valid) {
    DOM.loginError.querySelector('.alert-message').textContent = usernameCheck.error;
    showElement(DOM.loginError);
    return;
  }
  
  setLoginLoading(true);
  hideElement(DOM.loginError);
  
  try {
    const response = await fetch(`${API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAntiReplayHeaders() },
      body: JSON.stringify({ username: usernameCheck.username, password })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Erreur d\'authentification');
    }
    
    // Sauvegarde de session (sessionStorage uniquement pour la sécurité)
    state.token = data.token;
    state.user = data.user;
    sessionStorage.setItem('securpass_token', data.token);
    sessionStorage.setItem('securpass_user', JSON.stringify(data.user));
    localStorage.removeItem('securpass_logout');
    
    setupDashboard();
    await loadVaultData();
    showDashboardScreen();
    showToast(`Bienvenue, ${data.user.displayName} !`);
  } catch (error) {
    DOM.loginError.querySelector('.alert-message').textContent = error.message;
    showElement(DOM.loginError);
    DOM.passwordInput.value = ''; // efface le mot de passe
  } finally {
    setLoginLoading(false);
  }
}

// Connexion SSO Active Directory (NTLM / Mock)
async function handleSSOLogin() {
  setLoginLoading(true);
  hideElement(DOM.loginError);
  
  try {
    console.log('Déclenchement de la connexion SSO...');
    // On passe ?mock=true pour que, en mode mock, le backend lise process.env.USERNAME
    const response = await fetch(`${API_URL}/auth/sso?mock=true`);
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Erreur d\'authentification SSO');
    }
    
    // Sauvegarde de session (sessionStorage uniquement pour la sécurité)
    state.token = data.token;
    state.user = data.user;
    sessionStorage.setItem('securpass_token', data.token);
    sessionStorage.setItem('securpass_user', JSON.stringify(data.user));
    localStorage.removeItem('securpass_logout');
    
    setupDashboard();
    await loadVaultData();
    showDashboardScreen();
    showToast(`Connexion SSO réussie ! Bienvenue, ${data.user.displayName}`);
  } catch (error) {
    console.error('Erreur SSO :', error);
    DOM.loginError.querySelector('.alert-message').textContent = error.message;
    showElement(DOM.loginError);
  } finally {
    setLoginLoading(false);
  }
}

// Gestion de la déconnexion
function handleLogout() {
  state.token = null;
  state.user = null;
  state.passwords = [];
  sessionStorage.removeItem('securpass_token');
  sessionStorage.removeItem('securpass_user');
  localStorage.setItem('securpass_logout', 'true');

  showLoginScreen();
  DOM.loginForm.reset();

  // Cacher le bouton admin lors de la déconnexion
  if (DOM.navAdmin) {
    DOM.navAdmin.classList.add('hidden');
  }
}

// Mise en place des informations utilisateur sur le tableau de bord
function isAdminUser(user) {
  if (!user) return false;

  const adminUsernames = ['admin', 'administrateur', 'administrator'];
  const normalizedUsername = String(user.username || '').toLowerCase();
  if (adminUsernames.includes(normalizedUsername)) {
    return true;
  }

  const adminGroups = [
    'domain admins',
    'it-security',
    'administrateurs du domaine',
    'administrateurs de l\'entreprise',
    'enterprise admins',
    'administrateurs',
    'administrateurs entreprise'
  ];

  const groups = Array.isArray(user.groups) ? user.groups : [];
  return groups.some(g => {
    const normalizedGroup = String(g || '').toLowerCase();
    return adminGroups.some(adminGroup => normalizedGroup.includes(adminGroup));
  });
}

function setupDashboard() {
  if (!state.user) return;
  DOM.userDisplayName.textContent = state.user.displayName;
  DOM.userUsername.textContent = `@${state.user.username}`;
  
  const isAdmin = isAdminUser(state.user);
  
  // Afficher / masquer le menu d'administration
  if (DOM.navAdmin) {
    if (isAdmin) {
      DOM.navAdmin.classList.remove('hidden');
    } else {
      DOM.navAdmin.classList.add('hidden');
    }
  }
  
  // Badge LDAP
  if (isAdmin) {
    DOM.authModeBadge.textContent = 'Active Directory : Admin';
    DOM.authModeBadge.className = 'badge badge-ad';
  } else {
    DOM.authModeBadge.textContent = 'Active Directory : Standard';
    DOM.authModeBadge.className = 'badge badge-ad';
  }
}

// États de chargement
function setLoginLoading(loading) {
  if (loading) {
    DOM.btnLogin.setAttribute('disabled', 'true');
    DOM.btnLogin.querySelector('span').textContent = 'Connexion en cours...';
  } else {
    DOM.btnLogin.removeAttribute('disabled');
    DOM.btnLogin.querySelector('span').textContent = 'Se connecter';
  }
}

// ==========================================
// GESTION DU COFFRE-FORT (API CRUD)
// ==========================================

// Charger tous les mots de passe de l'utilisateur
async function loadVaultData() {
  if (!state.token) return;
  
  // Afficher le loader
  showElement(DOM.vaultLoader);
  hideElement(DOM.vaultGrid);
  hideElement(DOM.vaultEmptyState);
  
  try {
    const response = await fetch(`${API_URL}/vault`, {
      headers: {
        'Authorization': `Bearer ${state.token}`
      }
    });
    
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        handleLogout();
        return;
      }
      throw new Error('Erreur réseau lors de la récupération des données.');
    }
    
    state.passwords = await response.json();
    renderVault();
  } catch (error) {
    console.error('Erreur du coffre-fort :', error);
    showToast('Erreur lors du chargement de vos mots de passe.', 'danger');
  } finally {
    // Cacher le loader
    hideElement(DOM.vaultLoader);
  }
}

// Affichage dynamique du coffre-fort
function renderVault() {
  const searchQuery = DOM.vaultSearch.value.toLowerCase().trim();
  const selectedCategory = DOM.filterCategory.value;
  
  // Filtrage local des données (avec protection null safety)
  const filtered = state.passwords.filter(item => {
    const title = (item.title || '').toLowerCase();
    const username = (item.username || '').toLowerCase();
    const websiteUrl = (item.websiteUrl || '').toLowerCase();
    const notes = (item.notes || '').toLowerCase();
    
    const matchesSearch = 
      title.includes(searchQuery) ||
      username.includes(searchQuery) ||
      websiteUrl.includes(searchQuery) ||
      notes.includes(searchQuery);
      
    const matchesCategory = selectedCategory === 'all' || item.category === selectedCategory;
    
    return matchesSearch && matchesCategory;
  });
  
  // Tri par titre alphabétique
  filtered.sort((a, b) => (a.title || '').localeCompare(b.title || ''));
  
  // Vider la grille
  DOM.vaultGrid.innerHTML = '';
  
  if (filtered.length === 0) {
    showElement(DOM.vaultEmptyState);
    hideElement(DOM.vaultGrid);
    return;
  }
  
  hideElement(DOM.vaultEmptyState);
  showElement(DOM.vaultGrid);
  
  // Remplissage de la grille
  filtered.forEach(item => {
    const card = document.createElement('div');
    card.className = 'password-card';
    card.setAttribute('data-id', item.id);
    
    // Détermination de la classe CSS pour la catégorie (avec protection null)
    const category = item.category || 'Général';
    const catClass = category.toLowerCase().replace(/\s+/g, '-');
    
    // Formatage simplifié de l'URL pour affichage
    let displayUrl = item.websiteUrl || '';
    if (displayUrl) {
      try {
        displayUrl = new URL(item.websiteUrl).hostname;
      } catch (e) {
        // format invalide ou simple texte, on laisse en l'état
      }
    }
    
    card.innerHTML = `
      <div class="card-header">
        <div class="card-title-group">
          <h4>${escapeHTML(item.title)}</h4>
          ${item.websiteUrl ? `
            <a href="${escapeHTML(item.websiteUrl)}" target="_blank" rel="noopener noreferrer" class="card-url">
              <i data-lucide="external-link" style="width:12px; height:12px;"></i>
              <span>${escapeHTML(displayUrl)}</span>
            </a>
          ` : '<span class="card-url">Sans adresse URL</span>'}
        </div>
        <span class="cat-tag ${catClass}">${escapeHTML(category)}</span>
      </div>
      
      <div class="card-body">
        <div class="detail-row">
          <span class="detail-label">Identifiant</span>
          <div class="password-value-container">
            <span class="detail-value" title="${escapeHTML(item.username || '')}">${escapeHTML(item.username || 'Non renseigné')}</span>
            ${item.username ? `
              <button class="btn-card-copy btn-copy-username" title="Copier l'identifiant">
                <i data-lucide="copy"></i>
              </button>
            ` : ''}
          </div>
        </div>
        
        <div class="detail-row">
          <span class="detail-label">Mot de passe</span>
          <div class="password-value-container">
            <span class="password-val text-muted" data-visible="false">••••••••</span>
            <button class="btn-card-toggle btn-toggle-pwd" title="Afficher/Masquer">
              <i data-lucide="eye"></i>
            </button>
            <button class="btn-card-copy btn-copy-pwd" title="Copier le mot de passe">
              <i data-lucide="copy"></i>
            </button>
          </div>
        </div>
      </div>
      
      <div class="card-actions">
        <span class="user-subtext">Maj : ${formatDate(item.updatedAt)}</span>
        <div class="action-buttons">
          <button class="btn btn-outline btn-ghost btn-icon-only btn-check-hibp text-warning" title="Vérifier fuite (HIBP)">
            <i data-lucide="shield-alert" style="width:16px; height:16px;"></i>
          </button>
          ${item.websiteUrl ? `
            <button class="btn btn-outline btn-ghost btn-icon-only btn-direct-connect text-success" title="Connexion Directe (Style Bitwarden)">
              <i data-lucide="zap" style="width:16px; height:16px;"></i>
            </button>
          ` : ''}
          <button class="btn btn-outline btn-ghost btn-icon-only btn-share" title="Partager avec un collègue">
            <i data-lucide="share-2" style="width:16px; height:16px;"></i>
          </button>
          <button class="btn btn-outline btn-ghost btn-icon-only btn-manage-shares" title="Gérer les accès">
            <i data-lucide="users" style="width:16px; height:16px;"></i>
          </button>
          <button class="btn btn-outline btn-ghost btn-icon-only btn-edit" title="Modifier">
            <i data-lucide="edit-3" style="width:16px; height:16px;"></i>
          </button>
          <button class="btn btn-outline btn-ghost btn-icon-only btn-delete text-danger" title="Supprimer">
            <i data-lucide="trash-2" style="width:16px; height:16px;"></i>
          </button>
        </div>
        <div class="hibp-badge-wrapper" style="margin-top: 8px;">
          <span class="hibp-badge-container" style="display:none; font-size:0.75rem; padding: 2px 8px; border-radius: 4px;"></span>
        </div>
      </div>
    `;

    // Attacher les écouteurs d'événements spécifiques à cette carte
    setupCardListeners(card, item);

    DOM.vaultGrid.appendChild(card);
  });

  // Mettre à jour les icônes Lucide fraîchement ajoutées
  lucide.createIcons();
}

// Configurer les écouteurs d'événements pour les boutons d'une carte de mot de passe
function setupCardListeners(card, item) {
  // 0. HIBP Check
  const hibpBtn = card.querySelector('.btn-check-hibp');
  const hibpBadge = card.querySelector('.hibp-badge-container');
  if (hibpBtn) {
    hibpBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      checkHIBP(item.password, hibpBtn, hibpBadge);
    });
  }

  // 1. Copier Identifiant
  const copyUserBtn = card.querySelector('.btn-copy-username');
  if (copyUserBtn) {
    copyUserBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      copyToClipboard(item.username, 'Identifiant copié !');
    });
  }

  // 1b. Connexion Directe
  const directConnectBtn = card.querySelector('.btn-direct-connect');
  if (directConnectBtn) {
    directConnectBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      handleDirectConnect(item);
    });
  }
  
  // 2. Afficher/Masquer Mot de passe
  const togglePwdBtn = card.querySelector('.btn-toggle-pwd');
  const pwdValSpan = card.querySelector('.password-val');
  togglePwdBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    const isVisible = pwdValSpan.getAttribute('data-visible') === 'true';
    if (isVisible) {
      pwdValSpan.textContent = '••••••••';
      pwdValSpan.className = 'password-val text-muted';
      pwdValSpan.setAttribute('data-visible', 'false');
      togglePwdBtn.innerHTML = '<i data-lucide="eye"></i>';
    } else {
      pwdValSpan.textContent = item.password || '—';
      pwdValSpan.className = 'password-val text-main';
      pwdValSpan.setAttribute('data-visible', 'true');
      togglePwdBtn.innerHTML = '<i data-lucide="eye-off"></i>';
    }
    lucide.createIcons();
  });
  
  // 3. Copier Mot de passe
  const copyPwdBtn = card.querySelector('.btn-copy-pwd');
  copyPwdBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    copyToClipboard(item.password || '', 'Mot de passe copié !');
  });
  
  // 4. Modifier
  const editBtn = card.querySelector('.btn-edit');
  editBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    openModal(item);
  });
  
  // 5. Partager
  const shareBtn = card.querySelector('.btn-share');
  if (shareBtn) {
    shareBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      openShareModal(item);
    });
  }
  
  // 6. Gérer les partages
  const manageSharesBtn = card.querySelector('.btn-manage-shares');
  if (manageSharesBtn) {
    manageSharesBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      openManageSharesModal(item);
    });
  }
  
  // 7. Supprimer (utilise le modal de confirmation)
  const deleteBtn = card.querySelector('.btn-delete');
  deleteBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    openConfirmModal(item);
  });
}

// Gérer la sauvegarde (Ajout / Modification)
async function handleSavePassword(e) {
  e.preventDefault();
  
  const id = DOM.entryId.value;
  const passwordData = {
    title: DOM.entryTitle.value.trim(),
    category: DOM.entryCategory.value,
    websiteUrl: DOM.entryWebsite.value.trim(),
    username: DOM.entryUsername.value.trim(),
    password: DOM.entryPassword.value,
    notes: DOM.entryNotes.value.trim()
  };
  
  hideElement(DOM.modalError);
  
  const isEdit = !!id;
  const url = isEdit ? `${API_URL}/vault/${id}` : `${API_URL}/vault`;
  const method = isEdit ? 'PUT' : 'POST';
  
  try {
    const response = await fetch(url, {
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.token}`,
        ...getAntiReplayHeaders()
      },
      body: JSON.stringify(passwordData)
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Erreur lors de la sauvegarde');
    }
    
    // Mettre à jour l'état local
    if (isEdit) {
      const idx = state.passwords.findIndex(p => p.id === id);
      if (idx !== -1) state.passwords[idx] = data;
      showToast('Mot de passe mis à jour !');
    } else {
      state.passwords.push(data);
      showToast('Mot de passe enregistré !');
    }
    
    closeModal();
    renderVault();
  } catch (error) {
    DOM.modalError.querySelector('.alert-message').textContent = error.message;
    showElement(DOM.modalError);
  }
}

// Supprimer un mot de passe de l'API
async function handleDeletePassword(id) {
  try {
    const response = await fetch(`${API_URL}/vault/${id}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${state.token}`,
        ...getAntiReplayHeaders()
      }
    });
    
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Erreur lors de la suppression');
    }
    
    state.passwords = state.passwords.filter(p => p.id !== id);
    renderVault();
    showToast('Mot de passe supprimé avec succès.');
  } catch (error) {
    console.error(error);
    showToast(error.message, 'danger');
  }
}

// Générateur intégré dans le modal de modification/création
function handleModalGenerate() {
  // Génère un mot de passe fort de 16 caractères et le place directement dans le champ
  const strongPwd = generatePasswordString(16, true, true, true, true, false);
  DOM.entryPassword.value = strongPwd;
  // S'assurer que le mot de passe est visible après génération
  DOM.entryPassword.type = 'text';
  if (DOM.btnToggleModalPwd) {
    DOM.btnToggleModalPwd.innerHTML = '<i data-lucide="eye-off"></i>';
    lucide.createIcons();
  }
  showToast('Mot de passe fort généré !');
}

// Toggle visibilité du mot de passe dans le modal
function toggleModalPasswordVisibility() {
  const input = DOM.entryPassword;
  const btn = DOM.btnToggleModalPwd;
  if (input.type === 'password') {
    input.type = 'text';
    btn.innerHTML = '<i data-lucide="eye-off"></i>';
  } else {
    input.type = 'password';
    btn.innerHTML = '<i data-lucide="eye"></i>';
  }
  lucide.createIcons();
}

// Bouton principal de génération (Générer & Rafraîchir)
function handleGenerateBtnClick() {
  generateLocalPassword();
  // Ajouter une animation de rotation au bouton rafraîchir
  if (DOM.btnRefreshGen) {
    DOM.btnRefreshGen.classList.add('spinning');
    setTimeout(() => DOM.btnRefreshGen.classList.remove('spinning'), 600);
  }
  if (DOM.btnGenGenerate) {
    DOM.btnGenGenerate.classList.add('spinning');
    setTimeout(() => DOM.btnGenGenerate.classList.remove('spinning'), 600);
  }
}

// Sauvegarder le mot de passe généré directement dans le coffre-fort
function handleSaveFromGenerator() {
  const pwd = DOM.genOutput.value;
  if (!pwd) {
    showToast('Générez d\'abord un mot de passe !', 'danger');
    return;
  }
  // Pré-remplir le modal d'ajout avec le mot de passe généré
  openModal();
  DOM.entryPassword.value = pwd;
  // Afficher le mot de passe pré-rempli
  DOM.entryPassword.type = 'text';
  if (DOM.btnToggleModalPwd) {
    DOM.btnToggleModalPwd.innerHTML = '<i data-lucide="eye-off"></i>';
    lucide.createIcons();
  }
  showToast('Complétez les informations et enregistrez !');
}

// ==========================================
// MODAL DE CONFIRMATION DE SUPPRESSION
// ==========================================

function openConfirmModal(item) {
  state.pendingDeleteId = item.id;
  if (DOM.confirmMessage) {
    DOM.confirmMessage.textContent = `Êtes-vous sûr de vouloir supprimer le mot de passe pour « ${item.title || 'Sans titre'} » ? Cette action est irréversible.`;
  }
  showElement(DOM.confirmModal);
}

function closeConfirmModal() {
  state.pendingDeleteId = null;
  hideElement(DOM.confirmModal);
}

async function handleConfirmDelete() {
  if (state.pendingDeleteId) {
    await handleDeletePassword(state.pendingDeleteId);
  }
  closeConfirmModal();
}

// ==========================================
// LOGIQUE DE LA CONSOLE D'ADMINISTRATION
// ==========================================

// Naviguer entre sous-onglets d'admin
function switchAdminTab(subTab) {
  state.adminActiveTab = subTab;
  
  if (subTab === 'stats') {
    DOM.adminTabStats.classList.add('active');
    DOM.adminTabUsers.classList.remove('active');
    showElement(DOM.adminViewStats);
    hideElement(DOM.adminViewUsers);
  } else {
    DOM.adminTabStats.classList.remove('active');
    DOM.adminTabUsers.classList.add('active');
    hideElement(DOM.adminViewStats);
    showElement(DOM.adminViewUsers);
  }
}

// Charger les données d'administration (stats + utilisateurs AD)
async function loadAdminData() {
  if (!state.token) return;

  const searchTerm = DOM.adminUserSearch ? DOM.adminUserSearch.value.trim() : '';

  try {
    // 1. Fetch Statistiques
    const statsRes = await fetch(`${API_URL}/admin/stats`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    if (!statsRes.ok) {
      const errData = await statsRes.json().catch(() => ({}));
      throw new Error(errData.error || 'Impossible de charger les statistiques.');
    }
    const statsData = await statsRes.json();
    renderAdminStats(statsData);

    // 2. Fetch Utilisateurs AD
    const usersRes = await fetch(`${API_URL}/admin/users${searchTerm ? `?search=${encodeURIComponent(searchTerm)}` : ''}`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    if (!usersRes.ok) {
      const errData = await usersRes.json().catch(() => ({}));
      throw new Error(errData.error || 'Impossible de charger les utilisateurs Active Directory.');
    }
    const usersData = await usersRes.json();
    renderAdminUsers(usersData);
    attachAdminUserActionHandlers();

  } catch (error) {
    console.error('Erreur Administration :', error);
    showToast(error.message, 'danger');
  }
}

// Afficher les statistiques de robustesse et audit
function renderAdminStats(stats) {
  // KPI values
  DOM.statTotalPasswords.textContent = stats.totalPasswords || 0;
  DOM.statAvgLength.textContent = `${stats.avgLength || 0} car.`;
  DOM.statReusedPasswords.textContent = stats.reusedPasswords || 0;
  DOM.statExtremelyWeak.textContent = stats.extremelyWeak || 0;
  DOM.statLastModified.textContent = stats.lastModified ? formatDate(stats.lastModified) : 'Aucune';

  // Risques visuels sur les cartes KPI
  const reusedCard = DOM.statReusedPasswords.closest('.kpi-card');
  if (stats.reusedPasswords > 0) {
    reusedCard.classList.add('danger-glow');
  } else {
    reusedCard.classList.remove('danger-glow');
  }

  const weakCard = DOM.statExtremelyWeak.closest('.kpi-card');
  if (stats.extremelyWeak > 0) {
    weakCard.classList.add('danger-glow');
  } else {
    weakCard.classList.remove('danger-glow');
  }

  // Distribution par force de robustesse
  const dist = stats.strengthDistribution || {};
  const total = (dist.weak || 0) + (dist.fair || 0) + (dist.good || 0) + (dist.strong || 0);

  const setBar = (bar, label, count) => {
    label.textContent = count;
    const percent = total > 0 ? (count / total) * 100 : 0;
    bar.style.width = `${Math.max(percent, count > 0 ? 2 : 0)}%`;
  };

  setBar(DOM.barStrengthStrong, DOM.labelStrengthStrong, dist.strong || 0);
  setBar(DOM.barStrengthGood, DOM.labelStrengthGood, dist.good || 0);
  setBar(DOM.barStrengthFair, DOM.labelStrengthFair, dist.fair || 0);
  setBar(DOM.barStrengthWeak, DOM.labelStrengthWeak, dist.weak || 0);

  // Table des utilisateurs et statistiques par collaborateur
  DOM.statsUsersList.innerHTML = '';
  const users = Object.keys(stats.userDistribution || {}).sort((a, b) => a.localeCompare(b, 'fr'));
  
  if (users.length === 0) {
    DOM.statsUsersList.innerHTML = `<tr><td colspan="3" class="text-center text-muted">Aucun mot de passe en base.</td></tr>`;
    return;
  }

  users.forEach(username => {
    const count = stats.userDistribution[username];
    // Évaluer un niveau de risque arbitraire selon les statistiques globales
    let riskLevel = 'Faible';
    let riskClass = 'cat-tag personnel';
    
    if (count > 8 || stats.reusedPasswords > 1) {
      riskLevel = 'Élevé';
      riskClass = 'cat-tag finance';
    } else if (count > 4 || stats.extremelyWeak > 0) {
      riskLevel = 'Modéré';
      riskClass = 'cat-tag professionnel';
    }

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${escapeHTML(username)}</strong></td>
      <td>${count} secret(s)</td>
      <td><span class="${riskClass}">${riskLevel}</span></td>
    `;
    DOM.statsUsersList.appendChild(tr);
  });
}

// Afficher la table des utilisateurs LDAP/AD
function renderAdminUsers(users) {
  DOM.adminUsersList.innerHTML = '';

  const sorted = [...users]
    .filter(u => u.username && u.username.trim())
    .sort((a, b) => (a.displayName || a.username).localeCompare(b.displayName || b.username, 'fr'));

  if (DOM.adminUsersCount) {
    DOM.adminUsersCount.textContent = `${sorted.length} utilisateur(s)`;
  }

  if (sorted.length === 0) {
    DOM.adminUsersList.innerHTML = `<tr><td colspan="6" class="text-center text-muted">Aucun utilisateur trouvé.</td></tr>`;
    return;
  }

  sorted.forEach(u => {
    const tr = document.createElement('tr');
    
    // Rendre les groupes AD sous forme de badges
    const groupsBadges = (u.groups || []).map(g => {
      let badgeClass = 'general';
      const gLower = g.toLowerCase();
      if (gLower.includes('admin') || gLower.includes('security') || gLower.includes('administrateur')) {
        badgeClass = 'professionnel';
      }
      return `<span class="cat-tag ${badgeClass}" style="margin: 2px; font-size:0.65rem;">${escapeHTML(g)}</span>`;
    }).join(' ');

    // Normalize and format creation date; handle various LDAP formats and invalid values
    let dateStr = 'Non disponible';
    if (u.whenCreated) {
      // ignore placeholder invalid strings
      const raw = String(u.whenCreated).trim();
      if (raw && !/invalid/i.test(raw)) {
        const formatted = formatDate(raw);
        dateStr = formatted || 'Non disponible';
      }
    }

    tr.innerHTML = `
      <td>
        <div class="user-cell">
          <div class="user-avatar">${(u.displayName || u.username || '?').substring(0, 2).toUpperCase()}</div>
          <span class="user-fullname">${escapeHTML(u.displayName || u.username)}</span>
        </div>
      </td>
      <td><span class="text-muted">@${escapeHTML(u.username)}</span></td>
      <td>${u.email ? `<a href="mailto:${escapeHTML(u.email)}" class="card-url">${escapeHTML(u.email)}</a>` : '<span class="text-muted">—</span>'}</td>
      <td><div style="display:flex; flex-wrap:wrap; gap:4px;">${groupsBadges || '<span class="text-muted">Aucun groupe</span>'}</div></td>
      <td><span class="text-muted">${dateStr}</span></td>
      <td class="actions-cell" style="display:flex; gap:8px; justify-content:flex-end;">
        <button class="btn btn-sm btn-outline btn-edit-user" data-username="${escapeHTML(u.username)}">Modifier</button>
        <button class="btn btn-sm btn-danger btn-delete-user" data-username="${escapeHTML(u.username)}">Supprimer</button>
      </td>
    `;
    DOM.adminUsersList.appendChild(tr);
  });
}

async function handleAdminUserSearch() {
  await loadAdminData();
}

function getAdminUserActions() {
  return {
    editButtons: Array.from(document.querySelectorAll('.btn-edit-user')),
    deleteButtons: Array.from(document.querySelectorAll('.btn-delete-user'))
  };
}

function attachAdminUserActionHandlers() {
  const { editButtons, deleteButtons } = getAdminUserActions();

  editButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const username = button.dataset.username;
      openEditUserModal({ username, displayName: '', email: '' });
    });
  });

  deleteButtons.forEach((button) => {
    button.addEventListener('click', async () => {
      const username = button.dataset.username;
      if (!confirm(`Supprimer l\'utilisateur ${username} ? Cette action est irréversible.`)) return;
      try {
        const res = await fetch(`${API_URL}/admin/users/${encodeURIComponent(username)}`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${state.token}`,
            ...getAntiReplayHeaders()
          }
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Impossible de supprimer l\'utilisateur.');
        showToast(data.message || 'Utilisateur supprimé avec succès.');
        await loadAdminData();
      } catch (error) {
        showToast(error.message, 'danger');
      }
    });
  });
}

// Ajouter un utilisateur Active Directory (admin uniquement)
async function handleAddUser(e) {
  e.preventDefault();
  if (!state.token) return;

  const username = DOM.addUserUsername.value.trim();
  const displayName = DOM.addUserDisplayname.value.trim();
  const email = DOM.addUserEmail.value.trim();
  const password = DOM.addUserPassword.value;

  const usernameCheck = validateUsernameInput(username);
  if (!usernameCheck.valid) {
    showAddUserError(usernameCheck.error);
    return;
  }

  if (!displayName || displayName.length < 2) {
    showAddUserError('Le nom d\'affichage est obligatoire (min. 2 caractères).');
    return;
  }

  if (/[\0\(\)\*\\<>;]/.test(displayName)) {
    showAddUserError('Caractères non autorisés dans le nom d\'affichage.');
    return;
  }

  if (password.length < 8) {
    showAddUserError('Le mot de passe doit contenir au moins 8 caractères.');
    return;
  }

  hideElement(DOM.addUserError);
  DOM.btnAddUser.disabled = true;

  try {
    const res = await fetch(`${API_URL}/admin/users`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.token}`,
        ...getAntiReplayHeaders()
      },
      body: JSON.stringify({
        username: usernameCheck.username,
        displayName,
        email,
        password
      })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Impossible de créer l\'utilisateur.');

    showToast(data.warning || `Utilisateur ${usernameCheck.username} créé avec succès.`, data.warning ? 'warning' : 'success');
    DOM.addUserForm.reset();
    await loadAdminData();
  } catch (error) {
    showAddUserError(error.message);
  } finally {
    DOM.btnAddUser.disabled = false;
    if (window.lucide) lucide.createIcons();
  }
}

function showAddUserError(message) {
  DOM.addUserError.querySelector('.alert-message').textContent = message;
  showElement(DOM.addUserError);
}

function validateUsernameInput(username) {
  const sanitized = String(username || '').trim().toLowerCase();
  if (!sanitized || sanitized.length < 2 || sanitized.length > 64) {
    return { valid: false, error: 'Nom d\'utilisateur invalide (2 à 64 caractères).' };
  }
  if (!/^[a-z0-9._-]+$/.test(sanitized)) {
    return { valid: false, error: 'Caractères non autorisés. Utilisez lettres, chiffres, points, tirets ou underscores.' };
  }
  return { valid: true, username: sanitized };
}

// ==========================================
// GESTION DES LOGS D'INSCRIPTION
// ==========================================

async function loadRegistrationLogs() {
  if (!state.token) return;
  showElement(DOM.logsLoader);
  hideElement(DOM.logsEmpty);
  DOM.logsList.innerHTML = '';

  try {
    const res = await fetch(`${API_URL}/registration-logs`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    if (!res.ok) {
      if (res.status === 401 || res.status === 403) {
        handleLogout();
        return;
      }
      throw new Error('Erreur lors du chargement des logs.');
    }
    const logs = await res.json();
    renderRegistrationLogs(logs);
  } catch (error) {
    console.error('Erreur logs inscription :', error);
    showToast(error.message, 'danger');
  } finally {
    hideElement(DOM.logsLoader);
  }
}

function renderRegistrationLogs(logs) {
  DOM.logsList.innerHTML = '';
  if (!logs || logs.length === 0) {
    showElement(DOM.logsEmpty);
    return;
  }
  hideElement(DOM.logsEmpty);

  logs.forEach(log => {
    const date = new Date(log.timestamp);
    const div = document.createElement('div');
    div.className = 'password-card';
    div.innerHTML = `
      <div class="card-header">
        <div class="card-title-group">
          <h4>${escapeHTML(log.domain || 'inconnu')}</h4>
          <a href="${escapeHTML(log.url || '#')}" target="_blank" rel="noopener noreferrer" class="card-url">
            <i data-lucide="external-link" style="width:12px; height:12px;"></i>
            <span>${escapeHTML((log.url || '').substring(0, 60))}</span>
          </a>
        </div>
        <span class="cat-tag general">${date.toLocaleString('fr-FR')}</span>
      </div>
      <div class="card-body">
        <div class="detail-row">
          <span class="detail-label">Champs remplis</span>
          <span class="detail-value">${log.fieldsFilled || 0}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Mot de passe genere</span>
          <div class="password-value-container">
            <span class="password-val text-muted" data-visible="false">••••••••••</span>
            <button class="btn-card-toggle btn-toggle-pwd" title="Afficher/Masquer">
              <i data-lucide="eye"></i>
            </button>
            <button class="btn-card-copy btn-copy-pwd" title="Copier le mot de passe">
              <i data-lucide="copy"></i>
            </button>
          </div>
        </div>
      </div>
    `;

    const pwdSpan = div.querySelector('.password-val');
    const toggleBtn = div.querySelector('.btn-toggle-pwd');
    const copyBtn = div.querySelector('.btn-copy-pwd');

    toggleBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const isVisible = pwdSpan.getAttribute('data-visible') === 'true';
      if (isVisible) {
        pwdSpan.textContent = '••••••••••';
        pwdSpan.className = 'password-val text-muted';
        pwdSpan.setAttribute('data-visible', 'false');
        toggleBtn.innerHTML = '<i data-lucide="eye"></i>';
      } else {
        pwdSpan.textContent = log.passwordGenerated || '—';
        pwdSpan.className = 'password-val text-main';
        pwdSpan.setAttribute('data-visible', 'true');
        toggleBtn.innerHTML = '<i data-lucide="eye-off"></i>';
      }
      lucide.createIcons();
    });

    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      copyToClipboard(log.passwordGenerated || '', 'Mot de passe copié !');
    });

    DOM.logsList.appendChild(div);
  });

  lucide.createIcons();
}

// ==========================================
// GESTION DU GÉNÉRATEUR (LOCAL & INTERACTIF)
// ==========================================

// Génère localement le mot de passe selon les paramètres actuels du DOM
function generateLocalPassword() {
  const length = parseInt(DOM.genLength.value);
  const upper = DOM.genOptUpper.checked;
  const lower = DOM.genOptLower.checked;
  const numbers = DOM.genOptNumbers.checked;
  const symbols = DOM.genOptSymbols.checked;
  const similar = DOM.genOptSimilar.checked;
  
  // S'assurer qu'au moins une option est cochée
  if (!upper && !lower && !numbers && !symbols) {
    DOM.genOutput.value = '';
    updateStrengthBar(0);
    return;
  }
  
  const password = generatePasswordString(length, upper, lower, numbers, symbols, similar);
  DOM.genOutput.value = password;
  
  // Déclenche une légère animation pour signaler le nouveau mot de passe
  DOM.genOutput.classList.remove('pwd-animate');
  void DOM.genOutput.offsetWidth; // Force reflow
  DOM.genOutput.classList.add('pwd-animate');
  
  // Calculer et afficher la force du mot de passe
  const strength = calculateStrength(password, upper, lower, numbers, symbols);
  updateStrengthBar(strength);
}

// Génère de façon sécurisée un mot de passe en javascript
function generatePasswordString(length, upper, lower, numbers, symbols, similar) {
  let upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let lowerChars = 'abcdefghijklmnopqrstuvwxyz';
  let numberChars = '0123456789';
  let symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  if (similar) {
    // Écarter O, o, I, i, l, 0, 1
    upperChars = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    lowerChars = 'abcdefghjkmnpqrstuvwxyz';
    numberChars = '23456789';
  }
  
  let charset = '';
  const selectedSets = [];
  
  if (upper) { charset += upperChars; selectedSets.push(upperChars); }
  if (lower) { charset += lowerChars; selectedSets.push(lowerChars); }
  if (numbers) { charset += numberChars; selectedSets.push(numberChars); }
  if (symbols) { charset += symbolChars; selectedSets.push(symbolChars); }
  
  let result = [];
  
  // S'assure d'inclure au moins 1 caractère de chaque type sélectionné
  selectedSets.forEach(set => {
    const randomIdx = getRandomInt(0, set.length);
    result.push(set[randomIdx]);
  });
  
  // Remplir le reste
  while (result.length < length) {
    const randomIdx = getRandomInt(0, charset.length);
    result.push(charset[randomIdx]);
  }
  
  // Mélange (Fisher-Yates)
  for (let i = result.length - 1; i > 0; i--) {
    const j = getRandomInt(0, i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  
  return result.join('');
}

// Génération aléatoire pseudo-cryptographique locale (avec repli Math.random si contexte non sécurisé)
function getRandomInt(min, max) {
  if (window.crypto && window.crypto.getRandomValues) {
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    return min + (array[0] % (max - min));
  } else {
    // Repli pour les contextes non-sécurisés (ex: accès via IP en HTTP)
    return Math.floor(Math.random() * (max - min)) + min;
  }
}

// Calcul simple de l'entropie / force
function calculateStrength(pwd, upper, lower, numbers, symbols) {
  if (!pwd || pwd.length < 8) return 1; // Trop court
  
  let score = 0;
  
  // 1. Longueur
  if (pwd.length >= 16) score += 2;
  else if (pwd.length >= 12) score += 1;
  
  // 2. Diversité des jeux de caractères
  let varieties = 0;
  if (/[a-z]/.test(pwd)) varieties++;
  if (/[A-Z]/.test(pwd)) varieties++;
  if (/[0-9]/.test(pwd)) varieties++;
  if (/[^a-zA-Z0-9]/.test(pwd)) varieties++;
  
  score += Math.floor(varieties / 2);
  
  // Bonus pour grande complexité
  if (pwd.length >= 14 && varieties === 4) score++;
  
  // Score final borné entre 1 et 4
  return Math.min(4, Math.max(1, score));
}

// Met à jour la barre de couleur
function updateStrengthBar(strength) {
  // Reset
  DOM.genStrengthBar.className = 'strength-bar';
  
  switch (strength) {
    case 0:
      DOM.genStrengthBar.style.width = '0%';
      DOM.genStrengthText.textContent = 'Aucun';
      DOM.genStrengthText.className = 'text-danger';
      break;
    case 1:
      DOM.genStrengthBar.classList.add('weak');
      DOM.genStrengthText.textContent = 'Faible';
      DOM.genStrengthText.className = 'text-danger';
      break;
    case 2:
      DOM.genStrengthBar.classList.add('fair');
      DOM.genStrengthText.textContent = 'Moyen';
      DOM.genStrengthText.className = 'text-warning';
      break;
    case 3:
      DOM.genStrengthBar.classList.add('good');
      DOM.genStrengthText.textContent = 'Fort';
      DOM.genStrengthText.className = 'text-info';
      break;
    case 4:
      DOM.genStrengthBar.classList.add('strong');
      DOM.genStrengthText.textContent = 'Très Sécurisé';
      DOM.genStrengthText.className = 'text-success';
      break;
  }
}

// Copie du mot de passe du générateur
function copyGenPassword() {
  const pwd = DOM.genOutput.value;
  if (!pwd) return;
  
  copyToClipboard(pwd, 'Mot de passe copié !');
  
  // Ajouter à l'historique de session
  addToHistory(pwd);
}

// Ajouter le mot de passe à la session de l'historique
function addToHistory(pwd) {
  if (state.history.includes(pwd)) return;
  
  // Limiter à 5 éléments
  state.history.unshift(pwd);
  if (state.history.length > 5) {
    state.history.pop();
  }
  
  renderHistory();
}

function renderHistory() {
  DOM.genHistoryList.innerHTML = '';
  
  if (state.history.length === 0) {
    DOM.genHistoryList.innerHTML = '<li class="history-empty">Aucun mot de passe généré dans cette session.</li>';
    return;
  }
  
  state.history.forEach(pwd => {
    const li = document.createElement('li');
    li.className = 'history-item';
    li.innerHTML = `
      <span class="history-pwd">${escapeHTML(pwd)}</span>
      <button class="btn-card-copy btn-history-copy" title="Copier">
        <i data-lucide="copy"></i>
      </button>
    `;
    
    li.querySelector('.btn-history-copy').addEventListener('click', () => {
      copyToClipboard(pwd, 'Mot de passe historique copié !');
    });
    
    DOM.genHistoryList.appendChild(li);
  });
  
  lucide.createIcons();
}

// ==========================================
// OUTILS ET MODALS (Helpers)
// ==========================================

// Afficher un écran
function showLoginScreen() {
  hideElement(DOM.dashboardContainer);
  showElement(DOM.loginContainer);
}

function showDashboardScreen() {
  hideElement(DOM.loginContainer);
  showElement(DOM.dashboardContainer);
}

// Navigation par onglets (SPA Switching)
// Navigation par onglets (SPA Switching — Approche Data-Driven)
const routesMap = {
  'vault': { nav: 'navVault', section: 'sectionVault', action: () => renderVault() },
  'security': { nav: 'navSecurity', section: 'sectionSecurity', action: () => loadSecurityScore() },
  'shared-with-me': { nav: 'navSharedWithMe', section: 'sectionSharedWithMe', action: () => loadSharedWithMe() },
  'generator': { nav: 'navGenerator', section: 'sectionGenerator', action: () => setTimeout(generateLocalPassword, 10) },
  'extension': { nav: 'navExtension', section: 'sectionExtension' },
  'logs': { nav: 'navLogs', section: 'sectionLogs', action: () => loadRegistrationLogs() },
  'admin': { nav: 'navAdmin', section: 'sectionAdmin', action: () => loadAdminData() }
};

function switchTab(tab) {
  state.activeTab = tab;
  if (DOM.sidebar) DOM.sidebar.classList.remove('sidebar-open');

  Object.keys(routesMap).forEach(key => {
    const route = routesMap[key];
    const navEl = DOM[route.nav];
    const sectionEl = DOM[route.section];
    if (navEl) {
      if (key === tab) navEl.classList.add('active');
      else navEl.classList.remove('active');
    }
    if (sectionEl) {
      if (key === tab) showElement(sectionEl);
      else hideElement(sectionEl);
    }
  });

  const activeRoute = routesMap[tab];
  if (activeRoute && typeof activeRoute.action === 'function') {
    activeRoute.action();
  }
}

// Toggle menu mobile
function toggleMobileMenu() {
  if (DOM.sidebar) {
    DOM.sidebar.classList.toggle('sidebar-open');
  }
}

// Ouvrir le modal en mode Création ou Édition
function openModal(editItem = null) {
  hideElement(DOM.modalError);
  DOM.passwordForm.reset();
  
  // Reset password field visibility
  DOM.entryPassword.type = 'password';
  if (DOM.btnToggleModalPwd) {
    DOM.btnToggleModalPwd.innerHTML = '<i data-lucide="eye"></i>';
  }
  
  if (editItem) {
    DOM.modalTitle.textContent = 'Modifier le mot de passe';
    DOM.entryId.value = editItem.id;
    DOM.entryTitle.value = editItem.title || '';
    DOM.entryCategory.value = editItem.category || 'Général';
    DOM.entryWebsite.value = editItem.websiteUrl || '';
    DOM.entryUsername.value = editItem.username || '';
    DOM.entryPassword.value = editItem.password || '';
    DOM.entryNotes.value = editItem.notes || '';
  } else {
    DOM.modalTitle.textContent = 'Ajouter un mot de passe';
    DOM.entryId.value = '';
    DOM.entryCategory.value = 'Général';
  }
  
  showElement(DOM.passwordModal);
  lucide.createIcons();
}

function closeModal() {
  hideElement(DOM.passwordModal);
}

// Utilitaire de copie dans le presse-papier
function copyToClipboard(text, message = 'Copié !') {
  if (!navigator.clipboard) {
    // Méthode de secours
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      showToast(message);
    } catch (err) {
      showToast('Échec de la copie.', 'danger');
    }
    document.body.removeChild(textarea);
    return;
  }
  
  navigator.clipboard.writeText(text)
    .then(() => showToast(message))
    .catch(() => showToast('Échec de la copie.', 'danger'));
}

// Affichage d'un toast informatif temporaire
let toastTimeout;
function showToast(message, type = 'success') {
  DOM.toastMessage.textContent = message;
  
  // Icone et style du toast
  const icon = DOM.toast.querySelector('.toast-icon');
  DOM.toast.classList.remove('toast-success', 'toast-danger');
  
  if (type === 'success') {
    DOM.toast.classList.add('toast-success');
    icon.className = 'toast-icon text-success';
    icon.setAttribute('data-lucide', 'check-circle');
  } else if (type === 'warning') {
    DOM.toast.classList.add('toast-success');
    icon.className = 'toast-icon text-warning';
    icon.setAttribute('data-lucide', 'alert-triangle');
  } else {
    DOM.toast.classList.add('toast-danger');
    icon.className = 'toast-icon text-danger';
    icon.setAttribute('data-lucide', 'alert-triangle');
  }
  
  lucide.createIcons();
  
  showElement(DOM.toast);
  
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => {
    hideElement(DOM.toast);
  }, 2500);
}

// Fonctions d'affichage utilitaires
function showElement(el) {
  if (el) el.classList.remove('hidden');
}

// Cacher un élément
function hideElement(el) {
  if (el) el.classList.add('hidden');
}

// Échapper le code HTML pour se prémunir des failles XSS
function escapeHTML(str) {
  if (!str) return '';
  return str.replace(/[&<>'"]/g, 
    tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag)
  );
}

// Formate une date en chaîne lisible
function formatDate(isoString) {
  if (!isoString) return '';
  // Accept ISO string or LDAP generalizedTime like 20260713131400Z or 202607131314Z
  let s = String(isoString).trim();
  // If already a Date object
  if (s instanceof Date) s = s.toString();

  // Try direct parse first
  let date = new Date(s);
  if (isNaN(date.getTime())) {
    // Try LDAP generalizedTime YYYYMMDDHHmmssZ or YYYYMMDDHHmmss
    const m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?(Z?)$/);
    if (m) {
      // m[7] is fractional seconds (optional), m[8] is trailing Z (optional)
      const iso = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[8] ? 'Z' : ''}`;
      date = new Date(iso);
    }
  }

  if (isNaN(date.getTime())) return '';

  return date.toLocaleDateString('fr-FR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric'
  }) + ' à ' + date.toLocaleTimeString('fr-FR', {
    hour: '2-digit',
    minute: '2-digit'
  });
}

// Ouvrir un site enregistré et lancer la connexion directe
function handleDirectConnect(item) {
  if (!item.websiteUrl) return;

  const targetUrl = item.websiteUrl;

  const bridgeMessage = {
    type: 'SECURPASS_DIRECT_FILL',
    url: targetUrl,
    username: item.username || '',
    password: item.password || ''
  };

  try {
    window.postMessage(bridgeMessage, '*');
  } catch (e) {
    console.warn('Impossible d\'envoyer le message au pont SecurPass :', e);
  }

  window.open(targetUrl, '_blank');
  showToast('Tentative de connexion directe via l\'extension...');
}

// ==========================================
// IMPORT / EXPORT DE MOTS DE PASSE
// ==========================================

// Ouvrir le modal d'import
function openImportModal() {
  hideElement(DOM.importError);
  hideElement(DOM.importSuccess);
  if (DOM.importForm) DOM.importForm.reset();
  showElement(DOM.importModal);
  lucide.createIcons();
}

// Fermer le modal d'import
function closeImportModal() {
  hideElement(DOM.importModal);
}

// Gérer la soumission du formulaire d'import
async function handleImportSubmit(e) {
  e.preventDefault();
  
  const fileInput = DOM.importFileInput;
  const format = DOM.importFormatSelect.value;
  
  if (!fileInput.files || fileInput.files.length === 0) {
    showImportError('Veuillez sélectionner un fichier.');
    return;
  }
  
  const file = fileInput.files[0];
  hideElement(DOM.importError);
  hideElement(DOM.importSuccess);
  
  DOM.btnSubmitImport.disabled = true;
  DOM.btnSubmitImport.querySelector('span').textContent = 'Import en cours...';
  
  try {
    const fileContent = await file.text();
    
    const response = await fetch(`${API_URL}/vault/import`, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'Authorization': `Bearer ${state.token}`,
        'X-Import-Format': format,
        ...getAntiReplayHeaders()
      },
      body: fileContent
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Erreur lors de l\'import');
    }
    
    // Afficher le succès
    const successMsg = `${data.imported || 0} mot(s) de passe importé(s) avec succès !`;
    DOM.importSuccess.querySelector('.alert-message').textContent = successMsg;
    showElement(DOM.importSuccess);
    
    // Recharger le coffre-fort
    await loadVaultData();
    
    // Fermer après 2 secondes
    setTimeout(() => {
      closeImportModal();
    }, 2000);
    
    showToast(successMsg);
  } catch (error) {
    showImportError(error.message);
  } finally {
    DOM.btnSubmitImport.disabled = false;
    DOM.btnSubmitImport.querySelector('span').textContent = 'Importer maintenant';
  }
}

function showImportError(message) {
  DOM.importError.querySelector('.alert-message').textContent = message;
  showElement(DOM.importError);
}

// Export CSV
async function handleExportCSV() {
  if (!state.token) return;
  
  try {
    const response = await fetch(`${API_URL}/vault/export/csv`, {
      headers: {
        'Authorization': `Bearer ${state.token}`
      }
    });
    
    if (!response.ok) {
      throw new Error('Erreur lors de l\'export CSV');
    }
    
    const csvContent = await response.text();
    
    // Télécharger le fichier
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `securpass-export-${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    showToast('Export CSV téléchargé avec succès !');
  } catch (error) {
    console.error('Erreur export CSV:', error);
    showToast(error.message, 'danger');
  }
}

// Export JSON Bitwarden
async function handleExportJSON() {
  if (!state.token) return;
  
  try {
    const response = await fetch(`${API_URL}/vault/export/json`, {
      headers: {
        'Authorization': `Bearer ${state.token}`
      }
    });
    
    if (!response.ok) {
      throw new Error('Erreur lors de l\'export JSON');
    }
    
    const jsonContent = await response.text();
    
    // Télécharger le fichier
    const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `securpass-bitwarden-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    showToast('Export JSON Bitwarden téléchargé avec succès !');
  } catch (error) {
    console.error('Erreur export JSON:', error);
    showToast(error.message, 'danger');
  }
}

// ==========================================
// PARTAGE DE MOTS DE PASSE
// ==========================================

// Ouvrir le modal de partage
function openShareModal(item) {
  hideElement(DOM.shareError);
  if (DOM.shareForm) DOM.shareForm.reset();
  
  DOM.sharePasswordId.value = item.id;
  DOM.sharePasswordTitleDisplay.textContent = item.title || 'Sans titre';
  
  // Sélectionner "lecture seule" par défaut
  const readRadio = document.querySelector('input[name="share-permission"][value="read"]');
  if (readRadio) readRadio.checked = true;
  
  // Sélectionner "7 jours" par défaut
  DOM.shareExpiration.value = '7d';
  
  showElement(DOM.shareModal);
  lucide.createIcons();
}

// Fermer le modal de partage
function closeShareModal() {
  hideElement(DOM.shareModal);
}

// Gérer la soumission du formulaire de partage
async function handleShareSubmit(e) {
  e.preventDefault();
  
  const passwordId = DOM.sharePasswordId.value;
  const sharedWith = DOM.shareUsername.value.trim().toLowerCase();
  const permission = document.querySelector('input[name="share-permission"]:checked').value;
  const expirationValue = DOM.shareExpiration.value;
  
  // Calculer le nombre de jours d'expiration (le backend fait son propre calcul)
  let expiresInDays = null;
  if (expirationValue !== 'never') {
    if (expirationValue === '24h') {
      expiresInDays = 1;
    } else if (expirationValue === '7d') {
      expiresInDays = 7;
    } else if (expirationValue === '30d') {
      expiresInDays = 30;
    } else if (expirationValue === '90d') {
      expiresInDays = 90;
    }
  }
  
  hideElement(DOM.shareError);
  DOM.btnSubmitShare.disabled = true;
  DOM.btnSubmitShare.querySelector('span').textContent = 'Partage en cours...';
  
  try {
    const response = await fetch(`${API_URL}/vault/${passwordId}/share`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.token}`,
        ...getAntiReplayHeaders()
      },
      body: JSON.stringify({
        sharedWith,
        permission,
        expiresInDays  // Le backend calcule la date d'expiration à partir de ce nombre
      })
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.error || 'Erreur lors du partage');
    }
    
    showToast(`Mot de passe partagé avec ${sharedWith} !`);
    closeShareModal();
  } catch (error) {
    showShareError(error.message);
  } finally {
    DOM.btnSubmitShare.disabled = false;
    DOM.btnSubmitShare.querySelector('span').textContent = 'Partager';
  }
}

function showShareError(message) {
  DOM.shareError.querySelector('.alert-message').textContent = message;
  showElement(DOM.shareError);
}

// Ouvrir le modal de gestion des partages
async function openManageSharesModal(item) {
  DOM.manageSharesPasswordId = item.id;
  DOM.manageSharesPasswordTitle.textContent = item.title || 'Sans titre';
  
  showElement(DOM.manageSharesModal);
  showElement(DOM.manageSharesLoader);
  hideElement(DOM.manageSharesList);
  hideElement(DOM.manageSharesEmpty);
  
  lucide.createIcons();
  
  try {
    const response = await fetch(`${API_URL}/vault/${item.id}/shares`, {
      headers: {
        'Authorization': `Bearer ${state.token}`
      }
    });
    
    if (!response.ok) {
      throw new Error('Erreur lors du chargement des partages');
    }
    
    const shares = await response.json();
    renderManageShares(shares);
  } catch (error) {
    console.error('Erreur chargement partages:', error);
    showToast(error.message, 'danger');
    closeManageSharesModal();
  } finally {
    hideElement(DOM.manageSharesLoader);
  }
}

// Fermer le modal de gestion des partages
function closeManageSharesModal() {
  hideElement(DOM.manageSharesModal);
  DOM.manageSharesPasswordId = null;
}

// Afficher la liste des partages
function renderManageShares(shares) {
  DOM.manageSharesList.innerHTML = '';
  
  if (!shares || shares.length === 0) {
    showElement(DOM.manageSharesEmpty);
    hideElement(DOM.manageSharesList);
    return;
  }
  
  hideElement(DOM.manageSharesEmpty);
  showElement(DOM.manageSharesList);
  
  shares.forEach(share => {
    const card = document.createElement('div');
    card.style.cssText = 'padding: 15px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; display: flex; justify-content: space-between; align-items: center;';
    
    const permissionIcon = share.permission === 'write' ? '✏️' : '👁️';
    const permissionText = share.permission === 'write' ? 'Lecture + Modification' : 'Lecture seule';
    
    let expirationText = 'Permanent';
    if (share.expiresAt) {
      const expiryDate = new Date(share.expiresAt);
      expirationText = `Expire le ${formatDate(share.expiresAt)}`;
    }
    
    card.innerHTML = `
      <div>
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 5px;">
          <div class="user-avatar" style="width: 36px; height: 36px; border-radius: 50%; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; align-items: center; justify-content: center; color: #fff; font-weight: 600; font-size: 0.9rem;">
            ${(share.sharedWith || '?').substring(0, 2).toUpperCase()}
          </div>
          <div>
            <strong style="color: #fff; font-size: 0.95rem;">@${escapeHTML(share.sharedWith)}</strong>
            <div style="display: flex; align-items: center; gap: 8px; margin-top: 3px;">
              <span style="font-size: 0.8rem; color: rgba(255,255,255,0.6);">${permissionIcon} ${permissionText}</span>
              <span style="font-size: 0.8rem; color: rgba(255,255,255,0.5);">•</span>
              <span style="font-size: 0.8rem; color: rgba(255,255,255,0.6);">${expirationText}</span>
            </div>
          </div>
        </div>
      </div>
      <button class="btn btn-sm btn-danger btn-revoke-share" data-username="${escapeHTML(share.sharedWith)}">
        <i data-lucide="x"></i>
        <span>Révoquer</span>
      </button>
    `;
    
    card.querySelector('.btn-revoke-share').addEventListener('click', async () => {
      if (!confirm(`Révoquer l'accès de ${share.sharedWith} à ce mot de passe ?`)) return;
      
      try {
        const response = await fetch(`${API_URL}/vault/${DOM.manageSharesPasswordId}/share/${share.sharedWith}`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${state.token}`,
            ...getAntiReplayHeaders()
          }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
          throw new Error(data.error || 'Erreur lors de la révocation');
        }
        
        showToast(`Accès révoqué pour ${share.sharedWith}`);
        
        // Recharger la liste
        const item = state.passwords.find(p => p.id === DOM.manageSharesPasswordId);
        if (item) {
          await openManageSharesModal(item);
        }
      } catch (error) {
        console.error('Erreur révocation:', error);
        showToast(error.message, 'danger');
      }
    });
    
    DOM.manageSharesList.appendChild(card);
  });
  
  lucide.createIcons();
}

// Charger les mots de passe partagés avec moi
async function loadSharedWithMe() {
  if (!state.token) return;
  
  showElement(DOM.sharedLoader);
  hideElement(DOM.sharedWithMeGrid);
  hideElement(DOM.sharedWithMeEmpty);
  
  try {
    const response = await fetch(`${API_URL}/vault/shared-with-me`, {
      headers: {
        'Authorization': `Bearer ${state.token}`
      }
    });
    
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        handleLogout();
        return;
      }
      throw new Error('Erreur lors du chargement des mots de passe partagés');
    }
    
    const sharedPasswords = await response.json();
    renderSharedWithMe(sharedPasswords);
  } catch (error) {
    console.error('Erreur mots de passe partagés:', error);
    showToast(error.message, 'danger');
  } finally {
    hideElement(DOM.sharedLoader);
  }
}

// Afficher les mots de passe partagés avec moi
function renderSharedWithMe(sharedPasswords) {
  DOM.sharedWithMeGrid.innerHTML = '';
  
  if (!sharedPasswords || sharedPasswords.length === 0) {
    showElement(DOM.sharedWithMeEmpty);
    hideElement(DOM.sharedWithMeGrid);
    return;
  }
  
  hideElement(DOM.sharedWithMeEmpty);
  showElement(DOM.sharedWithMeGrid);
  
  sharedPasswords.forEach(item => {
    const card = document.createElement('div');
    card.className = 'password-card';
    card.style.borderLeft = '3px solid #60a5fa';
    
    const category = item.category || 'Général';
    const catClass = category.toLowerCase().replace(/\s+/g, '-');
    
    let displayUrl = item.websiteUrl || '';
    if (displayUrl) {
      try {
        displayUrl = new URL(item.websiteUrl).hostname;
      } catch (e) {
        // format invalide
      }
    }
    
    const permissionIcon = item.permission === 'write' ? '✏️' : '👁️';
    const permissionText = item.permission === 'write' ? 'Modification autorisée' : 'Lecture seule';
    
    let expirationBadge = '';
    if (item.expiresAt) {
      const expiryDate = new Date(item.expiresAt);
      const daysLeft = Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 3600 * 24));
      if (daysLeft > 0 && daysLeft <= 3) {
        expirationBadge = `<span class="cat-tag personnel" style="font-size: 0.75rem; background: rgba(239,68,68,0.2); border: 1px solid #f87171; color: #f87171;">⚠️ Expire dans ${daysLeft}j</span>`;
      } else {
        expirationBadge = `<span class="cat-tag professionnel" style="font-size: 0.75rem;">⏰ Expire le ${expiryDate.toLocaleDateString('fr-FR')}</span>`;
      }
    }
    
    card.innerHTML = `
      <div class="card-header">
        <div class="card-title-group">
          <h4>${escapeHTML(item.title)}</h4>
          ${item.websiteUrl ? `
            <a href="${escapeHTML(item.websiteUrl)}" target="_blank" rel="noopener noreferrer" class="card-url">
              <i data-lucide="external-link" style="width:12px; height:12px;"></i>
              <span>${escapeHTML(displayUrl)}</span>
            </a>
          ` : '<span class="card-url">Sans adresse URL</span>'}
        </div>
        <div style="display: flex; gap: 5px; align-items: center;">
          <span class="cat-tag ${catClass}">${escapeHTML(category)}</span>
          ${expirationBadge}
        </div>
      </div>
      
      <div style="padding: 10px 20px; background: rgba(96, 165, 250, 0.1); border-top: 1px solid rgba(96, 165, 250, 0.2); border-bottom: 1px solid rgba(96, 165, 250, 0.2);">
        <div style="display: flex; align-items: center; gap: 8px; font-size: 0.85rem; color: rgba(255,255,255,0.8);">
          <i data-lucide="user" style="width: 14px; height: 14px;"></i>
          <span>Partagé par <strong style="color: #60a5fa;">@${escapeHTML(item.owner)}</strong></span>
          <span style="margin: 0 5px; color: rgba(255,255,255,0.4);">•</span>
          <span>${permissionIcon} ${permissionText}</span>
        </div>
      </div>
      
      <div class="card-body">
        <div class="detail-row">
          <span class="detail-label">Identifiant</span>
          <div class="password-value-container">
            <span class="detail-value" title="${escapeHTML(item.username || '')}">${escapeHTML(item.username || 'Non renseigné')}</span>
            ${item.username ? `
              <button class="btn-card-copy btn-copy-username" title="Copier l'identifiant">
                <i data-lucide="copy"></i>
              </button>
            ` : ''}
          </div>
        </div>
        
        <div class="detail-row">
          <span class="detail-label">Mot de passe</span>
          <div class="password-value-container">
            <span class="password-val text-muted" data-visible="false">••••••••</span>
            <button class="btn-card-toggle btn-toggle-pwd" title="Afficher/Masquer">
              <i data-lucide="eye"></i>
            </button>
            <button class="btn-card-copy btn-copy-pwd" title="Copier le mot de passe">
              <i data-lucide="copy"></i>
            </button>
          </div>
        </div>
      </div>
      
      <div class="card-actions">
        <span class="user-subtext">Partagé le : ${formatDate(item.createdAt)}</span>
        <div class="action-buttons">
          ${item.websiteUrl ? `
            <button class="btn btn-outline btn-ghost btn-icon-only btn-direct-connect text-success" title="Connexion Directe">
              <i data-lucide="zap" style="width:16px; height:16px;"></i>
            </button>
          ` : ''}
        </div>
      </div>
    `;
    
    // Attacher les écouteurs
    setupSharedCardListeners(card, item);
    
    DOM.sharedWithMeGrid.appendChild(card);
  });
  
  lucide.createIcons();
}

// Configurer les écouteurs pour les cartes partagées
function setupSharedCardListeners(card, item) {
  const copyUserBtn = card.querySelector('.btn-copy-username');
  if (copyUserBtn) {
    copyUserBtn.addEventListener('click', () => {
      copyToClipboard(item.username, 'Identifiant copié !');
    });
  }
  
  const togglePwdBtn = card.querySelector('.btn-toggle-pwd');
  const pwdValSpan = card.querySelector('.password-val');
  togglePwdBtn.addEventListener('click', () => {
    const isVisible = pwdValSpan.getAttribute('data-visible') === 'true';
    if (isVisible) {
      pwdValSpan.textContent = '••••••••';
      pwdValSpan.className = 'password-val text-muted';
      pwdValSpan.setAttribute('data-visible', 'false');
      togglePwdBtn.innerHTML = '<i data-lucide="eye"></i>';
    } else {
      pwdValSpan.textContent = item.password || '—';
      pwdValSpan.className = 'password-val text-main';
      pwdValSpan.setAttribute('data-visible', 'true');
      togglePwdBtn.innerHTML = '<i data-lucide="eye-off"></i>';
    }
    lucide.createIcons();
  });
  
  const copyPwdBtn = card.querySelector('.btn-copy-pwd');
  copyPwdBtn.addEventListener('click', () => {
    copyToClipboard(item.password || '', 'Mot de passe copié !');
  });
  
  const directConnectBtn = card.querySelector('.btn-direct-connect');
  if (directConnectBtn) {
    directConnectBtn.addEventListener('click', () => {
      handleDirectConnect(item);
    });
  }
}

// ==========================================
// SCORE DE SÉCURITÉ & ANALYSE VULNÉRABILITÉS
// ==========================================

async function loadSecurityScore() {
  if (!state.token) return;
  try {
    const res = await fetch(`${API_URL}/vault/security-score`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    if (!res.ok) return;
    const data = await res.json();
    renderSecurityDashboard(data);
  } catch (err) {
    console.error('Erreur du chargement du score de sécurité :', err);
  }
}

function renderSecurityDashboard(data) {
  if (!data || !DOM.securityScoreNumber) return;
  const { overallScore, metrics, vulnerableItems } = data;

  DOM.securityScoreNumber.textContent = overallScore;
  if (DOM.scoreCircleBar) {
    DOM.scoreCircleBar.setAttribute('stroke-dasharray', `${overallScore}, 100`);
    if (overallScore >= 80) {
      DOM.securityScoreStatus.textContent = 'Excellente Sécurité';
      DOM.securityScoreStatus.style.color = '#4ade80';
      DOM.scoreCircleBar.setAttribute('stroke', '#4ade80');
    } else if (overallScore >= 60) {
      DOM.securityScoreStatus.textContent = 'Sécurité Bonne';
      DOM.securityScoreStatus.style.color = '#60a5fa';
      DOM.scoreCircleBar.setAttribute('stroke', '#60a5fa');
    } else if (overallScore >= 40) {
      DOM.securityScoreStatus.textContent = 'Sécurité Moyenne';
      DOM.securityScoreStatus.style.color = '#fbbf24';
      DOM.scoreCircleBar.setAttribute('stroke', '#fbbf24');
    } else {
      DOM.securityScoreStatus.textContent = 'Sécurité Critique';
      DOM.securityScoreStatus.style.color = '#f87171';
      DOM.scoreCircleBar.setAttribute('stroke', '#f87171');
    }
  }

  if (DOM.metricWeakCount) DOM.metricWeakCount.textContent = metrics?.weakCount || 0;
  if (DOM.metricReusedCount) DOM.metricReusedCount.textContent = metrics?.reusedCount || 0;
  if (DOM.metricExpiredCount) DOM.metricExpiredCount.textContent = metrics?.expiredCount || 0;

  if (DOM.securityVulnerabilitiesList) {
    DOM.securityVulnerabilitiesList.innerHTML = '';
    if (!vulnerableItems || vulnerableItems.length === 0) {
      DOM.securityVulnerabilitiesList.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px; color:rgba(255,255,255,0.5);">Aucune vulnérabilité détectée. Tous vos mots de passe sont robustes et uniques !</td></tr>';
    } else {
      vulnerableItems.forEach(item => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>${escapeHTML(item.title)}</strong></td>
          <td><code>${escapeHTML(item.username || '—')}</code></td>
          <td><span style="color:#f87171; font-size:0.85rem;">${item.issues.map(i => escapeHTML(i)).join(' • ')}</span></td>
          <td style="text-align:right;">
            <button class="btn btn-outline btn-sm btn-fix-vuln">Corriger</button>
          </td>
        `;
        tr.querySelector('.btn-fix-vuln').addEventListener('click', () => {
          switchTab('vault');
          const pwdItem = state.passwords.find(p => p.id === item.id);
          if (pwdItem) openModal(pwdItem);
        });
        DOM.securityVulnerabilitiesList.appendChild(tr);
      });
    }
  }
  if (window.lucide) lucide.createIcons();
}

// ==========================================
// VÉRIFICATION HIBP (PROXIED K-ANONYMITY)
// ==========================================

async function checkHIBP(password, btnEl, badgeEl) {
  if (!password) {
    showToast('Aucun mot de passe à vérifier.', 'warning');
    return;
  }
  try {
    if (btnEl) {
      btnEl.disabled = true;
      btnEl.textContent = 'Vérification...';
    }
    const res = await fetch(`${API_URL}/hibp/check?password=${encodeURIComponent(password)}`, {
      headers: { 'Authorization': `Bearer ${state.token}` }
    });
    const data = await res.json();
    if (data.breached) {
      if (badgeEl) {
        badgeEl.className = 'badge-hibp-breached';
        badgeEl.style.display = 'inline-flex';
        badgeEl.innerHTML = `<i data-lucide="alert-triangle" style="width:12px; height:12px;"></i> Fuite détectée (${data.count} fois)`;
      }
      showToast(`⚠️ Attention : ce mot de passe apparaît dans ${data.count} fuites de données HIBP !`, 'danger');
    } else {
      if (badgeEl) {
        badgeEl.className = 'badge-hibp-safe';
        badgeEl.style.display = 'inline-flex';
        badgeEl.innerHTML = `<i data-lucide="shield-check" style="width:12px; height:12px;"></i> Aucun risque connu (HIBP)`;
      }
      showToast('✅ Ce mot de passe n\'apparaît dans aucune fuite connue.');
    }
  } catch (e) {
    showToast('Erreur de communication avec le service HIBP.', 'danger');
  } finally {
    if (btnEl) {
      btnEl.disabled = false;
      btnEl.textContent = 'Vérifier fuite';
    }
    if (window.lucide) lucide.createIcons();
  }
}

// ==========================================
// EXPORTATION CHIFFRÉE AES-256-GCM
// ==========================================

function openExportEncryptedModal() {
  if (!DOM.exportEncryptedModal) return;
  hideElement(DOM.exportError);
  DOM.exportPasswordInput.value = '';
  DOM.exportPasswordConfirm.value = '';
  updateExportStrength();
  showElement(DOM.exportEncryptedModal);
  DOM.exportPasswordInput.focus();
  lucide.createIcons();
}

function closeExportEncryptedModal() {
  hideElement(DOM.exportEncryptedModal);
}

function updateExportStrength() {
  const pwd = DOM.exportPasswordInput.value;
  const len = pwd.length;
  let score = 0;
  if (len >= 8) score++;
  if (/[A-Z]/.test(pwd)) score++;
  if (/[0-9]/.test(pwd)) score++;
  if (/[^a-zA-Z0-9]/.test(pwd)) score++;

  if (!DOM.exportStrengthBar || !DOM.exportStrengthText) return;

  if (len === 0) {
    DOM.exportStrengthBar.style.width = '0%';
    DOM.exportStrengthText.textContent = '—';
    DOM.exportStrengthText.style.color = 'rgba(255,255,255,0.5)';
  } else if (score <= 1) {
    DOM.exportStrengthBar.style.width = '25%';
    DOM.exportStrengthBar.style.background = '#f87171';
    DOM.exportStrengthText.textContent = 'Faible';
    DOM.exportStrengthText.style.color = '#f87171';
  } else if (score === 2) {
    DOM.exportStrengthBar.style.width = '50%';
    DOM.exportStrengthBar.style.background = '#fbbf24';
    DOM.exportStrengthText.textContent = 'Moyen';
    DOM.exportStrengthText.style.color = '#fbbf24';
  } else if (score === 3) {
    DOM.exportStrengthBar.style.width = '75%';
    DOM.exportStrengthBar.style.background = '#60a5fa';
    DOM.exportStrengthText.textContent = 'Fort';
    DOM.exportStrengthText.style.color = '#60a5fa';
  } else {
    DOM.exportStrengthBar.style.width = '100%';
    DOM.exportStrengthBar.style.background = '#4ade80';
    DOM.exportStrengthText.textContent = 'Très Sécurisé';
    DOM.exportStrengthText.style.color = '#4ade80';
  }
}

function toggleExportPwdVisibility() {
  const input = DOM.exportPasswordInput;
  const btn = DOM.btnToggleExportPwd;
  if (input.type === 'password') {
    input.type = 'text';
    btn.innerHTML = '<i data-lucide="eye-off"></i>';
  } else {
    input.type = 'password';
    btn.innerHTML = '<i data-lucide="eye"></i>';
  }
  lucide.createIcons();
}

async function handleSubmitExportEncrypted(e) {
  e.preventDefault();
  const exportPassword = DOM.exportPasswordInput.value;
  if (!exportPassword) {
    DOM.exportError.querySelector('.alert-message').textContent = 'Un mot de passe d\'export est requis.';
    showElement(DOM.exportError);
    return;
  }
  if (exportPassword.length < 4) {
    DOM.exportError.querySelector('.alert-message').textContent = 'Le mot de passe d\'export doit contenir au moins 4 caractères.';
    showElement(DOM.exportError);
    return;
  }
  const confirmPwd = DOM.exportPasswordConfirm.value;
  if (confirmPwd !== exportPassword) {
    DOM.exportError.querySelector('.alert-message').textContent = 'Les mots de passe ne correspondent pas.';
    showElement(DOM.exportError);
    return;
  }

  hideElement(DOM.exportError);
  DOM.btnSubmitExportModal.disabled = true;
  DOM.btnSubmitExportModal.querySelector('span').textContent = 'Génération...';

  try {
    const res = await fetch(`${API_URL}/vault/export/encrypted`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.token}`,
        ...getAntiReplayHeaders()
      },
      body: JSON.stringify({ exportPassword })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Erreur lors de l\'export chiffré');

    const blob = new Blob([JSON.stringify(data.payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = data.filename || `securpass_export_${Date.now()}.enc`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('🔒 Export AES-256-GCM chiffré téléchargé avec succès !');
    closeExportEncryptedModal();
  } catch (err) {
    showToast(err.message, 'danger');
  } finally {
    DOM.btnSubmitExportModal.disabled = false;
    DOM.btnSubmitExportModal.querySelector('span').textContent = 'Générer l\'export chiffré';
  }
}

async function handleExportEncrypted() {
  openExportEncryptedModal();
}

// ==========================================
// INDICATEUR DE FORCE DU MODAL
// ==========================================

function updateModalStrength() {
  const pwd = DOM.entryPassword.value;
  const len = pwd.length;
  let score = 0;
  if (len >= 8) score++;
  if (/[A-Z]/.test(pwd)) score++;
  if (/[0-9]/.test(pwd)) score++;
  if (/[^a-zA-Z0-9]/.test(pwd)) score++;

  if (!DOM.modalStrengthBar || !DOM.modalStrengthText) return;

  if (len === 0) {
    DOM.modalStrengthBar.style.width = '0%';
    DOM.modalStrengthText.textContent = '—';
    DOM.modalStrengthText.style.color = 'rgba(255,255,255,0.5)';
  } else if (score <= 1) {
    DOM.modalStrengthBar.style.width = '25%';
    DOM.modalStrengthBar.style.background = '#f87171';
    DOM.modalStrengthText.textContent = 'Faible';
    DOM.modalStrengthText.style.color = '#f87171';
  } else if (score === 2) {
    DOM.modalStrengthBar.style.width = '50%';
    DOM.modalStrengthBar.style.background = '#fbbf24';
    DOM.modalStrengthText.textContent = 'Moyen';
    DOM.modalStrengthText.style.color = '#fbbf24';
  } else if (score === 3) {
    DOM.modalStrengthBar.style.width = '75%';
    DOM.modalStrengthBar.style.background = '#60a5fa';
    DOM.modalStrengthText.textContent = 'Fort';
    DOM.modalStrengthText.style.color = '#60a5fa';
  } else {
    DOM.modalStrengthBar.style.width = '100%';
    DOM.modalStrengthBar.style.background = '#4ade80';
    DOM.modalStrengthText.textContent = 'Très Sécurisé';
    DOM.modalStrengthText.style.color = '#4ade80';
  }
}

// ==========================================
// CONFIGURATION ET VÉRIFICATION TOTP 2FA
// ==========================================

async function handleTotpSetup() {
  try {
    const res = await fetch(`${API_URL}/auth/totp/setup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.token}`,
        ...getAntiReplayHeaders()
      }
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Erreur lors du setup TOTP.');

    if (DOM.totpSecretCode) DOM.totpSecretCode.textContent = data.secret;
    if (DOM.totpSetupDisplay) showElement(DOM.totpSetupDisplay);
    showToast('Clé secrète 2FA TOTP générée.');
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

async function handleTotpVerify() {
  const token = DOM.totpVerifyInput ? DOM.totpVerifyInput.value.trim() : '';
  if (!token || token.length !== 6) {
    showToast('Veuillez saisir un code TOTP valide à 6 chiffres.', 'warning');
    return;
  }
  try {
    const res = await fetch(`${API_URL}/auth/totp/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.token}`,
        ...getAntiReplayHeaders()
      },
      body: JSON.stringify({ token })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Code invalide');
    showToast('✅ Code 2FA TOTP vérifié avec succès !', 'success');
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

// ==========================================
// MODAL D'ÉDITION D'UTILISATEUR (SANS PROMPT)
// ==========================================

function openEditUserModal(user) {
  if (!DOM.editUserModal) return;
  DOM.editUserTargetUsername.value = user.username;
  DOM.editUserDisplayname.value = user.displayName || '';
  DOM.editUserEmail.value = user.email || '';
  DOM.editUserNewPassword.value = '';
  showElement(DOM.editUserModal);
}

function closeEditUserModal() {
  if (DOM.editUserModal) hideElement(DOM.editUserModal);
}

async function handleEditUserSubmit(e) {
  e.preventDefault();
  const username = DOM.editUserTargetUsername.value;
  const displayName = DOM.editUserDisplayname.value.trim();
  const email = DOM.editUserEmail.value.trim();
  const password = DOM.editUserNewPassword.value;

  try {
    const res = await fetch(`${API_URL}/admin/users/${encodeURIComponent(username)}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.token}`,
        ...getAntiReplayHeaders()
      },
      body: JSON.stringify({ displayName, email, password: password || undefined })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Erreur lors de la modification.');
    showToast(data.message || `Utilisateur ${username} mis à jour.`);
    closeEditUserModal();
    await loadAdminData();
  } catch (err) {
    showToast(err.message, 'danger');
  }
}
