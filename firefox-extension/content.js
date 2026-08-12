// SecurPass Content Script for Firefox
// Polyfill: use browser.* if available, otherwise chrome.*
if (typeof browser !== 'undefined' && browser.runtime && browser.runtime.id) {
  var chrome = browser;
}

const API_URL = 'https://localhost:5443/api';

function getDomain(urlStr) {
  if (!urlStr) return '';
  try {
    const formattedUrl = /^https?:\/\//i.test(urlStr.trim()) ? urlStr.trim() : `https://${urlStr.trim()}`;
    const url = new URL(formattedUrl);
    return url.hostname.replace(/^www\./i, '').toLowerCase();
  } catch (e) {
    return urlStr.toLowerCase();
  }
}

function fillCredentials(username, password) {
  const inputs = document.querySelectorAll('input');
  let usernameField = null;
  let passwordField = null;

  for (const input of inputs) {
    if (input.type === 'hidden' || input.disabled || input.readOnly) continue;

    const type = (input.type || '').toLowerCase();
    const name = (input.name || '').toLowerCase();
    const id = (input.id || '').toLowerCase();
    const placeholder = (input.placeholder || '').toLowerCase();
    const autocomplete = (input.autocomplete || '').toLowerCase();

    if (type === 'password' || autocomplete.includes('password')) {
      if (!passwordField) passwordField = input;
    } else if (
      type === 'email' ||
      type === 'text' ||
      autocomplete.includes('username') ||
      autocomplete.includes('email') ||
      name.includes('user') ||
      id.includes('user') ||
      name.includes('login') ||
      id.includes('login') ||
      name.includes('email') ||
      id.includes('email') ||
      placeholder.includes('identifiant') ||
      placeholder.includes('username') ||
      placeholder.includes('pseudo') ||
      placeholder.includes('e-mail') ||
      placeholder.includes('email')
    ) {
      if (!usernameField && type !== 'password') {
        usernameField = input;
      }
    }
  }

  let filledCount = 0;

  if (usernameField && username) {
    usernameField.value = username;
    usernameField.dispatchEvent(new Event('input', { bubbles: true }));
    usernameField.dispatchEvent(new Event('change', { bubbles: true }));
    usernameField.dispatchEvent(new Event('blur', { bubbles: true }));
    filledCount++;
  }

  if (passwordField && password) {
    passwordField.value = password;
    passwordField.dispatchEvent(new Event('input', { bubbles: true }));
    passwordField.dispatchEvent(new Event('change', { bubbles: true }));
    passwordField.dispatchEvent(new Event('blur', { bubbles: true }));
    filledCount++;
  }

  if (filledCount > 0) {
    console.log(`[SecurPass DirectFill] Remplissage automatique effectue avec succes (${filledCount} champ(s)).`);
    return true;
  }
  return false;
}

async function autoFillCurrentSite() {
  const currentUrl = window.location.href;
  const currentDomain = getDomain(currentUrl);
  if (!currentDomain) return;

  try {
    let items = [];
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      const stored = await chrome.storage.local.get(['securpass_vault', 'securpass_token']);
      items = stored.securpass_vault || [];

      if ((!items || items.length === 0) && stored.securpass_token) {
        try {
          const res = await fetch(`${API_URL}/vault`, {
            headers: { 'Authorization': `Bearer ${stored.securpass_token}` }
          });
          if (res.ok) {
            items = await res.json();
            await chrome.storage.local.set({ securpass_vault: items });
          }
        } catch (e) {
          console.warn('[SecurPass DirectFill] Impossible d\'interroger l\'API SecurPass :', e);
        }
      }
    }

    if (!items || items.length === 0) return;

    const match = items.find(item => {
      if (!item.websiteUrl) return false;
      const itemDomain = getDomain(item.websiteUrl);
      if (!itemDomain) return false;

      if (currentDomain === itemDomain || currentDomain.endsWith(`.${itemDomain}`) || itemDomain.endsWith(`.${currentDomain}`)) {
        return true;
      }

      const currentFileName = currentUrl.split('/').pop().split('#')[0].split('?')[0];
      const itemFileName = item.websiteUrl.split('/').pop().split('#')[0].split('?')[0];
      if (currentFileName && itemFileName && currentFileName === itemFileName && currentFileName.includes('.html')) {
        return true;
      }

      return false;
    });

    if (!match) return;

    console.log(`[SecurPass DirectFill] Compte trouve pour ${currentDomain} : « ${match.title} »`);

    let success = fillCredentials(match.username, match.password);

    if (!success) {
      let attempts = 0;
      const interval = setInterval(() => {
        attempts++;
        if (fillCredentials(match.username, match.password) || attempts > 10) {
          clearInterval(interval);
        }
      }, 500);

      const observer = new MutationObserver(() => {
        if (fillCredentials(match.username, match.password)) {
          observer.disconnect();
          clearInterval(interval);
        }
      });
      observer.observe(document.body || document.documentElement, { childList: true, subtree: true });
    }

  } catch (err) {
    console.warn('[SecurPass DirectFill Error] :', err);
  }
}

function isRegistrationPage() {
  const currentUrl = (window.location.href || '').toLowerCase();
  const registrationIndicators = [
    'signup', 'register', 'sign-up', 'register', 'create-account',
    'createaccount', 'inscription', 'enregistrement', 'join', 'subscribe',
    'new-account', 'newaccount', 'account/create', 'user/register'
  ];

  if (registrationIndicators.some(ind => currentUrl.includes(ind))) {
    return true;
  }

  const forms = document.querySelectorAll('form');
  for (const form of forms) {
    const formHtml = (form.innerHTML || '').toLowerCase();
    const formAction = (form.action || '').toLowerCase();
    if (registrationIndicators.some(ind => formHtml.includes(ind) || formAction.includes(ind))) {
      return true;
    }

    const inputs = form.querySelectorAll('input[type="password"]');
    if (inputs.length >= 2) {
      const names = Array.from(inputs).map(i => (i.name || '').toLowerCase()).join(' ');
      if (names.includes('confirm') || names.includes('repeat') || names.includes('verify')) {
        return true;
      }
    }
  }

  return false;
}

function fillRegistrationForm() {
  const inputs = document.querySelectorAll('input');
  let emailField = null;
  let passwordField = null;
  let confirmField = null;
  let nameField = null;

  for (const input of inputs) {
    if (input.type === 'hidden' || input.disabled || input.readOnly) continue;

    const type = (input.type || '').toLowerCase();
    const name = (input.name || '').toLowerCase();
    const id = (input.id || '').toLowerCase();
    const autocomplete = (input.autocomplete || '').toLowerCase();

    if (type === 'password') {
      if (!passwordField && (autocomplete.includes('new-password') || name.includes('password') || id.includes('password'))) {
        passwordField = input;
      } else if (!confirmField && passwordField && confirmField !== input) {
        confirmField = input;
      } else if (!passwordField) {
        passwordField = input;
      }
    } else if (
      type === 'email' ||
      autocomplete === 'email' ||
      name.includes('email') ||
      id.includes('email')
    ) {
      if (!emailField) emailField = input;
    } else if (
      type === 'text' &&
      (autocomplete === 'name' || autocomplete === 'given-name' || name.includes('name') || id.includes('name'))
    ) {
      if (!nameField) nameField = input;
    }
  }

  let filledCount = 0;
  const generatedPassword = generateSecurePassword();

  if (emailField) {
    emailField.value = 'nouveau.utilisateur@exemple.com';
    emailField.dispatchEvent(new Event('input', { bubbles: true }));
    emailField.dispatchEvent(new Event('change', { bubbles: true }));
    emailField.dispatchEvent(new Event('blur', { bubbles: true }));
    filledCount++;
  }

  if (nameField) {
    nameField.value = 'Nouvel Utilisateur';
    nameField.dispatchEvent(new Event('input', { bubbles: true }));
    nameField.dispatchEvent(new Event('change', { bubbles: true }));
    nameField.dispatchEvent(new Event('blur', { bubbles: true }));
    filledCount++;
  }

  if (passwordField) {
    passwordField.value = generatedPassword;
    passwordField.dispatchEvent(new Event('input', { bubbles: true }));
    passwordField.dispatchEvent(new Event('change', { bubbles: true }));
    passwordField.dispatchEvent(new Event('blur', { bubbles: true }));
    filledCount++;
  }

  if (confirmField) {
    confirmField.value = generatedPassword;
    confirmField.dispatchEvent(new Event('input', { bubbles: true }));
    confirmField.dispatchEvent(new Event('change', { bubbles: true }));
    confirmField.dispatchEvent(new Event('blur', { bubbles: true }));
    filledCount++;
  }

  if (filledCount > 0) {
    console.log(`[SecurPass Registration] Formulaire d'inscription rempli automatiquement (${filledCount} champ(s)).`);

    const currentDomain = getDomain(window.location.href);
    sendRegistrationLog({
      domain: currentDomain,
      url: window.location.href,
      passwordGenerated: generatedPassword,
      fieldsFilled: filledCount,
      timestamp: new Date().toISOString()
    });

    return true;
  }
  return false;
}

function generateSecurePassword() {
  const length = 16;
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
  const randomValues = new Uint32Array(length);
  crypto.getRandomValues(randomValues);

  let password = '';
  for (let i = 0; i < length; i++) {
    password += charset[randomValues[i] % charset.length];
  }
  return password;
}

async function sendRegistrationLog(logData) {
  try {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      const stored = await chrome.storage.local.get(['securpass_token']);
      if (stored.securpass_token) {
        await fetch(`${API_URL}/registration-logs`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${stored.securpass_token}`
          },
          body: JSON.stringify(logData)
        });
      }
    }
  } catch (e) {
    console.warn('[SecurPass RegistrationLog] Impossible d\'envoyer le log :', e);
  }
}

async function startRegistrationDetection() {
  if (isRegistrationPage()) {
    console.log('[SecurPass] Page d\'inscription detectee, tentative de remplissage...');
    const filled = fillRegistrationForm();

    if (!filled) {
      let attempts = 0;
      const interval = setInterval(() => {
        attempts++;
        if (fillRegistrationForm() || attempts > 10) {
          clearInterval(interval);
        }
      }, 500);

      const observer = new MutationObserver(() => {
        if (fillRegistrationForm()) {
          observer.disconnect();
          clearInterval(interval);
        }
      });
      observer.observe(document.body || document.documentElement, { childList: true, subtree: true });
    }
  }
}

if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'fill_credentials') {
      const success = fillCredentials(request.username, request.password);
      sendResponse({ success: success, filled: success ? 2 : 0 });
    }
    return true;
  });
}

if (typeof window !== 'undefined') {
  window.addEventListener('message', async (event) => {
    if (!event.data || typeof event.data !== 'object') return;
    if (event.data.type !== 'SECURPASS_DIRECT_FILL') return;

    const { url, username, password } = event.data;
    if (!url) return;

    try {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        const fillData = {
          id: (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : Date.now().toString(),
          url,
          username: username || '',
          password: password || '',
          timestamp: new Date().toISOString()
        };
        await chrome.storage.local.set({ securpass_direct_fill: fillData });
      }
    } catch (e) {
      console.warn('[SecurPass Bridge] Impossible de stocker le remplissage direct :', e);
    }
  });
}

async function checkPendingDirectFill() {
  if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return;

  for (let i = 0; i < 10; i++) {
    try {
      const stored = await chrome.storage.local.get(['securpass_direct_fill']);
      const pending = stored.securpass_direct_fill;
      if (!pending) break;

      const currentUrl = window.location.href;
      const currentDomain = getDomain(currentUrl);
      const pendingDomain = getDomain(pending.url);

      if (currentDomain && pendingDomain && (currentDomain === pendingDomain || currentDomain.endsWith(`.${pendingDomain}`) || pendingDomain.endsWith(`.${currentDomain}`))) {
        console.log(`[SecurPass Bridge] Remplissage direct en attente pour ${currentDomain}`);
        const success = fillCredentials(pending.username, pending.password);
        if (success) {
          await chrome.storage.local.remove('securpass_direct_fill');
          return;
        }
      }
    } catch (e) {
      console.warn('[SecurPass Bridge] Erreur verification remplissage direct :', e);
    }
    await new Promise(r => setTimeout(r, 500));
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', async () => {
    await checkPendingDirectFill();
    autoFillCurrentSite();
    startRegistrationDetection();
  });
} else {
  checkPendingDirectFill();
  autoFillCurrentSite();
  startRegistrationDetection();
}
