// SecurPass Background for Firefox
// Polyfill: use browser.* if available, otherwise chrome.*
if (typeof browser !== 'undefined' && browser.runtime && browser.runtime.id) {
  var chrome = browser;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'direct_fill') {
    const { url, username, password } = request;

    const fillData = {
      id: (typeof crypto !== 'undefined' && crypto.randomUUID)
        ? crypto.randomUUID()
        : Date.now().toString(),
      url,
      username: username || '',
      password: password || '',
      timestamp: new Date().toISOString()
    };

    chrome.storage.local.set({ securpass_direct_fill: fillData }, () => {
      chrome.tabs.create({ url }, (tab) => {
        if (chrome.runtime.lastError) {
          sendResponse({ success: false, error: chrome.runtime.lastError.message });
        } else {
          sendResponse({ success: true, tabId: tab.id });
        }
      });
    });

    return true;
  }

  if (request.action === 'get_direct_fill') {
    chrome.storage.local.get(['securpass_direct_fill'], (result) => {
      const data = result.securpass_direct_fill || null;
      if (data) {
        chrome.storage.local.remove('securpass_direct_fill');
      }
      sendResponse({ data });
    });
    return true;
  }
});
