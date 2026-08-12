chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
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
