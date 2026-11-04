importScripts('lib/domains.js', 'lib/dns.js');

const EV = globalThis.EmailVerifier;

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || request?.type !== 'lookup') return false;
  EV.lookupDomain(request.domain, request.dkim || [])
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => sendResponse({ ok: false, error: String(error) }));
  return true;
});

chrome.action.onClicked.addListener(() => chrome.runtime.openOptionsPage());
