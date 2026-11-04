(function () {
  const EV = globalThis.EmailVerifier;
  const PANEL_CLASS = 'email-verifier-panel';
  const SCAN_DELAY_MS = 300;

  const reports = new Map();
  let brands = [];
  let brandsReady = null;
  let scanTimer = null;

  function loadBrands() {
    brandsReady = chrome.storage.sync.get({ brandsText: EV.DEFAULT_BRANDS_TEXT }).then((stored) => {
      brands = EV.parseBrands(stored.brandsText);
    });
    return brandsReady;
  }

  function messageIds(node) {
    const permanent = (node.getAttribute('data-message-id') || '').replace(/^#/, '');
    const legacy = node.getAttribute('data-legacy-message-id') || '';
    const permmsgid = permanent.startsWith('msg-') ? permanent : '';
    return { permmsgid, legacy };
  }

  function extractRaw(text) {
    const looksLikeHtml = /^\s*(<!doctype|<html)/i.test(text);
    if (!looksLikeHtml) return text;
    const page = new DOMParser().parseFromString(text, 'text/html');
    return page.querySelector('#raw_message_text, .raw_message_text')?.textContent || '';
  }

  async function fetchRaw({ permmsgid, legacy }) {
    const base = `${location.origin}${location.pathname}`;
    const ik = document.documentElement.getAttribute('data-ev-ik');
    const urls = [];
    if (permmsgid) {
      if (ik) urls.push(`${base}?ik=${encodeURIComponent(ik)}&view=om&permmsgid=${permmsgid}`);
      urls.push(`${base}?view=om&permmsgid=${permmsgid}`);
    }
    if (legacy) urls.push(`${base}?view=att&th=${legacy}&attid=0&disp=comp&safe=1&zw`);

    for (const url of urls) {
      try {
        const response = await fetch(url, { credentials: 'include' });
        if (!response.ok) continue;
        const raw = extractRaw(await response.text());
        if (EV.parseHeaders(raw).some((header) => header.name === 'from')) return raw;
      } catch {
        // Se prueba con la siguiente URL.
      }
    }
    throw new Error('Gmail no ha entregado el original del correo.');
  }

  async function lookup(msg) {
    const dkim = msg.dkimSignatures
      .filter((signature) => signature.d && signature.s)
      .map((signature) => ({ domain: signature.d.toLowerCase(), selector: signature.s.toLowerCase() }));
    try {
      const response = await chrome.runtime.sendMessage({ type: 'lookup', domain: msg.from.domain, dkim });
      return response?.ok ? response.result : null;
    } catch {
      return null;
    }
  }

  function collectLinks(node) {
    return [...node.querySelectorAll('.a3s a[href]')].slice(0, 200).map((anchor) => ({
      href: anchor.href,
      text: anchor.textContent,
    }));
  }

  async function buildReport(node, ids) {
    await brandsReady;
    const msg = EV.parseMessage(await fetchRaw(ids));
    const dns = msg.from.domain ? await lookup(msg) : null;
    return EV.evaluate({ msg, dns, brands, links: collectLinks(node) });
  }

  // Al guardar, el aviso de cambios de storage vuelve a dibujar los paneles.
  async function addBrand(name, domain) {
    const stored = await chrome.storage.sync.get({ brandsText: EV.DEFAULT_BRANDS_TEXT });
    await chrome.storage.sync.set({ brandsText: EV.addBrandDomain(stored.brandsText, name, domain) });
  }

  function attach(node) {
    const body = node.querySelector('.a3s');
    if (!body || node.querySelector(`.${PANEL_CLASS}`)) return;
    const ids = messageIds(node);
    if (!ids.permmsgid && !ids.legacy) return;

    const host = document.createElement('div');
    host.className = PANEL_CLASS;
    const anchor = body.closest('.ii') || body;
    anchor.parentNode.insertBefore(host, anchor);
    const panel = EV.createPanel(host, { onAddBrand: addBrand });
    panel.loading();

    const key = ids.permmsgid || ids.legacy;
    if (!reports.has(key)) reports.set(key, buildReport(node, ids));
    reports.get(key).then(
      (report) => panel.show(report),
      (error) => {
        reports.delete(key);
        panel.error(error.message);
      },
    );
  }

  function scan() {
    document.querySelectorAll('div[data-message-id]').forEach(attach);
  }

  function scheduleScan() {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(scan, SCAN_DELAY_MS);
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'sync' || !changes.brandsText) return;
    loadBrands();
    reports.clear();
    document.querySelectorAll(`.${PANEL_CLASS}`).forEach((panel) => panel.remove());
    scan();
  });

  loadBrands();
  new MutationObserver(scheduleScan).observe(document.body, { childList: true, subtree: true });
  scan();
})();
