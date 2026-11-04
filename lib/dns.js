(function (root) {
  const EV = (root.EmailVerifier = root.EmailVerifier || {});

  const RESOLVERS = [
    (name, type) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    (name, type) => `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
  ];
  const TIMEOUT_MS = 6000;
  const DNS_NAME = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/;

  function txtValue(data) {
    const parts = [...String(data).matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
    return parts.length ? parts.join('') : String(data);
  }

  async function query(name, type, fetchFn) {
    for (const url of RESOLVERS) {
      try {
        const response = await fetchFn(url(name, type), {
          headers: { accept: 'application/dns-json' },
          signal: AbortSignal.timeout(TIMEOUT_MS),
        });
        if (!response.ok) continue;
        const body = await response.json();
        // 0 = existe, 3 = el nombre no existe. Lo demás es fallo del resolutor.
        if (body.Status !== 0 && body.Status !== 3) continue;
        const code = type === 'TXT' ? 16 : 15;
        const answers = (body.Answer || []).filter((a) => a.type === code).map((a) => a.data);
        return { error: false, answers, secure: Boolean(body.AD) };
      } catch {
        // Se prueba con el siguiente resolutor.
      }
    }
    return { error: true, answers: [], secure: false };
  }

  // Busca un TXT en el dominio y, si no está, en el dominio raíz.
  async function firstTxt(names, pattern, fetchFn) {
    let error = false;
    for (const name of [...new Set(names)]) {
      const response = await query(name, 'TXT', fetchFn);
      error = error || response.error;
      const record = response.answers.map(txtValue).find((text) => pattern.test(text));
      if (record) return { record, foundAt: name, error: false };
    }
    return { record: '', foundAt: '', error };
  }

  async function lookupRegistration(org, fetchFn) {
    try {
      const response = await fetchFn(`https://rdap.org/domain/${encodeURIComponent(org)}`, {
        headers: { accept: 'application/rdap+json' },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!response.ok) return null;
      const body = await response.json();
      const event = (body.events || []).find((e) => e.eventAction === 'registration');
      return event?.eventDate || null;
    } catch {
      return null;
    }
  }

  async function lookupDomain(domain, dkimTargets = [], fetchFn = root.fetch.bind(root)) {
    if (!DNS_NAME.test(domain || '')) throw new Error('Dominio no válido');
    const org = EV.orgDomain(domain);

    const [spfResponse, mx, dmarc, mtaSts, tlsRpt, bimi, registered, dkim] = await Promise.all([
      query(domain, 'TXT', fetchFn),
      query(domain, 'MX', fetchFn),
      firstTxt([`_dmarc.${domain}`, `_dmarc.${org}`], /^v=dmarc1/i, fetchFn),
      firstTxt([`_mta-sts.${domain}`, `_mta-sts.${org}`], /^v=stsv1/i, fetchFn),
      firstTxt([`_smtp._tls.${domain}`, `_smtp._tls.${org}`], /^v=tlsrptv1/i, fetchFn),
      firstTxt([`default._bimi.${domain}`, `default._bimi.${org}`], /^v=bimi1/i, fetchFn),
      lookupRegistration(org, fetchFn),
      Promise.all(
        dkimTargets
          .filter((t) => DNS_NAME.test(`${t.selector}._domainkey.${t.domain}`))
          .slice(0, 5)
          .map(async (t) => {
            const response = await query(`${t.selector}._domainkey.${t.domain}`, 'TXT', fetchFn);
            return {
              ...t,
              record: response.answers.map(txtValue).find((text) => /(^|;)\s*p=/i.test(text)) || '',
              error: response.error,
            };
          }),
      ),
    ]);

    return {
      spf: {
        records: spfResponse.answers.map(txtValue).filter((text) => /^v=spf1\b/i.test(text)),
        error: spfResponse.error,
      },
      mx: { records: mx.answers, error: mx.error },
      dmarc,
      mtaSts,
      tlsRpt,
      bimi,
      dkim,
      dnssec: spfResponse.secure,
      registered,
    };
  }

  Object.assign(EV, { lookupDomain, txtValue });
})(globalThis);
