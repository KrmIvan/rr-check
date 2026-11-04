(function (root) {
  const EV = (root.EmailVerifier = root.EmailVerifier || {});

  // Subconjunto de la Public Suffix List: cubre los sufijos más habituales,
  // no todos. Un sufijo ausente hace que el dominio raíz se calcule de más.
  const MULTI_LABEL_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk',
    'com.es', 'org.es', 'nom.es', 'gob.es', 'edu.es',
    'com.mx', 'org.mx', 'gob.mx', 'com.ar', 'gob.ar', 'com.br', 'gov.br',
    'com.co', 'gov.co', 'com.pe', 'gob.pe', 'com.ve',
    'com.au', 'net.au', 'org.au', 'gov.au', 'co.nz', 'co.za',
    'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'com.cn', 'com.tw', 'com.hk',
    'co.in', 'com.tr', 'com.sg', 'com.pt', 'com.ua', 'co.il',
  ]);

  const FREE_MAIL = new Set([
    'gmail.com', 'googlemail.com', 'outlook.com', 'outlook.es', 'hotmail.com',
    'hotmail.es', 'live.com', 'msn.com', 'yahoo.com', 'yahoo.es', 'ymail.com',
    'icloud.com', 'me.com', 'aol.com', 'proton.me', 'protonmail.com',
    'gmx.com', 'gmx.es', 'mail.com', 'zoho.com', 'yandex.com',
  ]);

  // Plataformas donde cualquier cliente puede enviar desde un subdominio propio:
  // confiar en el dominio raíz sería confiar en todos sus clientes.
  const SHARED_PLATFORMS = new Set([
    'zendesk.com', 'freshdesk.com', 'sendgrid.net', 'mailgun.org', 'amazonses.com',
    'mcsv.net', 'rsgsv.net', 'mailchimpapp.net', 'mandrillapp.com', 'hubspotemail.net',
    'sparkpostmail.com', 'exacttarget.com', 'force.com', 'postmarkapp.com',
    'constantcontact.com', 'onmicrosoft.com', 'googlegroups.com', 'github.io',
  ]);

  const SINGLE_HOMOGLYPHS = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's',
    'ο': 'o', 'α': 'a', 'ε': 'e', 'ı': 'i',
    0: 'o', 1: 'l', i: 'l', 3: 'e', 5: 's',
  };

  // Punto de partida: revisable por el usuario en la página de opciones.
  // El primer dominio de cada línea es el que se usa para detectar imitaciones.
  const DEFAULT_BRANDS_TEXT = `PayPal: paypal.com, paypal.es
Amazon: amazon.com, amazon.es, amazon.de, amazon.fr, amazon.it, amazon.co.uk
Google: google.com, youtube.com
Microsoft: microsoft.com, office.com, microsoftonline.com
Apple: apple.com
Facebook: facebook.com, facebookmail.com, meta.com
Instagram: instagram.com, facebookmail.com
WhatsApp: whatsapp.com
LinkedIn: linkedin.com
Netflix: netflix.com
Spotify: spotify.com
DHL: dhl.com, dhl.es
Correos: correos.es
SEUR: seur.com
Santander: santander.com, santander.es, bancosantander.es
BBVA: bbva.com, bbva.es
CaixaBank: caixabank.com, caixabank.es
Sabadell: bancsabadell.com, sabadell.com
ING: ing.es, ing.com
Bankinter: bankinter.com
Unicaja: unicaja.es, unicajabanco.es
Agencia Tributaria: agenciatributaria.gob.es, aeat.es
Hacienda: agenciatributaria.gob.es, aeat.es
Seguridad Social: seg-social.es
Iberdrola: iberdrola.es, iberdrola.com
Endesa: endesa.com, endesa.es
Movistar: movistar.es, telefonica.com
Vodafone: vodafone.es, vodafone.com
Orange: orange.es, orange.com`;

  function normalizeDomain(input) {
    const value = String(input || '').trim().toLowerCase().replace(/\.+$/, '');
    if (!value || /[\s/@:?#]/.test(value)) return '';
    try {
      return new URL(`http://${value}`).hostname;
    } catch {
      return '';
    }
  }

  // RFC 3492: los dominios llegan en punycode y hay que ver sus letras reales
  // para detectar homoglifos como una "а" cirílica en paypal.
  function decodePunycodeLabel(label) {
    if (!label.startsWith('xn--')) return label;
    const input = label.slice(4);
    const delimiter = input.lastIndexOf('-');
    const output = delimiter > 0 ? [...input.slice(0, delimiter)] : [];
    let index = delimiter > 0 ? delimiter + 1 : 0;
    let n = 128;
    let i = 0;
    let bias = 72;
    while (index < input.length) {
      const start = i;
      let weight = 1;
      for (let k = 36; ; k += 36) {
        if (index >= input.length) return label;
        const code = input.charCodeAt(index);
        index += 1;
        const digit = code >= 97 && code <= 122 ? code - 97 : code >= 48 && code <= 57 ? code - 22 : 36;
        if (digit >= 36) return label;
        i += digit * weight;
        const threshold = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
        if (digit < threshold) break;
        weight *= 36 - threshold;
      }
      const size = output.length + 1;
      let delta = start === 0 ? Math.floor((i - start) / 700) : Math.floor((i - start) / 2);
      delta += Math.floor(delta / size);
      let k = 0;
      while (delta > 455) {
        delta = Math.floor(delta / 35);
        k += 36;
      }
      bias = k + Math.floor((36 * delta) / (delta + 38));
      n += Math.floor(i / size);
      i %= size;
      if (n > 0x10ffff) return label;
      output.splice(i, 0, String.fromCodePoint(n));
      i += 1;
    }
    return output.join('');
  }

  function publicSuffix(domain) {
    const labels = domain.split('.');
    const lastTwo = labels.slice(-2).join('.');
    return labels.length > 2 && MULTI_LABEL_SUFFIXES.has(lastTwo)
      ? lastTwo
      : labels[labels.length - 1];
  }

  function orgDomain(domain) {
    if (!domain) return '';
    const suffix = publicSuffix(domain);
    const before = domain.slice(0, -(suffix.length + 1));
    if (!before) return domain;
    return `${before.split('.').pop()}.${suffix}`;
  }

  function sameOrg(a, b) {
    return Boolean(a && b) && orgDomain(a) === orgDomain(b);
  }

  function isFreeMail(domain) {
    return FREE_MAIL.has(orgDomain(domain));
  }

  function skeleton(text) {
    return String(text)
      .toLowerCase()
      .normalize('NFKD')
      .replace(/[̀-ͯ]/g, '')
      .replace(/./gu, (char) => SINGLE_HOMOGLYPHS[char] ?? char)
      .replace(/rn/g, 'm')
      .replace(/vv/g, 'w');
  }

  function levenshtein(a, b) {
    let previous = Array.from({ length: b.length + 1 }, (_, index) => index);
    for (let i = 1; i <= a.length; i += 1) {
      const current = [i];
      for (let j = 1; j <= b.length; j += 1) {
        current[j] = Math.min(
          previous[j] + 1,
          current[j - 1] + 1,
          previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
        );
      }
      previous = current;
    }
    return previous[b.length];
  }

  function parseBrands(text) {
    const brands = [];
    for (const line of String(text || '').split('\n')) {
      const separator = line.indexOf(':');
      if (separator < 1) continue;
      const name = line.slice(0, separator).trim();
      const domains = line
        .slice(separator + 1)
        .split(',')
        .map(normalizeDomain)
        .filter(Boolean);
      if (!name || !domains.length) continue;
      const primaryOrg = orgDomain(domains[0]);
      const primaryLabel = SHARED_PLATFORMS.has(primaryOrg) ? '' : primaryOrg.split('.')[0];
      const squashedName = name.toLowerCase().replace(/[^\p{L}\p{N}]/gu, '');
      brands.push({
        name,
        domains,
        labels: [...new Set([primaryLabel, squashedName])].filter(Boolean),
      });
    }
    return brands;
  }

  // Dominio que se guardaría al confiar en un remitente; vacío si no es seguro
  // confiar en él porque cualquiera puede enviar desde ahí.
  function trustableDomain(domain) {
    if (!domain || isFreeMail(domain)) return '';
    const org = orgDomain(domain);
    if (!SHARED_PLATFORMS.has(org)) return org;
    return domain === org ? '' : domain;
  }

  function cleanBrandName(name) {
    return String(name || '').replace(/[:\r\n]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 60);
  }

  // Devuelve la lista con el dominio añadido a la empresa, o con una línea nueva
  // si la empresa no existe. Las demás líneas no se tocan.
  function addBrandDomain(text, name, domain) {
    const cleanName = cleanBrandName(name);
    const cleanDomain = normalizeDomain(domain);
    if (cleanName.replace(/[^\p{L}\p{N}]/gu, '').length < 2) throw new Error('Escribe el nombre de la empresa.');
    if (!cleanDomain) throw new Error('El dominio no es válido.');

    const lines = String(text || '').split('\n');
    const index = lines.findIndex((line) => {
      const separator = line.indexOf(':');
      return separator > 0 && line.slice(0, separator).trim().toLowerCase() === cleanName.toLowerCase();
    });
    if (index !== -1) {
      const separator = lines[index].indexOf(':');
      const current = lines[index].slice(separator + 1).split(',').map(normalizeDomain);
      if (!current.includes(cleanDomain)) lines[index] = `${lines[index].trimEnd()}, ${cleanDomain}`;
      return lines.join('\n');
    }
    return `${String(text || '').trimEnd()}\n${cleanName}: ${cleanDomain}`.trimStart();
  }

  function isOfficial(domain, brand) {
    return brand.domains.some((d) => domain === d || domain.endsWith(`.${d}`));
  }

  function officialBrand(domain, brands) {
    return brands.find((brand) => isOfficial(domain, brand)) || null;
  }

  // Busca dominios que se hacen pasar por una marca sin pertenecerle.
  function findLookalike(domain, brands) {
    if (officialBrand(domain, brands)) return null;
    const suffix = publicSuffix(domain);
    const host = domain.slice(0, -(suffix.length + 1));
    const tokens = host
      .split('.')
      .map(decodePunycodeLabel)
      .flatMap((label) => label.split('-'))
      .filter(Boolean)
      .map(skeleton);
    const orgLabel = decodePunycodeLabel(orgDomain(domain).split('.')[0]);
    let partial = null;

    for (const brand of brands) {
      for (const label of brand.labels) {
        const target = skeleton(label);
        if (tokens.includes(target)) {
          const literal = host.split(/[.-]/).includes(label);
          const reason = literal ? `usa «${label}» dentro de un dominio ajeno` : `imita visualmente a «${label}»`;
          return { brand, level: 'danger', reason };
        }
        if (label.length >= 5 && levenshtein(skeleton(orgLabel), target) <= 1) {
          return { brand, level: 'danger', reason: `se escribe casi igual que «${label}»` };
        }
        if (!partial && label.length >= 5 && orgLabel.includes(label)) {
          partial = { brand, level: 'warn', reason: `contiene «${label}»` };
        }
      }
    }
    return partial;
  }

  // Marcas citadas como palabra completa, para no confundir "Marketing" con ING.
  function mentionedBrands(text, brands) {
    const haystack = ` ${skeleton(text).replace(/[^\p{L}\p{N}]+/gu, ' ')} `;
    return brands.filter((brand) => {
      const name = skeleton(brand.name).replace(/[^\p{L}\p{N}]+/gu, ' ').trim();
      return (name && haystack.includes(` ${name} `))
        || brand.labels.some((label) => haystack.includes(` ${skeleton(label)} `));
    });
  }

  Object.assign(EV, {
    DEFAULT_BRANDS_TEXT,
    normalizeDomain,
    orgDomain,
    sameOrg,
    isFreeMail,
    skeleton,
    levenshtein,
    parseBrands,
    trustableDomain,
    addBrandDomain,
    isOfficial,
    officialBrand,
    findLookalike,
    mentionedBrands,
  });
})(globalThis);
