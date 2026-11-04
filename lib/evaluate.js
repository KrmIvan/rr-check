(function (root) {
  const EV = (root.EmailVerifier = root.EmailVerifier || {});

  const DAY_MS = 86400000;
  const POLICY_LABELS = {
    reject: 'rechazar (p=reject)',
    quarantine: 'cuarentena (p=quarantine)',
    none: 'solo observar (p=none)',
  };
  const UNTRUSTED_ACTION = 'No uses sus enlaces ni adjuntos; entra en la web oficial escribiendo tú la dirección.';
  const SENSITIVE_ACTION = `Si pide dinero, contraseñas o datos, o te mete prisa: ${UNTRUSTED_ACTION.charAt(0).toLowerCase()}${UNTRUSTED_ACTION.slice(1)}`;

  function resultsFor(auth, method) {
    return auth ? auth.results.filter((r) => r.method === method) : [];
  }

  function domainFromIdentity(value) {
    const text = String(value || '');
    return EV.normalizeDomain(text.slice(text.lastIndexOf('@') + 1));
  }

  function spfRow(msg, dns, domain) {
    const record = dns?.spf.records[0] || '';
    let expected = 'Consulta DNS no disponible';
    if (dns && !dns.spf.error) {
      if (dns.spf.records.length > 1) expected = 'Registro inválido: hay más de un SPF';
      else if (!record) expected = 'El dominio no publica SPF';
      else if (/[+]all\b/.test(record) || !/[-~?]all\b|redirect=/.test(record)) expected = 'SPF publicado, pero permisivo';
      else if (/-all\b/.test(record)) expected = 'SPF estricto (-all)';
      else if (/~all\b/.test(record)) expected = 'SPF flexible (~all)';
      else expected = 'SPF publicado';
    }

    const spf = resultsFor(msg.auth, 'spf')[0];
    if (!spf) return { name: 'SPF', expected, actual: 'Sin resultado', status: 'warn', record };
    const checked = domainFromIdentity(spf.props['smtp.mailfrom']) || msg.returnPath?.domain || '';
    const aligned = spf.result === 'pass' && EV.sameOrg(checked, domain);
    let status = 'bad';
    if (aligned) status = 'ok';
    else if (spf.result === 'pass' || spf.result === 'none' || spf.result === 'neutral') status = 'warn';
    const alignment = spf.result === 'pass' ? (aligned ? ', alineado con From' : ', no alineado con From') : '';
    return {
      name: 'SPF',
      expected,
      actual: `${spf.result}${checked ? ` para ${checked}` : ''}${alignment}`,
      status,
      record,
    };
  }

  function dkimKeyNote(entry) {
    if (!entry || entry.error) return '';
    if (!entry.record) return 'clave no encontrada en DNS';
    const tags = EV.parseTagList(entry.record);
    if (!tags.p) return 'clave revocada';
    if ((tags.k || 'rsa').toLowerCase() !== 'rsa') return `clave ${tags.k}`;
    // Tamaño aproximado: la clave pública incluye unos 38 bytes de cabecera.
    const bytes = Math.floor((tags.p.length * 3) / 4);
    return `clave RSA de unos ${Math.max(0, bytes - 38) * 8} bits`;
  }

  function dkimRow(msg, dns, domain) {
    const results = resultsFor(msg.auth, 'dkim');
    const pass = results.filter((r) => r.result === 'pass');
    const signerOf = (r) => domainFromIdentity(r.props['header.d'] || r.props['header.i']);
    const aligned = pass.find((r) => EV.sameOrg(signerOf(r), domain));
    const shown = aligned || pass[0] || results[0];
    const selector = shown?.props['header.s'];
    const keyEntry = dns?.dkim.find((d) => d.selector === selector && d.domain === signerOf(shown || { props: {} }))
      || dns?.dkim[0];
    const note = dkimKeyNote(keyEntry);
    const expected = `Firma válida de ${EV.orgDomain(domain)}${note ? ` (${note})` : ''}`;

    if (!results.length) return { name: 'DKIM', expected, actual: 'Correo sin firma', status: 'warn', record: keyEntry?.record || '' };
    const weakAlgorithm = msg.dkimSignatures.some((s) => /sha1/i.test(s.a || ''));
    let status = 'bad';
    if (aligned) status = weakAlgorithm ? 'warn' : 'ok';
    else if (pass.length) status = 'warn';
    const signer = shown ? signerOf(shown) : '';
    const detail = shown?.result === 'pass' ? (aligned ? ', alineada con From' : ', de otro dominio') : '';
    return {
      name: 'DKIM',
      expected,
      actual: `${shown.result}${signer ? ` con ${signer}` : ''}${detail}${weakAlgorithm ? ', algoritmo SHA-1 débil' : ''}`,
      status,
      record: keyEntry?.record || '',
    };
  }

  function dmarcPolicy(dns, domain) {
    if (!dns?.dmarc.record) return null;
    const tags = EV.parseTagList(dns.dmarc.record);
    const inherited = dns.dmarc.foundAt !== `_dmarc.${domain}`;
    return ((inherited && tags.sp) || tags.p || 'none').toLowerCase();
  }

  function dmarcRow(msg, dns, domain) {
    const policy = dmarcPolicy(dns, domain);
    let expected = 'Consulta DNS no disponible';
    if (dns && !dns.dmarc.error) {
      expected = policy ? `Política: ${POLICY_LABELS[policy] || policy}` : 'El dominio no publica DMARC';
    }
    const dmarc = resultsFor(msg.auth, 'dmarc')[0];
    let status = 'warn';
    if (dmarc?.result === 'fail') status = 'bad';
    else if (dmarc?.result === 'pass' && (policy === 'reject' || policy === 'quarantine')) status = 'ok';
    return {
      name: 'DMARC',
      expected,
      actual: dmarc ? dmarc.result : 'Sin resultado',
      status,
      record: dns?.dmarc.record || '',
    };
  }

  function tlsRow(msg) {
    const hop = msg.hop;
    const expected = 'TLS 1.2 o superior hasta Gmail';
    if (!hop) return { name: 'TLS', expected, actual: 'Sin datos de entrega', status: 'info', record: '' };
    if (hop.tlsVersion) {
      const old = /TLS (1\.0|1\.1|1)$/.test(hop.tlsVersion);
      return { name: 'TLS', expected, actual: hop.tlsVersion, status: old ? 'warn' : 'ok', record: hop.tlsCipher };
    }
    return hop.esmtps
      ? { name: 'TLS', expected, actual: 'Cifrado, versión no indicada', status: 'info', record: '' }
      : { name: 'TLS', expected, actual: 'Entregado sin cifrar', status: 'warn', record: '' };
  }

  function presenceRow(name, expected, entry) {
    const failed = !entry || entry.error;
    return {
      name,
      expected,
      actual: failed ? 'Consulta DNS no disponible' : entry.record ? 'Publicado' : 'No publicado',
      status: entry?.record ? 'ok' : 'info',
      record: entry?.record || '',
    };
  }

  function buildProtocols(msg, dns, domain) {
    const arc = resultsFor(msg.auth, 'arc')[0];
    return [
      spfRow(msg, dns, domain),
      dkimRow(msg, dns, domain),
      dmarcRow(msg, dns, domain),
      {
        name: 'ARC',
        expected: 'Solo en correos reenviados',
        actual: arc ? arc.result : 'No aplicado',
        status: 'info',
        record: '',
      },
      tlsRow(msg),
      presenceRow('MTA-STS', 'Recomendado: protege el correo que recibe el dominio', dns?.mtaSts),
      presenceRow('TLS-RPT', 'Recomendado: informes de fallos TLS', dns?.tlsRpt),
      presenceRow('BIMI', 'Opcional: logotipo verificado', dns?.bimi),
      {
        name: 'DNSSEC',
        expected: 'Recomendado: firma las respuestas DNS',
        actual: dns ? (dns.dnssec ? 'Validado' : 'No validado') : 'Consulta DNS no disponible',
        status: dns?.dnssec ? 'ok' : 'info',
        record: '',
      },
    ];
  }

  function linkSignals(links, brands) {
    const signals = [];
    const seen = new Set();
    const add = (level, text) => {
      if (!seen.has(text)) {
        seen.add(text);
        signals.push({ level, text });
      }
    };
    for (const link of links) {
      let url;
      try {
        url = new URL(link.href);
      } catch {
        continue;
      }
      if (url.protocol !== 'http:' && url.protocol !== 'https:') continue;
      const host = url.hostname.toLowerCase();
      if (/^\d+\.\d+\.\d+\.\d+$|^\[/.test(host)) {
        add('warn', `Un enlace apunta a una dirección IP (${host}).`);
        continue;
      }
      if (host.split('.').some((label) => label.startsWith('xn--'))) {
        add('warn', `Un enlace usa caracteres internacionales que pueden imitar letras (${host}).`);
      }
      const shown = String(link.text || '').trim().match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/?#:]\S*)?$/i);
      if (shown && !EV.sameOrg(EV.normalizeDomain(shown[1]), host)) {
        add('danger', `Un enlace muestra ${shown[1].toLowerCase()} pero lleva a ${host}.`);
      }
      const lookalike = EV.findLookalike(host, brands);
      if (lookalike?.level === 'danger') {
        add('danger', `Un enlace lleva a ${host}, que imita a ${lookalike.brand.name}.`);
      }
    }
    return signals;
  }

  function identitySignals({ msg, dns, brands, links, now, domain, official }) {
    const signals = [];
    const { from } = msg;

    if (msg.fromCount > 1) {
      signals.push({ level: 'danger', text: 'El correo tiene más de un campo From.' });
    }

    if (official) {
      signals.push({ level: 'ok', text: `${domain} está en tu lista como dominio de ${official.name}.` });
    }

    const lookalike = EV.findLookalike(domain, brands);
    if (lookalike) {
      signals.push({
        level: lookalike.level,
        text: `${domain} ${lookalike.reason}, pero no es un dominio de ${lookalike.brand.name}.`,
      });
    }

    for (const brand of EV.mentionedBrands(from.display, brands)) {
      if (!EV.isOfficial(domain, brand)) {
        signals.push({
          level: 'danger',
          text: `El nombre visible dice «${from.display}», pero ${domain} no es un dominio de ${brand.name}.`,
        });
      }
    }

    if (!official) {
      for (const brand of EV.mentionedBrands(msg.subject, brands)) {
        signals.push({ level: 'info', text: `El asunto menciona a ${brand.name}, y el remitente no es esa empresa.` });
      }
    }

    const embedded = from.display.match(/[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/);
    if (embedded && !EV.sameOrg(EV.normalizeDomain(embedded[1]), domain)) {
      signals.push({
        level: 'danger',
        text: `El nombre visible contiene otra dirección (${embedded[0]}); el remitente real es ${from.address}.`,
      });
    }

    if (domain.split('.').some((label) => label.startsWith('xn--'))) {
      signals.push({ level: 'warn', text: `El dominio usa caracteres internacionales que pueden imitar letras (${domain}).` });
    }

    if (EV.isFreeMail(domain)) {
      signals.push({ level: 'info', text: `${domain} es correo gratuito: cualquiera puede crear una cuenta ahí.` });
    }

    if (msg.replyTo?.domain && !EV.sameOrg(msg.replyTo.domain, domain)) {
      signals.push({ level: 'warn', text: `Las respuestas irían a otro dominio: ${msg.replyTo.address}.` });
    }

    if (msg.returnPath?.domain && !EV.sameOrg(msg.returnPath.domain, domain)) {
      signals.push({ level: 'info', text: `El envío técnico sale de ${msg.returnPath.domain}. Es normal en plataformas de envío masivo.` });
    }

    if (dns?.registered && !official) {
      const ageDays = Math.floor((now - Date.parse(dns.registered)) / DAY_MS);
      if (ageDays >= 0 && ageDays < 30) {
        signals.push({ level: 'danger', text: `${EV.orgDomain(domain)} se registró hace ${ageDays} días.` });
      } else if (ageDays >= 30 && ageDays < 90) {
        signals.push({ level: 'warn', text: `${EV.orgDomain(domain)} se registró hace ${ageDays} días.` });
      }
    }

    return signals.concat(linkSignals(links, brands));
  }

  function buildDetails(msg, dns, domain, links) {
    const details = [
      ['Remitente', msg.from.address],
      ['Dominio raíz', EV.orgDomain(domain)],
    ];
    if (msg.returnPath?.address) details.push(['Return-Path', msg.returnPath.address]);
    if (msg.replyTo?.address) details.push(['Reply-To', msg.replyTo.address]);
    if (msg.hop?.host) details.push(['Servidor de origen', msg.hop.host]);
    if (msg.hop?.ip) details.push(['IP de origen', msg.hop.ip]);
    if (dns?.registered) details.push(['Dominio registrado', dns.registered.slice(0, 10)]);
    if (dns?.mx.records.length) details.push(['MX', dns.mx.records.slice(0, 3).join(', ')]);
    const hosts = new Set();
    for (const link of links) {
      try {
        const url = new URL(link.href);
        if (url.protocol === 'http:' || url.protocol === 'https:') hosts.add(EV.orgDomain(url.hostname.toLowerCase()));
      } catch {
        // Enlace no analizable.
      }
    }
    if (hosts.size) details.push(['Dominios enlazados', [...hosts].slice(0, 8).join(', ')]);
    return details;
  }

  function suggestedBrandName(display) {
    return display.includes('@') ? '' : display.trim();
  }

  function evaluate({ msg, dns = null, brands = [], links = [], now = Date.now() }) {
    const domain = msg.from.domain;
    if (!domain) {
      return {
        verdict: {
          level: 'unknown',
          title: 'Remitente no legible',
          summary: 'El campo From no contiene una dirección válida.',
          meaning: 'No se puede saber quién envía este correo.',
          actions: [UNTRUSTED_ACTION],
        },
        addable: null,
        protocols: [],
        signals: [],
        details: [],
      };
    }

    const official = EV.officialBrand(domain, brands);
    const protocols = buildProtocols(msg, dns, domain);
    const signals = identitySignals({ msg, dns, brands, links, now, domain, official });
    const details = buildDetails(msg, dns, domain, links);

    const signerOf = (r) => domainFromIdentity(r.props['header.d'] || r.props['header.i']);
    const dmarc = resultsFor(msg.auth, 'dmarc')[0]?.result;
    const dkimAligned = resultsFor(msg.auth, 'dkim').some((r) => r.result === 'pass' && EV.sameOrg(signerOf(r), domain));
    const spf = resultsFor(msg.auth, 'spf')[0];
    const spfAligned = spf?.result === 'pass'
      && EV.sameOrg(domainFromIdentity(spf.props['smtp.mailfrom']) || msg.returnPath?.domain, domain);
    const authenticated = dmarc !== 'fail' && (dmarc === 'pass' || dkimAligned || spfAligned);
    const dangers = signals.filter((s) => s.level === 'danger');
    const warnings = signals.filter((s) => s.level === 'warn');

    // Solo se ofrece guardar lo que no regalaría «Verificado» a una suplantación.
    const trustable = EV.trustableDomain(domain);
    const addable = authenticated && !dangers.length && !official && trustable && !EV.findLookalike(domain, brands)
      ? { domain: trustable, suggestedName: suggestedBrandName(msg.from.display) }
      : null;
    const addAction = addable
      ? `Si sabes que ${addable.domain} es de esa empresa, añádelo a tu lista y sus correos saldrán como verificados.`
      : null;

    let verdict;
    if (dangers.length) {
      verdict = {
        level: 'danger',
        title: 'Posible suplantación',
        summary: dangers[0].text,
        meaning: 'Hay señales de que alguien intenta hacerse pasar por otro. Aunque los protocolos salgan correctos, solo prueban que el correo viene de ese dominio, no que el dominio sea de quien dice ser.',
        actions: [
          UNTRUSTED_ACTION,
          'No respondas ni facilites datos. Si te preocupa el aviso, contacta con la empresa por sus canales oficiales.',
        ],
      };
    } else if (!msg.auth) {
      verdict = {
        level: 'unknown',
        title: 'Autenticación no disponible',
        summary: 'Gmail no ha dejado un resultado de autenticación en este correo.',
        meaning: 'No se puede comprobar si el correo viene del dominio que indica. No es una alerta, pero tampoco una garantía.',
        actions: [SENSITIVE_ACTION],
      };
    } else if (!authenticated) {
      verdict = {
        level: 'danger',
        title: 'Remitente sin autenticar',
        summary: `Nada prueba que este correo venga de ${domain}: no supera DMARC, SPF ni DKIM alineados.`,
        meaning: `Cualquiera puede escribir ${domain} como remitente, y este correo no demuestra que lo haya enviado ese dominio. Puede ser una suplantación o un dominio mal configurado.`,
        actions: [UNTRUSTED_ACTION, 'No respondas ni facilites datos hasta confirmarlo por otra vía.'],
      };
    } else if (warnings.length) {
      verdict = {
        level: 'warn',
        title: official ? `De ${official.name}, con avisos` : 'Autenticado, con avisos',
        summary: warnings[0].text,
        meaning: `El correo viene de verdad de ${domain}, pero hay algo que conviene revisar antes de fiarse. Mira las señales de abajo.`,
        actions: [SENSITIVE_ACTION, ...(addAction ? [addAction] : [])],
      };
    } else if (official) {
      verdict = {
        level: 'ok',
        title: `Verificado: ${official.name}`,
        summary: `Autenticado por ${domain}, un dominio de ${official.name} en tu lista.`,
        meaning: `El correo viene de verdad de ${domain}, y tu lista dice que ese dominio es de ${official.name}.`,
        actions: ['Puedes tratarlo con normalidad, con la prudencia habitual: una cuenta legítima también puede estar comprometida.'],
      };
    } else {
      verdict = {
        level: 'neutral',
        title: 'Dominio auténtico, empresa sin confirmar',
        summary: `El correo viene de ${domain}, pero ese dominio no está en tu lista de empresas.`,
        meaning: `No es una alerta ni una garantía. El correo viene de verdad de ${domain}, pero eso no dice quién hay detrás: un estafador también puede registrar un dominio y obtener este resultado.`,
        actions: [
          `Comprueba que ${domain} es el dominio oficial de la empresa. El nombre visible lo puede escribir cualquiera.`,
          SENSITIVE_ACTION,
          ...(addAction ? [addAction] : []),
        ],
      };
    }

    return { verdict, addable, protocols, signals, details };
  }

  Object.assign(EV, { evaluate });
})(globalThis);
