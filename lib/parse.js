(function (root) {
  const EV = (root.EmailVerifier = root.EmailVerifier || {});

  const TRUSTED_AUTHSERV = 'mx.google.com';

  function parseHeaders(raw) {
    const text = String(raw || '').replace(/\r\n/g, '\n').replace(/^\s+/, '');
    const end = text.indexOf('\n\n');
    const section = end === -1 ? text : text.slice(0, end);
    const headers = [];
    for (const line of section.split('\n')) {
      if (/^[ \t]/.test(line) && headers.length) {
        headers[headers.length - 1].value += ` ${line.trim()}`;
        continue;
      }
      const separator = line.indexOf(':');
      if (separator < 1) continue;
      headers.push({
        name: line.slice(0, separator).trim().toLowerCase(),
        value: line.slice(separator + 1).trim(),
      });
    }
    return headers;
  }

  function decodeWord(charset, encoding, text) {
    let bytes;
    if (encoding.toUpperCase() === 'B') {
      bytes = Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
    } else {
      const binary = text
        .replace(/_/g, ' ')
        .replace(/=([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
      bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    }
    return new TextDecoder(charset).decode(bytes);
  }

  function decodeMimeWords(value) {
    return String(value || '')
      .replace(/(\?=)\s+(=\?)/g, '$1$2')
      .replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi, (match, charset, encoding, text) => {
        try {
          return decodeWord(charset, encoding, text);
        } catch {
          return match;
        }
      });
  }

  // La dirección se separa antes de decodificar: un nombre codificado podría
  // esconder un "<otro@dominio>" que no es el remitente real.
  function parseAddress(value) {
    const text = String(value || '').trim();
    const angle = text.match(/<([^<>]*)>\s*(?:\([^)]*\))?\s*$/);
    const address = (angle ? angle[1] : text.split(/\s+/).find((part) => part.includes('@')) || '')
      .trim()
      .toLowerCase();
    const display = angle
      ? decodeMimeWords(text.slice(0, angle.index)).trim().replace(/^"(.*)"$/, '$1').replace(/\\(.)/g, '$1')
      : '';
    const at = address.lastIndexOf('@');
    return {
      display,
      address,
      domain: at === -1 ? '' : EV.normalizeDomain(address.slice(at + 1)),
    };
  }

  // Separa por ";" ignorando comentarios entre paréntesis y comillas.
  function splitSegments(value) {
    const segments = [];
    let current = '';
    let depth = 0;
    let quoted = false;
    for (const char of value) {
      if (char === '"' && depth === 0) quoted = !quoted;
      if (!quoted && char === '(') depth += 1;
      if (!quoted && char === ')' && depth > 0) depth -= 1;
      if (char === ';' && depth === 0 && !quoted) {
        segments.push(current);
        current = '';
      } else {
        current += char;
      }
    }
    segments.push(current);
    return segments;
  }

  function parseAuthResults(value) {
    const [first, ...rest] = splitSegments(value);
    const results = [];
    for (const segment of rest) {
      const comments = [...segment.matchAll(/\(([^)]*)\)/g)].map((m) => m[1]);
      const bare = segment.replace(/\([^)]*\)/g, ' ');
      const head = bare.match(/^\s*([a-z0-9-]+)\s*=\s*([a-z]+)/i);
      if (!head) continue;
      const props = {};
      for (const m of bare.matchAll(/([a-z]+\.[a-z0-9-]+)=("[^"]*"|\S+)/gi)) {
        props[m[1].toLowerCase()] = m[2].replace(/^"|"$/g, '').toLowerCase();
      }
      results.push({
        method: head[1].toLowerCase(),
        result: head[2].toLowerCase(),
        comment: comments.join(' '),
        props,
      });
    }
    return { authserv: first.trim().split(/\s+/)[0].toLowerCase(), results };
  }

  function isInboundReceived(value) {
    return /\bby\s+mx\.google\.com\b/i.test(value);
  }

  // Solo vale la cabecera que escribió Gmail al recibir. Cualquier
  // Authentication-Results más abajo la pudo redactar quien envía el correo.
  function findTrustedAuthResults(headers) {
    const received = headers
      .map((header, index) => ({ ...header, index }))
      .filter((header) => header.name === 'received');
    const inbound = received.find((header) => isInboundReceived(header.value)) || received[0];
    const limit = inbound
      ? received.find((header) => header.index > inbound.index)?.index ?? Infinity
      : Infinity;
    const index = headers.findIndex((header) => header.name === 'authentication-results');
    if (index === -1 || index >= limit) return null;
    const parsed = parseAuthResults(headers[index].value);
    return parsed.authserv === TRUSTED_AUTHSERV ? parsed : null;
  }

  function parseTagList(value) {
    const tags = {};
    for (const part of String(value || '').split(';')) {
      const separator = part.indexOf('=');
      if (separator === -1) continue;
      const key = part.slice(0, separator).trim().toLowerCase();
      if (key) tags[key] = part.slice(separator + 1).replace(/\s+/g, '');
    }
    return tags;
  }

  function parseInboundHop(headers) {
    const header = headers.find((h) => h.name === 'received' && isInboundReceived(h.value));
    if (!header) return null;
    const value = header.value;
    const ip = value.match(/\[([0-9a-f:.]+)\]/i);
    const host = value.match(/^from\s+(\S+)/i);
    const tls = value.match(/version=(TLS[\w.]*)\s+cipher=([^\s)]+)/i);
    return {
      host: host ? host[1].toLowerCase() : '',
      ip: ip ? ip[1] : '',
      tlsVersion: tls ? tls[1].replace(/^TLS(?:v)?/i, 'TLS ').replace('_', '.') : '',
      tlsCipher: tls ? tls[2] : '',
      esmtps: /\bwith\s+ESMTPS\b/i.test(value),
    };
  }

  function parseMessage(raw) {
    const headers = parseHeaders(raw);
    const get = (name) => headers.find((h) => h.name === name)?.value || '';
    const all = (name) => headers.filter((h) => h.name === name).map((h) => h.value);
    return {
      from: parseAddress(get('from')),
      fromCount: all('from').length,
      replyTo: get('reply-to') ? parseAddress(get('reply-to')) : null,
      returnPath: get('return-path') ? parseAddress(get('return-path')) : null,
      subject: decodeMimeWords(get('subject')),
      messageId: get('message-id'),
      auth: findTrustedAuthResults(headers),
      dkimSignatures: all('dkim-signature').map(parseTagList),
      hop: parseInboundHop(headers),
    };
  }

  Object.assign(EV, {
    parseHeaders,
    decodeMimeWords,
    parseAddress,
    parseAuthResults,
    findTrustedAuthResults,
    parseTagList,
    parseInboundHop,
    parseMessage,
  });
})(globalThis);
