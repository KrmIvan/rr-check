const test = require('node:test');
const assert = require('node:assert/strict');

require('../lib/domains.js');
require('../lib/parse.js');
require('../lib/evaluate.js');
require('../lib/dns.js');
const { buildRaw, passing, dnsFor } = require('./fixtures.js');

const EV = globalThis.EmailVerifier;
const brands = EV.parseBrands(EV.DEFAULT_BRANDS_TEXT);
const NOW = Date.parse('2026-11-04T00:00:00Z');

function report(rawOptions, { dns = dnsFor(), links = [] } = {}) {
  const msg = EV.parseMessage(buildRaw(rawOptions));
  return EV.evaluate({ msg, dns, brands, links, now: NOW });
}

const row = (result, name) => result.protocols.find((p) => p.name === name);

test('correo legítimo de una empresa de la lista queda verificado', () => {
  const result = report({
    from: 'PayPal <service@paypal.com>',
    mailfrom: 'bounce@paypal.com',
    auth: passing('paypal.com'),
  });
  assert.equal(result.verdict.level, 'ok');
  assert.equal(result.verdict.title, 'Verificado: PayPal');
  assert.equal(row(result, 'SPF').status, 'ok');
  assert.equal(row(result, 'DKIM').status, 'ok');
  assert.equal(row(result, 'DMARC').status, 'ok');
  assert.equal(row(result, 'TLS').actual, 'TLS 1.3');
  assert.match(row(result, 'DKIM').expected, /2048|20\d\d/);
});

test('subdominio de la empresa también cuenta como oficial', () => {
  const result = report({
    from: 'PayPal <service@mail.paypal.com>',
    mailfrom: 'bounce@mail.paypal.com',
    auth: passing('mail.paypal.com'),
  });
  assert.equal(result.verdict.level, 'ok');
});

test('dominio parecido que supera todos los protocolos sigue siendo peligro', () => {
  const result = report({
    from: 'Soporte <service@paypa1.com>',
    mailfrom: 'bounce@paypa1.com',
    auth: passing('paypa1.com'),
  });
  assert.equal(row(result, 'DMARC').actual, 'pass');
  assert.equal(result.verdict.level, 'danger');
  assert.match(result.verdict.summary, /PayPal/);
});

test('detecta imitaciones con guion, subdominio y homoglifos', () => {
  const cyrillicA = 'а';
  const cases = ['paypal-secure.com', 'paypal.com.evil.net', 'rnicrosoft.com', `p${cyrillicA}ypal.com`];
  for (const domain of cases) {
    const normalized = EV.normalizeDomain(domain);
    assert.equal(EV.findLookalike(normalized, brands)?.brand.name, domain.startsWith('rn') ? 'Microsoft' : 'PayPal', domain);
    assert.equal(EV.findLookalike(normalized, brands)?.level, 'danger', domain);
  }
  assert.match(EV.normalizeDomain(`p${cyrillicA}ypal.com`), /^xn--/);
});

test('un dominio dentro de otro no pasa por oficial', () => {
  assert.equal(EV.officialBrand('notpaypal.com', brands), null);
  assert.equal(EV.officialBrand('paypal.com.evil.net', brands), null);
  assert.equal(EV.officialBrand('www.paypal.com', brands)?.name, 'PayPal');
});

test('nombre visible de una marca desde un dominio ajeno es peligro', () => {
  const result = report({
    from: '"Banco Santander" <avisos@ofertas-web.example>',
    mailfrom: 'x@ofertas-web.example',
    auth: passing('ofertas-web.example'),
  });
  assert.equal(result.verdict.level, 'danger');
  assert.match(result.verdict.summary, /Santander/);
});

test('nombre visible codificado en MIME también se comprueba', () => {
  const encoded = `=?UTF-8?B?${Buffer.from('Agencia Tributaria').toString('base64')}?=`;
  const result = report({
    from: `${encoded} <a@web.example>`,
    mailfrom: 'a@web.example',
    auth: passing('web.example'),
  });
  assert.equal(result.verdict.level, 'danger');
});

test('una dirección dentro del nombre visible es peligro', () => {
  const result = report({
    from: '"service@paypal.com" <a@web.example>',
    mailfrom: 'a@web.example',
    auth: passing('web.example'),
  });
  assert.equal(result.verdict.level, 'danger');
  assert.equal(EV.parseAddress('"service@paypal.com" <a@web.example>').domain, 'web.example');
});

test('Authentication-Results falsificado por el remitente no se tiene en cuenta', () => {
  const forged = 'Authentication-Results: mx.google.com; dkim=pass header.i=@paypal.com; dmarc=pass header.from=paypal.com';
  const raw = buildRaw({
    from: 'PayPal <service@paypal.com>',
    mailfrom: 'x@evil.example',
    auth: 'spf=fail smtp.mailfrom=x@evil.example; dkim=none; dmarc=fail (p=REJECT) header.from=paypal.com',
    extra: ['Received: from evil (evil [203.0.113.1]) by evil.example with SMTP', forged],
  });
  const msg = EV.parseMessage(raw);
  assert.equal(msg.auth.results.find((r) => r.method === 'dmarc').result, 'fail');
  assert.equal(EV.evaluate({ msg, dns: dnsFor(), brands, now: NOW }).verdict.level, 'danger');
});

test('sin cabecera real de Gmail, la falsificada no vale', () => {
  const forged = 'Authentication-Results: mx.google.com; dmarc=pass header.from=paypal.com';
  const raw = buildRaw({
    from: 'PayPal <service@paypal.com>',
    extra: ['Received: from evil (evil [203.0.113.1]) by evil.example with SMTP', forged],
  });
  assert.equal(EV.parseMessage(raw).auth, null);
});

test('otro authserv-id no se considera fiable', () => {
  const headers = EV.parseHeaders('Authentication-Results: evil.example; dmarc=pass header.from=paypal.com\r\nFrom: a@b.c\r\n\r\n');
  assert.equal(EV.findTrustedAuthResults(headers), null);
});

test('DMARC fallido en dominio oficial es peligro', () => {
  const result = report({
    from: 'PayPal <service@paypal.com>',
    mailfrom: 'x@evil.example',
    auth: 'dkim=none; spf=pass smtp.mailfrom=x@evil.example; dmarc=fail (p=REJECT) header.from=paypal.com',
  });
  assert.equal(result.verdict.level, 'danger');
  assert.equal(row(result, 'DMARC').status, 'bad');
  assert.equal(row(result, 'SPF').status, 'warn');
});

test('dominio auténtico desconocido no se confirma como empresa', () => {
  const result = report(
    { from: 'Tienda <hola@tienda.example>', mailfrom: 'x@tienda.example', auth: passing('tienda.example') },
    { dns: dnsFor({ dkim: [] }) },
  );
  assert.equal(result.verdict.level, 'neutral');
  assert.match(result.verdict.summary, /no está en tu lista/);
});

test('sin DMARC publicado se avisa en la comparativa', () => {
  const result = report(
    { from: 'T <a@tienda.example>', mailfrom: 'a@tienda.example', auth: passing('tienda.example') },
    { dns: dnsFor({ dmarc: { record: '', foundAt: '', error: false } }) },
  );
  assert.equal(row(result, 'DMARC').expected, 'El dominio no publica DMARC');
  assert.equal(row(result, 'DMARC').status, 'warn');
});

test('p=none se marca como atención aunque DMARC pase', () => {
  const result = report(
    { from: 'T <a@tienda.example>', mailfrom: 'a@tienda.example', auth: passing('tienda.example', 'NONE') },
    { dns: dnsFor({ dmarc: { record: 'v=DMARC1; p=none', foundAt: '_dmarc.tienda.example', error: false } }) },
  );
  assert.equal(row(result, 'DMARC').status, 'warn');
});

test('fallo de DNS no se confunde con registro ausente', () => {
  const failed = { record: '', foundAt: '', error: true };
  const result = report(
    { from: 'T <a@tienda.example>', mailfrom: 'a@tienda.example', auth: passing('tienda.example') },
    { dns: dnsFor({ dmarc: failed, spf: { records: [], error: true }, mtaSts: failed }) },
  );
  assert.equal(row(result, 'DMARC').expected, 'Consulta DNS no disponible');
  assert.equal(row(result, 'SPF').expected, 'Consulta DNS no disponible');
  assert.equal(row(result, 'MTA-STS').actual, 'Consulta DNS no disponible');
});

test('Reply-To a otro dominio baja el veredicto de un correo oficial', () => {
  const result = report({
    from: 'PayPal <service@paypal.com>',
    mailfrom: 'bounce@paypal.com',
    auth: passing('paypal.com'),
    extra: ['Reply-To: cobros@evil.example'],
  });
  assert.equal(result.verdict.level, 'warn');
  assert.match(result.verdict.summary, /cobros@evil.example/);
});

test('dominio registrado hace pocos días es peligro', () => {
  const result = report(
    { from: 'T <a@tienda.example>', mailfrom: 'a@tienda.example', auth: passing('tienda.example') },
    { dns: dnsFor({ registered: '2026-10-25T00:00:00Z' }) },
  );
  assert.equal(result.verdict.level, 'danger');
  assert.match(result.verdict.summary, /10 días/);
});

test('enlace que muestra un dominio y lleva a otro es peligro', () => {
  const result = report(
    { from: 'PayPal <service@paypal.com>', mailfrom: 'b@paypal.com', auth: passing('paypal.com') },
    { links: [{ href: 'https://evil.example/login', text: 'https://www.paypal.com/login' }] },
  );
  assert.equal(result.verdict.level, 'danger');
  assert.match(result.verdict.summary, /evil\.example/);
});

test('enlace coherente con su texto no genera aviso', () => {
  const result = report(
    { from: 'PayPal <service@paypal.com>', mailfrom: 'b@paypal.com', auth: passing('paypal.com') },
    { links: [{ href: 'https://www.paypal.com/login', text: 'paypal.com/login' }, { href: 'https://www.paypal.com', text: 'Entra' }] },
  );
  assert.equal(result.verdict.level, 'ok');
});

test('sin autenticación de Gmail no se da por verificado', () => {
  const result = report({ from: 'PayPal <service@paypal.com>' });
  assert.equal(result.verdict.level, 'unknown');
});

test('Marketing no se confunde con ING', () => {
  assert.equal(EV.mentionedBrands('Equipo de Marketing', brands).length, 0);
  assert.equal(EV.mentionedBrands('ING Direct', brands)[0].name, 'ING');
});

test('dominio raíz con sufijos de varias partes', () => {
  assert.equal(EV.orgDomain('mail.amazon.co.uk'), 'amazon.co.uk');
  assert.equal(EV.orgDomain('sede.agenciatributaria.gob.es'), 'agenciatributaria.gob.es');
  assert.equal(EV.orgDomain('a.b.example.com'), 'example.com');
});

test('lookupDomain distingue registro ausente de resolutor caído', async () => {
  const seen = [];
  const fetchOk = async (url) => {
    seen.push(url);
    if (url.includes('rdap.org')) return { ok: false };
    const name = new URL(url).searchParams.get('name');
    const answer = name === 'paypal.com'
      ? [{ type: 16, data: '"v=spf1 " "-all"' }, { type: 16, data: '"google-site-verification=x"' }]
      : [];
    return { ok: true, json: async () => ({ Status: answer.length ? 0 : 3, Answer: answer, AD: true }) };
  };
  const found = await EV.lookupDomain('paypal.com', [], fetchOk);
  assert.deepEqual(found.spf.records, ['v=spf1 -all']);
  assert.equal(found.dmarc.record, '');
  assert.equal(found.dmarc.error, false);
  assert.equal(found.dnssec, true);
  assert.ok(seen.every((url) => !url.includes('service@')));

  const down = await EV.lookupDomain('paypal.com', [], async () => { throw new Error('offline'); });
  assert.equal(down.dmarc.error, true);
  assert.equal(down.spf.error, true);
  assert.equal(down.registered, null);
});

test('cada veredicto explica qué significa y qué hacer', () => {
  const cases = [
    { from: 'PayPal <a@paypal.com>', mailfrom: 'a@paypal.com', auth: passing('paypal.com') },
    { from: 'Soporte <a@paypa1.com>', mailfrom: 'a@paypa1.com', auth: passing('paypa1.com') },
    { from: 'T <a@tienda.example>', mailfrom: 'a@tienda.example', auth: passing('tienda.example') },
    { from: 'T <a@tienda.example>' },
    { from: 'T <a@tienda.example>', auth: 'spf=fail smtp.mailfrom=a@tienda.example; dkim=none; dmarc=fail header.from=tienda.example' },
    { from: 'sin direccion' },
  ];
  const levels = new Set();
  for (const options of cases) {
    const { verdict } = report(options);
    levels.add(verdict.level);
    assert.ok(verdict.meaning, verdict.title);
    assert.ok(verdict.actions.length, verdict.title);
  }
  assert.deepEqual([...levels].sort(), ['danger', 'neutral', 'ok', 'unknown']);
});

test('se ofrece añadir un dominio auténtico desconocido, con su dominio raíz', () => {
  const result = report({
    from: 'Riot Games <noreply@mail.riotgames.com>',
    mailfrom: 'b@mail.riotgames.com',
    auth: passing('mail.riotgames.com'),
  });
  assert.equal(result.verdict.level, 'neutral');
  assert.deepEqual(result.addable, { domain: 'riotgames.com', suggestedName: 'Riot Games' });
});

test('no se ofrece añadir nada que regalaría «Verificado» a una suplantación', () => {
  const cases = {
    oficial: { from: 'PayPal <a@paypal.com>', mailfrom: 'a@paypal.com', auth: passing('paypal.com') },
    parecido: { from: 'Soporte <a@paypa1.com>', mailfrom: 'a@paypa1.com', auth: passing('paypa1.com') },
    'contiene marca': { from: 'Soporte <a@mipaypalito.example>', mailfrom: 'a@mipaypalito.example', auth: passing('mipaypalito.example') },
    'nombre de marca': { from: 'Santander <a@tienda.example>', mailfrom: 'a@tienda.example', auth: passing('tienda.example') },
    gratuito: { from: 'Riot Games <riot@gmail.com>', mailfrom: 'riot@gmail.com', auth: passing('gmail.com') },
    'sin autenticar': { from: 'T <a@tienda.example>', auth: 'spf=fail smtp.mailfrom=a@tienda.example; dkim=none; dmarc=fail header.from=tienda.example' },
    'sin datos': { from: 'T <a@tienda.example>' },
    'raíz de plataforma': { from: 'T <a@zendesk.com>', mailfrom: 'a@zendesk.com', auth: passing('zendesk.com') },
  };
  for (const [label, options] of Object.entries(cases)) {
    assert.equal(report(options).addable, null, label);
  }
});

test('en plataformas compartidas se guarda solo el subdominio del cliente', () => {
  assert.equal(EV.trustableDomain('riotgames.zendesk.com'), 'riotgames.zendesk.com');
  const list = EV.parseBrands(EV.addBrandDomain('', 'Riot Games', 'riotgames.zendesk.com'));
  assert.equal(EV.officialBrand('riotgames.zendesk.com', list)?.name, 'Riot Games');
  assert.equal(EV.officialBrand('estafa.zendesk.com', list), null);
  assert.equal(EV.findLookalike('otra.zendesk.com', list), null);
});

test('añadir a la lista crea la línea o amplía la empresa sin tocar el resto', () => {
  const base = 'PayPal: paypal.com\nGoogle: google.com';
  assert.equal(EV.addBrandDomain(base, 'Riot Games', 'riotgames.com'), `${base}\nRiot Games: riotgames.com`);
  assert.equal(EV.addBrandDomain(base, 'paypal', 'paypal.fr'), 'PayPal: paypal.com, paypal.fr\nGoogle: google.com');
  assert.equal(EV.addBrandDomain(base, 'PayPal', 'PAYPAL.com'), base);
  assert.equal(EV.addBrandDomain('', 'Riot', 'riotgames.com'), 'Riot: riotgames.com');
});

test('el nombre no puede romper el formato de la lista', () => {
  const text = EV.addBrandDomain('PayPal: paypal.com', 'Evil: paypal.com\nOtra', 'evil.example');
  assert.equal(text, 'PayPal: paypal.com\nEvil paypal.com Otra: evil.example');
  assert.equal(EV.parseBrands(text).length, 2);
  assert.equal(EV.officialBrand('evil.example', EV.parseBrands(text)).name, 'Evil paypal.com Otra');
  assert.throws(() => EV.addBrandDomain('', '  ', 'a.example'), /nombre/);
  assert.throws(() => EV.addBrandDomain('', '***', 'a.example'), /nombre/);
  assert.throws(() => EV.addBrandDomain('', 'Riot', 'no valido'), /dominio/);
});

test('tras añadir el dominio, el mismo correo queda verificado', () => {
  const msg = EV.parseMessage(buildRaw({
    from: 'Riot Games <noreply@mail.riotgames.com>',
    mailfrom: 'b@mail.riotgames.com',
    auth: passing('mail.riotgames.com'),
  }));
  const before = EV.evaluate({ msg, dns: dnsFor(), brands, now: NOW });
  const text = EV.addBrandDomain(EV.DEFAULT_BRANDS_TEXT, before.addable.suggestedName, before.addable.domain);
  const after = EV.evaluate({ msg, dns: dnsFor(), brands: EV.parseBrands(text), now: NOW });
  assert.equal(after.verdict.title, 'Verificado: Riot Games');
  assert.equal(after.addable, null);
});

test('lookupDomain rechaza nombres no válidos', async () => {
  await assert.rejects(EV.lookupDomain('evil.com/?x=1', [], async () => ({})));
  await assert.rejects(EV.lookupDomain('', [], async () => ({})));
});
