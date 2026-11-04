// Correos de ejemplo con el orden de cabeceras real de Gmail.
function buildRaw({
  from,
  mailfrom,
  ip = '198.51.100.7',
  host = 'mail.sender.example',
  tls = 'version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128',
  auth,
  extra = [],
  subject = 'Aviso de tu cuenta',
}) {
  const returnPath = mailfrom ? [`Return-Path: <${mailfrom}>`] : [];
  const authHeader = auth ? [`Authentication-Results: mx.google.com;\r\n       ${auth}`] : [];
  return [
    'Delivered-To: yo@gmail.com',
    'Received: by 2002:a05:6a10:1234:b0:1 with SMTP id abc; Tue, 3 Nov 2026 10:00:01 -0800 (PST)',
    ...returnPath,
    `Received: from ${host} (${host}. [${ip}])`,
    `        by mx.google.com with ESMTPS id x12 for <yo@gmail.com>`,
    `        (${tls});`,
    '        Tue, 03 Nov 2026 10:00:00 -0800 (PST)',
    `Received-SPF: pass (google.com: domain of ${mailfrom || 'x'} designates ${ip} as permitted sender)`,
    ...authHeader,
    ...extra,
    `From: ${from}`,
    `Subject: ${subject}`,
    'Message-ID: <abc@sender.example>',
    '',
    'Cuerpo del mensaje con una línea: que parece cabecera',
  ].join('\r\n');
}

const passing = (domain, policy = 'REJECT') =>
  `dkim=pass header.i=@${domain} header.s=s1 header.b=abc123;\r\n       ` +
  `spf=pass (google.com: domain of bounce@${domain} designates 198.51.100.7 as permitted sender) smtp.mailfrom=bounce@${domain};\r\n       ` +
  `dmarc=pass (p=${policy} sp=${policy} dis=NONE) header.from=${domain}`;

const dnsFor = (overrides = {}) => ({
  spf: { records: ['v=spf1 include:_spf.example -all'], error: false },
  mx: { records: ['10 mx.example.'], error: false },
  dmarc: { record: 'v=DMARC1; p=reject; rua=mailto:d@example.com', foundAt: '_dmarc.paypal.com', error: false },
  mtaSts: { record: 'v=STSv1; id=1', foundAt: '_mta-sts.paypal.com', error: false },
  tlsRpt: { record: '', foundAt: '', error: false },
  bimi: { record: '', foundAt: '', error: false },
  dkim: [{ domain: 'paypal.com', selector: 's1', record: `v=DKIM1; k=rsa; p=${'A'.repeat(392)}`, error: false }],
  dnssec: false,
  registered: '2005-01-01T00:00:00Z',
  ...overrides,
});

module.exports = { buildRaw, passing, dnsFor };
