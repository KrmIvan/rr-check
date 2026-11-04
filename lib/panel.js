(function (root) {
  const EV = (root.EmailVerifier = root.EmailVerifier || {});

  const STYLES = `
    :host { all: initial; display: block; margin: 8px 0 12px; }
    * { box-sizing: border-box; }
    .card {
      --ink: #1f2328; --muted: #5b626b; --line: #dfe3e8; --surface: #ffffff; --soft: #f5f6f8;
      --tone: #5b626b; --tone-soft: #eef0f3;
      color-scheme: light;
      font: 13px/1.45 "Google Sans", Roboto, Arial, sans-serif;
      color: var(--ink);
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }
    .card[data-level="ok"] { --tone: #17693a; --tone-soft: #e6f4ea; }
    .card[data-level="neutral"] { --tone: #1a5fb4; --tone-soft: #e8f0fb; }
    .card[data-level="warn"] { --tone: #8a5a00; --tone-soft: #fdf3dc; }
    .card[data-level="danger"] { --tone: #b3261e; --tone-soft: #fce8e6; }
    .head { display: flex; align-items: center; gap: 10px; padding: 10px 12px; background: var(--tone-soft); }
    .mark {
      flex: none; width: 22px; height: 22px; border-radius: 50%;
      display: grid; place-items: center;
      background: var(--tone); color: #fff; font-size: 13px; font-weight: 700; line-height: 1;
    }
    .text { flex: 1; min-width: 0; }
    .title { font-weight: 600; color: var(--tone); overflow-wrap: anywhere; }
    .summary { color: var(--ink); overflow-wrap: anywhere; }
    button {
      flex: none; font: inherit; font-weight: 500; color: var(--ink);
      background: var(--surface); border: 1px solid var(--line); border-radius: 6px;
      padding: 4px 10px; cursor: pointer;
    }
    button:hover { background: var(--soft); }
    button:focus-visible { outline: 2px solid #1a5fb4; outline-offset: 1px; }
    .body { padding: 12px; display: grid; gap: 14px; }
    .body[hidden] { display: none; }
    h3 { margin: 0 0 6px; font-size: 12px; font-weight: 600; color: var(--muted); }
    .scroll { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; font-weight: 500; color: var(--muted); white-space: nowrap; }
    th, td { padding: 6px 12px 6px 0; border-bottom: 1px solid var(--line); vertical-align: top; }
    td { overflow-wrap: anywhere; }
    tr:last-child td { border-bottom: 0; }
    .name { font-weight: 600; white-space: nowrap; }
    .record {
      display: block; margin-top: 2px; font: 11px/1.4 ui-monospace, Menlo, Consolas, monospace;
      color: var(--muted);
    }
    .status { white-space: nowrap; font-weight: 500; }
    .status[data-status="ok"] { color: #17693a; }
    .status[data-status="warn"] { color: #8a5a00; }
    .status[data-status="bad"] { color: #b3261e; }
    .status[data-status="info"] { color: var(--muted); }
    ul { list-style: none; margin: 0; padding: 0; display: grid; gap: 4px; }
    li { display: grid; grid-template-columns: 72px 1fr; gap: 8px; overflow-wrap: anywhere; }
    .tag { font-weight: 500; }
    .tag[data-level="danger"] { color: #b3261e; }
    .tag[data-level="warn"] { color: #8a5a00; }
    .tag[data-level="ok"] { color: #17693a; }
    .tag[data-level="info"] { color: var(--muted); }
    dl { margin: 0; display: grid; grid-template-columns: max-content 1fr; gap: 3px 14px; }
    dt { color: var(--muted); }
    dd { margin: 0; overflow-wrap: anywhere; }
    .meaning { margin: 0 0 6px; }
    .actions { margin: 0; padding-left: 18px; display: grid; gap: 3px; list-style: disc; }
    .actions li { display: list-item; }
    form { padding: 10px 12px; background: var(--soft); border-radius: 6px; display: grid; gap: 6px; }
    label { font-weight: 500; }
    .row { display: flex; flex-wrap: wrap; gap: 8px; }
    input {
      flex: 1 1 200px; min-width: 0; font: inherit; color: var(--ink); background: var(--surface);
      border: 1px solid var(--line); border-radius: 6px; padding: 4px 8px;
    }
    input:focus-visible { outline: 2px solid #1a5fb4; outline-offset: 1px; }
    .primary { background: #1a5fb4; border-color: #1a5fb4; color: #fff; }
    .primary:hover { background: #164f97; }
    .hint { margin: 0; color: var(--muted); font-size: 12px; overflow-wrap: anywhere; }
    .fail { margin: 0; color: #b3261e; font-size: 12px; }
    .fail:empty { display: none; }
  `;

  const MARKS = { ok: '✓', neutral: 'i', warn: '!', danger: '!', unknown: '?' };
  const STATUS_LABELS = { ok: 'Correcto', warn: 'Atención', bad: 'Fallo', info: 'Informativo' };
  const SIGNAL_LABELS = { danger: 'Peligro', warn: 'Atención', ok: 'Correcto', info: 'Dato' };
  const SIGNAL_ORDER = { danger: 0, warn: 1, ok: 2, info: 3 };

  // Todo el contenido sale del correo y lo controla quien lo envía: se inserta
  // siempre como texto, nunca como HTML.
  function el(tag, attributes = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
    node.append(...children);
    return node;
  }

  function protocolTable(protocols) {
    const rows = protocols.map((row) => {
      const expected = el('td', {}, row.expected);
      if (row.record) expected.append(el('code', { class: 'record' }, row.record.slice(0, 160)));
      return el(
        'tr',
        {},
        el('td', { class: 'name' }, row.name),
        expected,
        el('td', {}, row.actual),
        el('td', { class: 'status', 'data-status': row.status }, STATUS_LABELS[row.status]),
      );
    });
    const head = el(
      'tr',
      {},
      el('th', { scope: 'col' }, 'Protocolo'),
      el('th', { scope: 'col' }, 'Debería'),
      el('th', { scope: 'col' }, 'Este correo'),
      el('th', { scope: 'col' }, 'Estado'),
    );
    return el('div', { class: 'scroll' }, el('table', {}, el('thead', {}, head), el('tbody', {}, ...rows)));
  }

  function signalList(signals) {
    const sorted = [...signals].sort((a, b) => SIGNAL_ORDER[a.level] - SIGNAL_ORDER[b.level]);
    return el(
      'ul',
      {},
      ...sorted.map((signal) => el(
        'li',
        {},
        el('span', { class: 'tag', 'data-level': signal.level }, SIGNAL_LABELS[signal.level]),
        el('span', {}, signal.text),
      )),
    );
  }

  function detailList(details) {
    const list = el('dl');
    for (const [label, value] of details) list.append(el('dt', {}, label), el('dd', {}, value));
    return list;
  }

  function section(title, content) {
    return el('section', {}, el('h3', {}, title), content);
  }

  function explanation(verdict) {
    return el(
      'div',
      {},
      el('p', { class: 'meaning' }, verdict.meaning),
      el('ul', { class: 'actions' }, ...verdict.actions.map((action) => el('li', {}, action))),
    );
  }

  function addBrandForm(addable, onAddBrand) {
    const name = el('input', {
      type: 'text',
      id: 'ev-brand-name',
      maxlength: '60',
      autocomplete: 'off',
      placeholder: 'Nombre de la empresa',
    });
    name.value = addable.suggestedName;
    const submit = el('button', { type: 'submit', class: 'primary' }, 'Añadir');
    const fail = el('p', { class: 'fail', role: 'alert' });
    const form = el(
      'form',
      {},
      el('label', { for: 'ev-brand-name' }, 'Añadir a mi lista de empresas'),
      el('div', { class: 'row' }, name, submit),
      el('p', { class: 'hint' }, `Se guardará ${addable.domain} como dominio de esta empresa. Hazlo solo si estás seguro de que es suyo.`),
      fail,
    );
    // Sin esto, lo que se escribe aquí activaría los atajos de teclado de Gmail.
    for (const type of ['keydown', 'keypress', 'keyup']) {
      name.addEventListener(type, (event) => event.stopPropagation());
    }
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      fail.textContent = '';
      submit.disabled = true;
      try {
        await onAddBrand(name.value, addable.domain);
      } catch (error) {
        fail.textContent = error.message;
        submit.disabled = false;
      }
    });
    return form;
  }

  function createPanel(host, { onAddBrand } = {}) {
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.append(el('style', {}, STYLES));
    const card = el('div', { class: 'card', 'data-level': 'unknown' });
    shadow.append(card);

    function renderHead(level, title, summary, toggle) {
      card.setAttribute('data-level', level);
      const text = el('div', { class: 'text' }, el('div', { class: 'title' }, title));
      if (summary) text.append(el('div', { class: 'summary' }, summary));
      const head = el(
        'div',
        { class: 'head' },
        el('span', { class: 'mark', 'aria-hidden': 'true' }, MARKS[level] || '?'),
        text,
      );
      if (toggle) head.append(toggle);
      card.replaceChildren(head);
    }

    return {
      loading() {
        renderHead('unknown', 'Comprobando remitente…', '');
      },
      error(message) {
        renderHead('unknown', 'No se pudo comprobar este correo', message);
      },
      show(report) {
        const toggle = el('button', { type: 'button', 'aria-expanded': 'false' }, 'Detalles');
        renderHead(report.verdict.level, report.verdict.title, report.verdict.summary, toggle);

        const body = el('div', { class: 'body', hidden: '' });
        body.append(section('Qué significa y qué hacer', explanation(report.verdict)));
        if (report.addable && onAddBrand) body.append(addBrandForm(report.addable, onAddBrand));
        if (report.protocols.length) body.append(section('Protocolos', protocolTable(report.protocols)));
        if (report.signals.length) body.append(section('Señales', signalList(report.signals)));
        if (report.details.length) body.append(section('Datos', detailList(report.details)));
        card.append(body);

        toggle.addEventListener('click', () => {
          const open = body.hasAttribute('hidden');
          body.toggleAttribute('hidden', !open);
          toggle.setAttribute('aria-expanded', String(open));
          toggle.textContent = open ? 'Ocultar' : 'Detalles';
        });
      },
    };
  }

  Object.assign(EV, { createPanel });
})(globalThis);
