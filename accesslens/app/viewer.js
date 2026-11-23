// AccessLens viewer — UI thread. All parsing lives in worker.js.
(function () {
  'use strict';
  const $ = (s) => document.querySelector(s);
  const ROW_H = 28, PAGE = 500, OVERSCAN = 10;

  let worker = new Worker('worker.js');
  let msgId = 0;
  const pending = new Map();
  function wireWorker() {
    worker.onmessage = (ev) => {
      const m = ev.data;
      const p = pending.get(m.id);
      if (!p) return;
      if (m.progress) { if (p.onProgress) p.onProgress(m.progress); return; }
      pending.delete(m.id);
      if (m.ok) p.resolveP(m); else p.rejectP(m);
    };
  }
  // The SQLite engine's WebAssembly heap cannot grow, and sql.js caches that module for the
  // life of the worker — so once it aborts, nothing in this worker can convert again. The
  // only real recovery is a new worker, which means re-reading the file the user had open.
  async function restartWorker() {
    try { worker.terminate(); } catch { /* already gone */ }
    for (const [, p] of pending) p.rejectP({ error: 'worker restarted' });
    pending.clear();
    worker = new Worker('worker.js');
    wireWorker();
    if (state.bytes) {
      const keep = state.current;
      await openBytes(state.bytes, state.fileName, state.password, { reopen: true });
      if (keep && state.tables.some(t => t.name === keep)) selectTable(keep);
    }
  }
  // Returns a promise carrying `.id` (used to cancel long ops); onProgress gets {done,total,label,rows}.
  function call(op, payload, transfer, onProgress) {
    const id = ++msgId;
    const p = new Promise((resolveP, rejectP) => {
      pending.set(id, { resolveP, rejectP, onProgress });
      worker.postMessage(Object.assign({ id, op }, payload), transfer || []);
    });
    p.id = id;
    return p;
  }
  wireWorker();

  // dev/test hook
  window.__AL = { state: 'idle', tables: [], table: null, rows: 0, lastSearch: null, relationships: 0, view: 'data', lastExport: null };

  const state = {
    fileName: '', bytes: null, password: undefined,
    pro: null,            // {key, activatedAt, productId} once activated
    gate: null,           // ALGate.evaluate() result for the open database
    pendingAction: null,  // what the user tried to do when the wall appeared
    tables: [], current: null, cols: [], complex: [],
    relationships: [],     // decoded by the worker (schema.mjs)
    view: 'data',          // 'data' | 'schema' | 'results'
    rowCount: 0,
    cache: new Map(),      // pageIndex -> rows[]
    inflight: new Set(),
    searchMode: false, searchRows: [],
    lastOpen: null, lastBytes: null,   // the last SUCCESSFUL open, for restoreAfterFailedOpen()
  };
  // Bumped on every table selection and file open. A worker reply that arrives after that
  // (a page or search for the previous table or the previous FILE) is dropped instead of
  // being painted into, or toasted over, a screen it no longer belongs to. Found 2026-09-10 as
  // "Read error: Could not find table Table1" on a freshly opened Northwind.
  let tableGen = 0;
  // Same idea for the `open` call itself: decrypting takes ~2 s, and a reply for a file the
  // user has since replaced must not paint that file — or its password prompt, or its error
  // card — over the one now on screen (seen 2026-09-10 on the v0.1.2 build).
  let openGen = 0;

  function toast(msg, info) {
    const t = $('#toast');
    t.textContent = msg;
    t.className = 'toast' + (info ? ' info' : '');
    t.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => { t.hidden = true; }, 5000);
  }

  // ---- open flow ------------------------------------------------------------
  // opts.reopen: restartWorker() re-reading the file the user already had open (not a new open).
  async function openBytes(bytes, name, password, opts = {}) {
    const gen = ++openGen;
    try {
      const res = await call('open', { bytes, name, password });
      if (gen !== openGen) return;   // another file was opened while this one was being read
      state.password = password;   // kept in memory only, so a worker restart can reopen the file
      state.fileName = res.fileName;
      state.tables = res.tables;
      state.lastOpen = res;        // what restoreAfterFailedOpen() brings back if the NEXT open fails
      state.lastBytes = bytes;
      tableGen++;                  // replies for the previous file are now stale
      // A newly opened database must not inherit the previous one's screen. Leaving the
      // results view up showed matches from a file that is no longer open, and its
      // "Open in table" buttons pointed at tables that no longer exist.
      if (state.view !== 'data') setView('data');
      $('#scope').value = 'table';
      $('#search').placeholder = 'Search this table… (Enter)';
      window.__AL.state = 'open';
      window.__AL.tables = res.tables.map(t => ({ name: t.name, rows: t.rowCount }));
      renderFile(res);
      if (res.tables.length) selectTable(res.tables[0].name);
      else toast('Database opened — it contains no user tables.', true);
      if (!opts.reopen) noteOpenForRating();
    } catch (m) {
      if (gen !== openGen) return;   // stale failure for a file that is no longer the one being opened
      if (m.needPassword) {
        askPassword(bytes, name, password !== undefined);
      } else {
        window.__AL.state = 'error:' + m.error;
        showOpenError({ name, size: bytes ? bytes.byteLength : 0 }, 'parse', m.error);
      }
    }
  }

  // ---- open failures (2026-09-10) ---------------------------------------------
  // There is no telemetry, by design, so a file that will not open is invisible to the
  // developer unless the USER says so. The card names the likely cause in Access terms and
  // offers a one-click report carrying the error text and file size — never the file.
  const REPORT_EMAIL = 'phakeoa@gmail.com';
  function showOpenError(file, kind, error) {
    const name = file && file.name ? file.name : 'that file';
    const kb = file && file.size ? Math.round(file.size / 1024) : 0;
    let why;
    if (kind === 'lockfile') {
      why = `<strong>${esc(name)}</strong> is a <em>lock file</em>, not a database. Access creates it beside a database ` +
        `while that database is open. Pick the <code>.accdb</code> or <code>.mdb</code> file with the same name that sits next to it.`;
    } else {
      why = `<strong>${esc(name)}</strong> could not be read as an Access database` + (error ? ` (<code>${esc(error)}</code>)` : '') + `. Usual causes:` +
        `<ul><li>it is not an Access file — a renamed export, a backup container, or a <code>.laccdb</code>/<code>.ldb</code> lock file;</li>` +
        `<li>it was saved in a format this viewer does not read (Access 97 through 2019 <code>.mdb</code> and <code>.accdb</code> are supported);</li>` +
        `<li>the file is damaged — in Access, run <em>Compact &amp; Repair</em> on a copy, then try again.</li></ul>`;
    }
    $('#openerr-why').innerHTML = why;
    const subject = encodeURIComponent('AccessLens: a file did not open');
    const body = encodeURIComponent(
      `File type: ${(name.match(/\.[^.]+$/) || ['?'])[0]}\nSize: ${kb} KB\nError: ${error || kind}\n\n` +
      `(No data is attached. If you are able to share the file, reply and say so.)`);
    $('#openerr-report').href = `mailto:${REPORT_EMAIL}?subject=${subject}&body=${body}`;
    $('#openerr').hidden = false;
    restoreAfterFailedOpen();
    window.__AL.state = 'error:' + (error || kind);
  }
  function hideOpenError() { $('#openerr').hidden = true; }

  // ---- rating ask (2026-09-10; widened in v1.2, 2026-11-23) -----------------------
  // Ratings were still 0 at ~160 weekly users. v1.1 asked only right after a successful export
  // and never in Edge — but with no Edge Add-ons listing yet, every Edge user installed from the
  // Chrome Web Store and can rate there, and people who only LOOK at a file were never asked.
  // Who to ask, when, and where the rating goes lives in src/rate.mjs (ALGate.rate, unit-tested);
  // this block only does the DOM. Never on install, never after an error, a few showings at most,
  // one answer ends it, nothing offered in return. localStorage on the page's own origin, so no
  // `storage` permission (same as the Pro record).
  const R = ALGate.rate;
  const IS_EDGE = /\bEdg\//.test(navigator.userAgent);
  const IS_FIREFOX = /\bFirefox\//.test(navigator.userAgent);
  // The web version (site/app/, built by web/build_web.mjs) defines window.AL_WEB in web.js before
  // this file loads. There is no store copy to rate there, so the same slots offer the extension.
  const WEB = (window.AL_WEB && typeof window.AL_WEB === 'object') ? window.AL_WEB : null;
  const NUDGE_KEY = WEB ? R.WEB_KEY : R.RATE_KEY;
  const NUDGE_MAX = WEB ? R.WEB_MAX_SHOWINGS : R.MAX_SHOWINGS;
  const RETURN_ASK_DELAY_MS = 12000;   // let a returning user see their data before anything appears
  let askedThisPage = false;
  let sessionNoted = false;
  function extensionId() {
    try { return (globalThis.chrome && chrome.runtime && chrome.runtime.id) || ''; } catch { return ''; }
  }
  // Evaluated on demand: the dev rig's ?forceRate=1 is read at the END of this file.
  function nudgeTarget() {
    if (WEB) {
      const url = IS_FIREFOX ? (WEB.firefoxUrl || WEB.installUrl) : WEB.installUrl;
      return url ? { kind: 'install', url, label: IS_FIREFOX ? 'Add to Firefox' : 'Get the extension' } : null;
    }
    const store = R.storeFor(extensionId()) || (window.__AL._forceRate ? R.storeFor(R.CWS_ID) : null);
    return store ? { kind: 'rate', url: store.reviewUrl, label: `Rate it on ${store.name}`, store: store.short } : null;
  }
  function maybeAsk(trigger) {
    const t = nudgeTarget();
    if (!t || !$('#rate').hidden) return false;
    const st = R.read(localStorage, NUDGE_KEY);
    if (!R.shouldAsk(st, trigger, { askedThisPage, max: NUDGE_MAX })) return false;
    askedThisPage = true;
    R.write(localStorage, NUDGE_KEY, R.markShown(st));
    $('#rate-text').textContent = R.message(t.kind, trigger);
    $('#rate-go').textContent = t.label;
    $('#rate-go').dataset.url = t.url;
    $('#rate').hidden = false;
    window.__AL.rateAsked = { trigger, kind: t.kind };
    return true;
  }
  function maybeAskRating() { maybeAsk('export'); }
  function answerRating(go) {
    R.write(localStorage, NUDGE_KEY, R.markAnswered(R.read(localStorage, NUDGE_KEY)));
    $('#rate').hidden = true;
    const url = $('#rate-go').dataset.url;
    if (go && url) window.open(url, '_blank', 'noopener');
  }
  // After every successful open the user started. The first one in a page load counts a session;
  // from the second session on the user has come back to AccessLens, so ask once the file has
  // been on screen for a moment — unless something else is going on.
  function noteOpenForRating() {
    if (sessionNoted) return;
    sessionNoted = true;
    const st = R.noteSession(R.read(localStorage, NUDGE_KEY));
    R.write(localStorage, NUDGE_KEY, st);
    window.__AL.rateSessions = st.sessions;
    if (!nudgeTarget() || !R.shouldAsk(st, 'return', { askedThisPage, max: NUDGE_MAX })) return;
    const delay = Number.isFinite(window.__AL._rateDelay) ? window.__AL._rateDelay : RETURN_ASK_DELAY_MS;
    setTimeout(() => {
      if (window.__AL.state !== 'open' || busy() || document.querySelector('dialog[open]')) return;
      maybeAsk('return');
    }, delay);
  }
  // The quiet, always-there link at the foot of the table list.
  function renderSideLink() {
    const a = $('#side-link');
    const t = nudgeTarget();
    if (!a || !t) { if (a) a.hidden = true; return; }
    a.href = t.url;
    a.textContent = t.kind === 'install' ? 'Get the free extension' : '★ Rate AccessLens';
    a.title = t.kind === 'install' ? 'Opens the store page in a new tab' : `Opens AccessLens on ${t.store} in a new tab`;
    a.hidden = false;
  }

  let pwCtx = null; // {bytes, name} while the password dialog is up
  function askPassword(bytes, name, wasWrong) {
    pwCtx = { bytes, name };
    $('#pw-err').hidden = !wasWrong;
    $('#pw').value = '';
    $('#pwdlg').showModal();
    $('#pw').focus();
  }
  function pwSubmit() {
    const v = $('#pw').value;
    const ctx = pwCtx;
    $('#pwdlg').close();
    if (v && ctx) {
      // Decrypting takes ~2 s per attempt and the dialog is gone meanwhile — say what is happening.
      $('#filemeta').textContent = `Checking the password for ${ctx.name}…`;
      openBytes(ctx.bytes, ctx.name, v);
    } else {
      pwCancel();
    }
  }
  function pwCancel() {
    pwCtx = null;
    if ($('#pwdlg').open) $('#pwdlg').close();
    restoreAfterFailedOpen();
  }
  // A file that did not open (bad file, cancelled password) must not leave the screen in the
  // half-state openFile put it in — an empty <main> with "Opening…" in the sidebar and nothing
  // to click (found 2026-09-10). Bring back either the previously open database or the drop zone.
  function restoreAfterFailedOpen() {
    if (state.lastOpen && state.tables.length) {
      state.bytes = state.lastBytes;
      renderFile(state.lastOpen);
      document.querySelectorAll('#tables li').forEach(li => li.classList.toggle('active', li.dataset.t === state.current));
      window.__AL.state = 'open';
    } else {
      state.bytes = null;
      $('#filemeta').textContent = '';
      $('#main').hidden = true;
      $('#drop').hidden = false;
      window.__AL.state = 'idle';
    }
  }

  async function openFile(file) {
    // The worker has ONE reader. Replacing it under a running export or cross-table search
    // would feed the rest of that job rows from the wrong database (found 2026-09-10).
    if (busy()) return toast('Please wait for the current export or search to finish before opening another file.', true);
    hideOpenError();
    // The lock file Access writes beside an open database is the most common wrong pick in a
    // folder listing: same name, sits right next to the real file, and is NOT a database.
    if (/\.(laccdb|ldb)$/i.test(file.name)) {
      window.__AL.state = 'error:lockfile';
      return showOpenError(file, 'lockfile');
    }
    window.__AL.state = 'loading';
    $('#drop').hidden = true;
    $('#welcome').hidden = true;
    $('#main').hidden = false;
    // A big file on a slow disk takes seconds to read before parsing even starts. Say so —
    // a blank screen with no feedback reads as "broken", which is a silent uninstall.
    $('#filemeta').textContent = `Opening ${file.name} — ${(file.size / 1048576).toFixed(1)} MB…`;
    $('#tables').innerHTML = '';
    const bytes = await file.arrayBuffer();
    state.bytes = bytes;
    await openBytes(bytes, file.name);
  }

  // ---- rendering ------------------------------------------------------------
  function renderFile(res) {
    const kb = state.bytes ? Math.round(state.bytes.byteLength / 1024) : 0;
    const rels = state.relationships = Array.isArray(res.relationships) ? res.relationships : [];
    window.__AL.relationships = rels.length;
    for (const s of ['#btn-zip', '#btn-xlsx', '#btn-sqlite', '#btn-sql']) $(s).disabled = !res.tables.length;
    refreshGate();
    // A split database: the front-end holds linked tables whose rows live in a separate
    // back-end file. Without this line it shows as an empty database and reads as "broken".
    const linked = Number(res.linkedTables) || 0;
    const frontEnd = linked > 0 && res.tables.every(t => !t.rowCount);
    const linkedNote = linked
      ? `<br>${linked} linked table${linked === 1 ? '' : 's'} (data in another file)` +
        (frontEnd ? `<div class="note">This is a <strong>front-end</strong> database: its ${linked} linked table${linked === 1 ? '' : 's'} point at a separate ` +
          `<strong>back-end</strong> file, usually named like <em>…_be.accdb</em> or <em>…_data.mdb</em>, in the same folder or on a network share. ` +
          `Open that file to see the rows.</div>` : '')
      : '';
    $('#filemeta').innerHTML =
      `<strong>${esc(res.fileName)}</strong><br>${res.tables.length} tables · ${kb.toLocaleString()} KB` +
      (rels.length ? `<br><a href="#" id="rel-link" title="Open the schema view">${rels.length} relationship${rels.length === 1 ? '' : 's'}</a>` : '<br>no relationships') +
      linkedNote;
    const link = $('#rel-link');
    if (link) link.addEventListener('click', (e) => { e.preventDefault(); setView('schema'); });
    const ul = $('#tables');
    ul.innerHTML = res.tables.map(t =>
      `<li data-t="${esc(t.name)}"><span class="n" title="${esc(t.name)}">${esc(t.name)}</span><span class="c">${t.rowCount.toLocaleString()}</span></li>`
    ).join('');
  }

  async function selectTable(name) {
    const meta = state.tables.find(t => t.name === name);
    if (!meta) return;
    tableGen++;
    state.current = name;
    state.cols = meta.cols.filter(c => c.type !== 'complex');
    state.complex = meta.complexCols;
    state.rowCount = meta.rowCount;
    state.cache.clear(); state.inflight.clear();
    state.searchMode = false; state.searchRows = [];
    window.__AL.table = name; window.__AL.rows = meta.rowCount;

    document.querySelectorAll('#tables li').forEach(li => li.classList.toggle('active', li.dataset.t === name));
    $('#search').disabled = false; $('#scope').disabled = false; $('#search').value = '';
    $('#btn-clear').hidden = true;
    $('#btn-csv').disabled = false;
    $('#tablemeta').textContent = `${name} — ${meta.rowCount.toLocaleString()} rows, ${meta.cols.length} columns` +
      (state.complex.length ? ` (${state.complex.length} multi-valued column${state.complex.length > 1 ? 's' : ''} not shown)` : '');

    renderHead();
    layoutRows();
    $('#grid').scrollTop = 0;
    renderWindow();
    $('#btn-schema').disabled = false;
    // Picking a table is a request to SEE that table. Staying on cross-table results made the
    // click look broken: the selection changed behind a screen that never updated.
    if (state.view === 'results') setView('data');
    else if (state.view === 'schema') renderSchema();
  }

  // ---- schema view (v1.1 B1, free) ------------------------------------------
  const TYPE_LABEL = {
    boolean: 'Yes/No', byte: 'Byte', integer: 'Integer', long: 'Long Integer', currency: 'Currency',
    float: 'Single', double: 'Double', datetime: 'Date/Time', datetimextended: 'Date/Time Extended',
    binary: 'Binary', text: 'Short Text', memo: 'Long Text', ole: 'OLE Object', repid: 'Replication ID',
    numeric: 'Decimal', complex: 'Multi-valued / Attachment', bigint: 'Large Number',
  };
  function typeLabel(c) {
    let s = TYPE_LABEL[c.type] || c.type;
    if (c.type === 'numeric' && c.precision !== undefined) s += ` (${c.precision},${c.scale ?? 0})`;
    return s;
  }
  function sizeLabel(c) {
    return (c.type === 'memo' || c.type === 'ole' || c.type === 'complex' || c.type === 'boolean') ? '—' : String(c.size ?? '');
  }
  function renderSchema() {
    const meta = state.tables.find(t => t.name === state.current);
    if (!meta) return;
    $('#schema-title').textContent = `${meta.name} — ${meta.cols.length} column${meta.cols.length === 1 ? '' : 's'}`;
    $('#schema-table tbody').innerHTML = meta.cols.map(c => {
      // complex (multi-valued/attachment) columns carry an internal auto id — not a user AutoNumber
      const auto = c.type === 'complex' ? '' : c.autoLong ? 'AutoNumber' : c.autoUUID ? 'AutoNumber (GUID)' : '';
      const notes = [c.type === 'complex' ? 'not displayed' : '', c.fixedLength ? 'fixed length' : ''].filter(Boolean).join(', ');
      return `<tr><td class="mono">${esc(c.name)}</td><td>${esc(typeLabel(c))}</td><td class="num">${esc(sizeLabel(c))}</td>` +
        `<td>${c.nullable ? 'yes' : 'no'}</td><td>${auto}</td><td class="muted">${esc(notes)}</td></tr>`;
    }).join('');
    const rels = state.relationships;
    const isMine = (r) => r.from.table === state.current || r.to.table === state.current;
    const mine = rels.filter(isMine).length;
    $('#rel-count').textContent = rels.length ? `${mine} involve ${meta.name} · ${rels.length} in database` : '';
    const side = (t, cols) => `<a href="#" data-t="${esc(t)}" class="mono">${esc(t)}</a>.${esc(cols.join(' + '))}`;
    $('#rels').innerHTML = rels.length ? rels.map(r => {
      const f = r.flags || {};
      const flags = [
        f.enforced ? 'referential integrity enforced' : 'not enforced',
        f.unique ? 'one-to-one' : 'one-to-many',
        f.cascadeUpdate ? 'cascade update' : '', f.cascadeDelete ? 'cascade delete' : '',
        f.join && f.join !== 'inner' ? f.join + ' join' : '',
      ].filter(Boolean).join(' · ');
      return `<li class="${isMine(r) ? 'mine' : ''}">${side(r.from.table, r.from.cols)}<span class="arrow">→</span>${side(r.to.table, r.to.cols)}` +
        `<span class="flags">${esc(r.name)} — ${esc(flags)}</span></li>`;
    }).join('') : '<li class="empty">No relationships are defined in this database.</li>';
  }
  function setView(v) {
    state.view = v; window.__AL.view = v;
    $('#grid').hidden = v !== 'data';
    $('#schema').hidden = v !== 'schema';
    $('#results').hidden = v !== 'results';
    $('#btn-schema').textContent = v === 'schema' ? 'Data' : 'Schema';
    $('#btn-schema').classList.toggle('on', v === 'schema');
    if (v === 'schema') renderSchema();
    else if (v === 'data') renderWindow();
  }

  // ---- cross-table search (v1.1 B4) -----------------------------------------
  // Gated by the B5 size gate like the whole-database exports (runSearchAll → showWall).
  function highlight(text, q) {
    const s = String(text ?? '');
    const i = s.toLowerCase().indexOf(q.toLowerCase());
    if (i < 0 || !q) return esc(s);
    return esc(s.slice(0, i)) + '<mark>' + esc(s.slice(i, i + q.length)) + '</mark>' + esc(s.slice(i + q.length));
  }
  function renderResults(res, q) {
    const head = res.totalMatched
      ? `${res.totalMatched.toLocaleString()} match${res.totalMatched === 1 ? '' : 'es'} for “${esc(q)}” in ` +
        `${res.tablesWithMatches} of ${res.tablesSearched} table${res.tablesSearched === 1 ? '' : 's'}` +
        (res.hitsTruncated ? ' — showing the first rows of each' : '')
      : `No matches for “${esc(q)}” in any of the ${res.tablesSearched} tables.`;
    $('#results-head').innerHTML = head;
    $('#results-list').innerHTML = res.perTable.map(t => {
      const cols = t.cols;
      const body = t.hits.map(h =>
        `<tr>${cols.map(c => `<td title="${esc(String(h[c] ?? ''))}">${highlight(h[c], q)}</td>`).join('')}</tr>`).join('');
      return `<section class="rgroup">
        <header>
          <span class="rname">${esc(t.name)}</span>
          <span class="rcount">${t.matched.toLocaleString()} match${t.matched === 1 ? '' : 'es'}</span>
          <span class="rspacer"></span>
          <button class="btn ghost small" data-open="${esc(t.name)}">Open in table</button>
        </header>
        ${t.hits.length ? `<div class="rwrap"><table><thead><tr>${cols.map(c => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${body}</tbody></table></div>` : ''}
        ${t.capped ? `<div class="rmore">Showing ${t.hits.length} of ${t.matched.toLocaleString()} — open the table to see the rest.</div>` : ''}
      </section>`;
    }).join('') || '<p class="rempty">Try a shorter or different term.</p>';
  }
  async function runSearchAll(q) {
    if (!state.tables.length) return;
    // Export and cross-table search share one worker AND one progress bar. Letting both run
    // made the bar report whichever finished a table last, and Cancel could only reach the
    // export — leaving the search with no way to stop it.
    if (busy()) return toast('Please wait for the current job to finish.', true);
    if (state.gate && state.gate.needsPro) return showWall('searchAll');
    $('#tablemeta').textContent = '';
    const p = call('searchAll', { query: q }, null, showProgress);
    searchJob = p.id;
    showProgress({ done: 0, total: state.tables.length, label: state.tables[0].name, rows: 0 });
    try {
      const res = await p;
      window.__AL.lastSearchAll = { q, totalMatched: res.totalMatched, tables: res.tablesWithMatches };
      renderResults(res, q);
      setView('results');
      $('#btn-clear').hidden = false;
    } catch (m) {
      if (m.cancelled) toast('Search cancelled.', true); else toast('Search error: ' + m.error);
    } finally {
      searchJob = null;
      showProgress(null);
    }
  }

  function renderHead() {
    const head = state.cols.map(c => `<div class="h" title="${esc(c.name)} (${esc(c.type)})">${esc(c.name)}</div>`).join('') +
      state.complex.map(n => `<div class="h complex" title="Multi-valued field — not supported">${esc(n)} ⊘</div>`).join('');
    $('#ghead').innerHTML = head;
  }

  function rowsShown() { return state.searchMode ? state.searchRows.length : state.rowCount; }

  function layoutRows() {
    $('#gspacer').style.height = (rowsShown() * ROW_H) + 'px';
    const width = (state.cols.length + state.complex.length) * 170;
    $('#gspacer').style.minWidth = width + 'px';
  }

  function rowHtml(r) {
    let cells = state.cols.map(c => {
      const v = r ? r[c.name] : undefined;
      return `<div class="c${v === undefined ? ' ph' : ''}" title="${r ? esc(String(v ?? '')) : ''}">${r ? esc(String(v ?? '')) : '…'}</div>`;
    }).join('');
    cells += state.complex.map(() => `<div class="c ph">[multi-valued]</div>`).join('');
    return cells;
  }

  async function ensurePage(pi) {
    if (state.cache.has(pi) || state.inflight.has(pi)) return;
    state.inflight.add(pi);
    const gen = tableGen;
    try {
      const res = await call('page', { name: state.current, offset: pi * PAGE, limit: PAGE });
      if (gen !== tableGen) return;   // the table or the file changed while this was in flight
      state.cache.set(pi, res.rows);
      if (state.cache.size > 40) { // bound memory: drop farthest pages
        const keys = [...state.cache.keys()].sort((a, b) => Math.abs(b - pi) - Math.abs(a - pi));
        state.cache.delete(keys[0]);
      }
      renderWindow();
    } catch (m) {
      if (gen === tableGen) toast('Read error: ' + m.error);
    } finally {
      state.inflight.delete(pi);
    }
  }

  function renderWindow() {
    if (!state.current) return;
    const grid = $('#grid');
    const start = Math.max(0, Math.floor(grid.scrollTop / ROW_H) - OVERSCAN);
    const count = Math.ceil(grid.clientHeight / ROW_H) + OVERSCAN * 2;
    const end = Math.min(rowsShown(), start + count);
    let html = '';
    for (let i = start; i < end; i++) {
      let r;
      if (state.searchMode) {
        r = state.searchRows[i];
      } else {
        const pi = Math.floor(i / PAGE);
        const page = state.cache.get(pi);
        r = page ? page[i - pi * PAGE] : undefined;
        if (!page) ensurePage(pi);
      }
      html += `<div class="r" style="top:0">${rowHtml(r)}</div>`;
    }
    const rows = $('#grows');
    rows.style.transform = `translateY(${start * ROW_H}px)`;
    rows.innerHTML = html;
  }

  // ---- search ---------------------------------------------------------------
  async function runSearch(q) {
    if (state.view !== 'data') setView('data');
    if (!state.current) return;
    const gen = tableGen;
    try {
      const res = await call('search', { name: state.current, query: q });
      if (gen !== tableGen) return;   // the user moved on before the answer came back
      state.searchMode = true;
      state.searchRows = res.hits;
      window.__AL.lastSearch = { q, matched: res.matched };
      $('#btn-clear').hidden = false;
      $('#tablemeta').textContent = `${res.matched.toLocaleString()} match${res.matched === 1 ? '' : 'es'} for "${q}"` +
        (res.capped ? ` — showing first ${state.searchRows.length}` : '');
      layoutRows(); $('#grid').scrollTop = 0; renderWindow();
    } catch (m) { toast('Search error: ' + m.error); }
  }

  function clearSearch() {
    state.searchMode = false; state.searchRows = [];
    $('#search').value = ''; $('#btn-clear').hidden = true;
    const meta = state.tables.find(t => t.name === state.current);
    if (meta) $('#tablemeta').textContent = `${state.current} — ${meta.rowCount.toLocaleString()} rows, ${meta.cols.length} columns`;
    layoutRows();
    if (state.view === 'results') setView('data'); else renderWindow();
  }

  // ---- Pro gate (v1.1 B5) ----------------------------------------------------
  // ONE rule for everything: whole-database exports and cross-table search are free while
  // the database is small, and Pro above that. Single-table CSV is never gated, so no one is
  // ever locked out of their own data. Decided at open time, so no wall ever appears mid-job.
  const GATED_BTN = { zip: '#btn-zip', xlsx: '#btn-xlsx', sqlite: '#btn-sqlite', sql: '#btn-sql' };

  function refreshGate() {
    state.gate = ALGate.evaluate(state.tables, { isPro: !!state.pro });
    const locked = state.gate.needsPro;
    window.__AL.gate = { free: state.gate.free, needsPro: locked, isPro: !!state.pro, size: state.gate.size };
    for (const sel of Object.values(GATED_BTN)) {
      const b = $(sel);
      if (b) b.classList.toggle('gated', locked);
    }
    // A "Pro" pill on a feature that ACTUALLY WORKS for the open database is a lie and reads
    // as nagware — show it only when this database really is gated.
    document.querySelectorAll('.menu-items .pill').forEach(p => { p.hidden = !locked; });
    const scopeAll = $('#scope') && $('#scope').querySelector('option[value="all"]');
    if (scopeAll) scopeAll.textContent = locked ? 'All tables (Pro)' : 'All tables';
    const pb = $('#btn-pro');
    if (pb) {
      pb.hidden = !state.tables.length;
      pb.textContent = state.pro ? 'Pro ✓' : locked ? `Get Pro ${ALLicense.price()}` : 'Pro…';
      pb.classList.toggle('pro', locked && !state.pro);
      pb.title = state.pro
        ? 'Pro is active on this browser. Thank you.'
        : locked ? 'Whole-database export and all-tables search need Pro for a database this size'
                 : 'This database is within the free limits — everything is unlocked';
    }
  }

  function showWall(action) {
    state.pendingAction = action;
    const gated = !!(state.gate && state.gate.needsPro);
    $('#pro-title').textContent = state.pro ? 'Pro is active'
      : !gated ? 'About Pro'
      : action === 'searchAll' ? 'Searching every table' : 'Exporting the whole database';
    $('#pro-why').textContent = ALGate.proMessage(state.gate, ALLicense.price());
    $('#pro-buy').hidden = !ALLicense.isConfigured() || !!state.pro;
    // Shown exactly when the Buy button is — the Business choice is made on the Payhip page.
    // Wording mirrors store/licence_terms.md — the licence, not the code, makes Business required.
    $('#pro-work').textContent = `Using Pro for work? The licence terms require the Business licence (${ALLicense.businessPrice()} once, covers your team at one organisation). Choose it at checkout.`;
    $('#pro-work').hidden = $('#pro-buy').hidden;
    $('#pro-keyrow').hidden = true;
    $('#pro-err').hidden = true;
    $('#pro-key').value = '';
    $('#prodlg').showModal();
  }

  // Enter twice, or Enter + a click, must not start two activations (found 2026-09-10 when
  // activation was a provider call; the check is local now, but a double run would still race
  // the dialog close and the pending action, so the guard stays).
  let activating = false;
  async function activateKey() {
    if (activating) return;
    activating = true;
    const btn = $('#pro-activate');
    btn.disabled = true;
    try {
      const res = await ALLicense.validateKey($('#pro-key').value);
      if (!res.ok) {
        $('#pro-err').textContent = res.reason;
        $('#pro-err').hidden = false;
        return;
      }
      state.pro = res.record;
      ALGate.writePro(localStorage, res.record);
      $('#prodlg').close();
      refreshGate();
      toast('Pro activated — thank you. Everything is unlocked on this browser.', true);
      const next = state.pendingAction;
      state.pendingAction = null;
      if (next === 'searchAll') { const q = $('#search').value.trim(); if (q) runSearchAll(q); }
      else if (next) runExport(next);
    } finally {
      activating = false;
      btn.disabled = false;
    }
  }

  // ---- exports (v1.1 B2: CSV · ZIP of CSVs · XLSX; B3: SQLite · .sql) --------
  const EXPORT_BTNS = ['#btn-csv', '#btn-zip', '#btn-xlsx', '#btn-sqlite', '#btn-sql'];
  let exportJob = null;  // worker message id of the export in flight
  let searchJob = null;  // worker message id of a cross-table search in flight
  const busy = () => exportJob !== null || searchJob !== null;

  function baseName() {
    return (state.fileName || 'database').replace(/\.(mdb|accdb)$/i, '').replace(/[^\w\- ]+/g, '_') || 'database';
  }
  function saveBytes(data, name, mime) {
    const blob = new Blob([data], { type: mime });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  }
  function showProgress(p) {
    const box = $('#progress');
    if (!p) { box.hidden = true; return; }
    box.hidden = false;
    const meta = state.tables.find(t => t.name === p.label);
    const frac = meta && meta.rowCount ? Math.min(1, (p.rows || 0) / meta.rowCount) : 0;
    $('#pbar').value = p.total ? Math.round(((p.done + frac) / p.total) * 100) : 0;
    $('#ptext').textContent = `${p.label}${p.rows ? ' · ' + p.rows.toLocaleString() + ' rows' : ''} (${p.done + 1}/${p.total})`;
  }
  async function runExport(kind) {
    if (!state.current) return;
    $('#export').open = false;
    if (busy()) return toast('Please wait for the current job to finish.', true);
    if (ALGate.isGatedAction(kind) && state.gate && state.gate.needsPro) return showWall(kind);
    EXPORT_BTNS.forEach(s => { $(s).disabled = true; });
    const op = { zip: 'csvAll', xlsx: 'xlsx', sqlite: 'sqlite', sql: 'sql' }[kind] || 'csv';
    const p = call(op, op === 'csv' ? { name: state.current } : {}, null, showProgress);
    exportJob = p.id;
    if (op !== 'csv') showProgress({ done: 0, total: state.tables.length, label: state.tables[0].name, rows: 0 });
    try {
      const res = await p;
      if (op === 'csv') {
        saveBytes(res.csv, state.current.replace(/[^\w\- ]+/g, '_') + '.csv', 'text/csv;charset=utf-8');
        if (res.excluded.length) toast('CSV exported — multi-valued columns excluded: ' + res.excluded.join(', '), true);
      } else if (op === 'csvAll') {
        saveBytes(res.bytes, baseName() + '_tables.zip', 'application/zip');
        const ex = res.report.filter(r => r.excluded.length).map(r => r.name);
        toast(`ZIP exported — ${res.report.length} CSV file${res.report.length === 1 ? '' : 's'}` +
          (ex.length ? ` · multi-valued columns excluded in: ${ex.join(', ')}` : ''), true);
      } else if (op === 'xlsx') {
        saveBytes(res.bytes, baseName() + '.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        const rows = res.report.reduce((a, r) => a + r.rows, 0);
        toast(`Excel workbook exported — ${res.report.length} sheet${res.report.length === 1 ? '' : 's'}, ${rows.toLocaleString()} rows`, true);
      } else if (op === 'sqlite') {
        saveBytes(res.bytes, baseName() + '.sqlite', 'application/vnd.sqlite3');
        const rows = res.report.reduce((a, r) => a + r.rows, 0);
        const dropped = res.report.filter(r => r.pkDropped).map(r => r.table);
        toast(`SQLite database exported — ${res.report.length} tables, ${rows.toLocaleString()} rows` +
          (res.skippedFks ? ` · ${res.skippedFks} relationship${res.skippedFks === 1 ? '' : 's'} noted but not enforced` : '') +
          (dropped.length ? ` · primary key not applied to: ${dropped.join(', ')}` : ''), true);
      } else {
        saveBytes(res.sql, baseName() + '.sql', 'application/sql;charset=utf-8');
        toast('SQL script exported — run it with sqlite3 or any SQLite tool.' +
          (res.skippedFks ? ` ${res.skippedFks} relationship${res.skippedFks === 1 ? '' : 's'} noted as comments.` : ''), true);
      }
      window.__AL.lastExport = { kind, bytes: res.bytes ? res.bytes.byteLength : (res.csv || res.sql).length, report: res.report || null };
      maybeAskRating();
    } catch (m) {
      if (m.cancelled) toast('Export cancelled.', true);
      else toast(m.fatal ? m.error : 'Export error: ' + m.error);
      window.__AL.lastExport = { kind, error: m.error, cancelled: !!m.cancelled, fatal: !!m.fatal };
      // The engine is unusable now — rebuild it so the other exports keep working.
      if (m.fatal) await restartWorker();
    } finally {
      exportJob = null;
      showProgress(null);
      EXPORT_BTNS.forEach(s => { $(s).disabled = false; });
    }
  }
  // One job at a time (see busy()), so this always targets the right one.
  function cancelExport() {
    const job = exportJob !== null ? exportJob : searchJob;
    if (job !== null) worker.postMessage({ op: 'cancel', target: job });
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  }

  // ---- wiring ---------------------------------------------------------------
  $('#pw-ok').addEventListener('click', pwSubmit);
  $('#pw-cancel').addEventListener('click', pwCancel);
  $('#pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); pwSubmit(); } });
  $('#pwdlg').addEventListener('cancel', () => pwCancel());   // Escape = the Cancel button
  $('#btn-open').addEventListener('click', () => $('#file-input').click());
  $('#file-input').addEventListener('change', (e) => {
    const f = e.target.files[0];
    // Clear the input so picking the SAME file again fires `change` (it does not otherwise —
    // the classic "I fixed the file and re-opened it and nothing happened").
    e.target.value = '';
    if (f) openFile(f);
  });
  $('#btn-csv').addEventListener('click', () => runExport('csv'));
  $('#btn-zip').addEventListener('click', () => runExport('zip'));
  $('#btn-xlsx').addEventListener('click', () => runExport('xlsx'));
  $('#btn-sqlite').addEventListener('click', () => runExport('sqlite'));
  $('#btn-sql').addEventListener('click', () => runExport('sql'));
  $('#btn-cancel').addEventListener('click', cancelExport);
  $('#btn-pro').addEventListener('click', () => showWall(null));
  $('#openerr-close').addEventListener('click', hideOpenError);
  $('#rate-go').addEventListener('click', () => answerRating(true));
  $('#rate-no').addEventListener('click', () => answerRating(false));
  // Following the side link is an answer too: it opens the page itself (plain link, new tab),
  // so it only has to stop the card from asking again.
  $('#side-link').addEventListener('click', () => {
    R.write(localStorage, NUDGE_KEY, R.markAnswered(R.read(localStorage, NUDGE_KEY)));
    $('#rate').hidden = true;
  });
  renderSideLink();
  $('#pro-close').addEventListener('click', () => { state.pendingAction = null; $('#prodlg').close(); });
  $('#prodlg').addEventListener('cancel', () => { state.pendingAction = null; });   // Escape = "Not now"
  $('#pro-have').addEventListener('click', () => { $('#pro-keyrow').hidden = false; $('#pro-key').focus(); });
  $('#pro-activate').addEventListener('click', activateKey);
  $('#pro-key').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); activateKey(); } });
  $('#pro-buy').addEventListener('click', () => {
    const url = ALLicense.checkoutUrl();
    if (url) window.open(url, '_blank', 'noopener');
    $('#pro-keyrow').hidden = false;
  });
  state.pro = ALGate.readPro(localStorage);
  document.addEventListener('click', (e) => { if (!$('#export').contains(e.target)) $('#export').open = false; });
  $('#btn-clear').addEventListener('click', clearSearch);
  $('#search').addEventListener('keydown', (e) => {
    const q = e.target.value.trim();
    if (e.key === 'Enter' && q) ($('#scope').value === 'all' ? runSearchAll : runSearch)(q);
    if (e.key === 'Escape') clearSearch();
  });
  $('#scope').addEventListener('change', (e) => {
    const all = e.target.value === 'all';
    $('#search').placeholder = all ? 'Search every table… (Enter)' : 'Search this table… (Enter)';
    // Scope changed, so any showing result set is for the other scope — drop it.
    if (state.view === 'results') setView('data');
    if (state.searchMode) clearSearch();
  });
  $('#results-list').addEventListener('click', (e) => {
    const b = e.target.closest('button[data-open]');
    if (!b) return;
    const q = $('#search').value.trim();
    $('#scope').value = 'table';
    $('#search').placeholder = 'Search this table… (Enter)';
    selectTable(b.dataset.open);
    setView('data');
    if (q) runSearch(q);
  });
  $('#tables').addEventListener('click', (e) => {
    const li = e.target.closest('li');
    if (li) selectTable(li.dataset.t);
  });
  $('#btn-schema').addEventListener('click', () => setView(state.view === 'schema' ? 'data' : 'schema'));
  $('#rels').addEventListener('click', (e) => {
    const a = e.target.closest('a[data-t]');
    if (a) { e.preventDefault(); selectTable(a.dataset.t); }
  });
  $('#grid').addEventListener('scroll', () => requestAnimationFrame(renderWindow));
  window.addEventListener('resize', renderWindow);

  const drop = $('#drop');
  for (const el of [document.body]) {
    el.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('hover'); });
    el.addEventListener('dragleave', () => drop.classList.remove('hover'));
    el.addEventListener('drop', (e) => {
      e.preventDefault(); drop.classList.remove('hover');
      const f = e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) openFile(f);
    });
  }

  // First run: bg.js opens viewer.html?welcome=1 on install. Chrome hides the toolbar icon
  // behind the puzzle-piece menu, so tell the user where the extension lives before they
  // close this tab and lose track of it.
  if (!WEB && new URLSearchParams(location.search).get('welcome') === '1') {
    $('#welcome').hidden = false;
    if (IS_EDGE) $('#welcome-browser').textContent = 'Edge';   // same puzzle-piece menu, different browser name
    $('#welcome-ok').addEventListener('click', () => { $('#welcome').hidden = true; });
  }

  
})();
