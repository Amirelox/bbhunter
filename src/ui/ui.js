// bbhunter — aplikacja. Bez frameworka, hash routing, dane z /api.
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (v) =>
    String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const enc = encodeURIComponent;
  const num = (n) => Number(n ?? 0).toLocaleString("pl-PL");

  async function api(path, options = {}) {
    const res = await fetch(path, options);
    const type = res.headers.get("content-type") || "";
    const body = type.includes("json") ? await res.json().catch(() => null) : await res.text();
    if (!res.ok) throw new Error((body && body.error) || body || res.statusText);
    return body;
  }

  const TITLES = {
    dashboard: "Dashboard",
    live: "Skan na żywo",
    scans: "Skany",
    targets: "Cele i zakres",
    findings: "Znaleziska",
    osint: "OSINT",
    reports: "Raporty",
    modules: "Moduły i reguły",
    settings: "Ustawienia",
    logs: "Logi",
  };
  const STAGES = [
    ["osint", "OSINT"],
    ["subs", "Subdomeny"],
    ["probe", "Probe"],
    ["crawl", "Crawl"],
    ["paths", "Ścieżki"],
  ];
  const SEV = { high: "wysokie", medium: "średnie", low: "niskie", info: "informacyjne" };
  const STATUS = { running: "w toku", done: "gotowe", error: "błąd", stopped: "zatrzymany" };
  const FIND_RE = /^\[!\]\s+(high|medium|low|info)\s{2,}(.+?)\s{2,}(\S+)\s*$/;

  const S = {
    settings: null,
    scopes: [],
    runs: [],
    job: null,
    keys: {},
    cache: {},
    triage: {},
    editingScope: null,
    pendingScope: null,
    filters: { sev: new Set(["high", "medium", "low", "info"]), status: "", q: "" },
    drawerFocus: null,
  };

  // ------------------------------------------------------------- helpers

  function toast(message, kind = "") {
    const el = $("#toast");
    el.textContent = message;
    el.dataset.kind = kind;
    el.hidden = false;
    clearTimeout(el._t);
    el._t = setTimeout(() => (el.hidden = true), 3400);
  }

  function plural(n, one, few, many) {
    const m10 = n % 10;
    const m100 = n % 100;
    if (n === 1) return one;
    if (m10 >= 2 && m10 <= 4 && !(m100 >= 12 && m100 <= 14)) return few;
    return many;
  }

  const runById = (id) => S.runs.find((r) => r.id === id) || null;
  const latestRun = () => S.runs[0] || null;

  async function loadFindings(id) {
    if (!id) return [];
    if (S.cache[id]) return S.cache[id];
    const data = await api(`/api/runs/${enc(id)}/findings`);
    S.cache[id] = Array.isArray(data) ? data : [];
    return S.cache[id];
  }

  async function loadTriage(id) {
    if (!id) return {};
    if (S.triage[id]) return S.triage[id];
    try {
      S.triage[id] = (await api(`/api/runs/${enc(id)}/triage`)) || {};
    } catch {
      S.triage[id] = {};
    }
    return S.triage[id];
  }

  const fkey = (f) => `${f.url}|${f.title}`;

  function parseFindings(logs) {
    const out = [];
    const seen = new Set();
    for (const line of logs || []) {
      const m = FIND_RE.exec(line);
      if (!m) continue;
      const key = `${m[2]}|${m[3]}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ severity: m[1], title: m[2], url: m[3] });
    }
    return out;
  }

  function sevCounts(list) {
    const c = { high: 0, medium: 0, low: 0, info: 0 };
    for (const f of list) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  }

  function stageStrip(stage, finished) {
    const idx = STAGES.findIndex(([k]) => k === stage);
    return `<ol class="stages" aria-label="Etapy skanu">${STAGES.map(([k, label], i) => {
      const state = finished || (idx > -1 && i < idx) ? "done" : idx === i ? "current" : "";
      return `<li class="stages__item" data-state="${state}"><span class="stages__n">${String(i + 1).padStart(2, "0")}</span>${label}</li>`;
    }).join("")}</ol>`;
  }

  function pill(job) {
    const status = job ? job.status : "idle";
    const label = job ? (STATUS[status] || status) : "bezczynny";
    return `<span class="pill" data-state="${status}" id="job-pill">${label}${
      job && job.status === "running" ? ` · ${job.elapsed}s` : ""
    }</span>`;
  }

  function empty(title, body, action = "") {
    return `<div class="empty"><p class="empty__title">${title}</p><p class="empty__body">${body}</p>${
      action ? `<div class="empty__actions">${action}</div>` : ""
    }</div>`;
  }

  function runOptions(selected) {
    return S.runs
      .map((r) => `<option value="${esc(r.id)}"${r.id === selected ? " selected" : ""}>${esc(r.target || r.id)} — ${esc(r.generated || "")}</option>`)
      .join("");
  }

  // ------------------------------------------------------------- shell

  function setChrome() {
    const name = routeName();
    $("#page-title").textContent = TITLES[name] || "bbhunter";
    document.title = `bbhunter — ${TITLES[name] || "dashboard"}`;
    document.querySelectorAll(".nav__link").forEach((a) => {
      const active = a.dataset.route === name;
      if (active) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    const p = $("#job-pill");
    if (p) p.outerHTML = pill(S.job);
    $("#rail-job").textContent = S.job ? `${S.job.target} · ${STATUS[S.job.status] || S.job.status}` : "bezczynny";
    const live = $("#nav-live");
    if (live) live.textContent = S.job && S.job.status === "running" ? "●" : "";
    $("#count-scans").textContent = S.runs.length ? String(S.runs.length) : "";
    const latest = latestRun();
    const total = latest ? Object.values(latest.counts || {}).reduce((a, b) => a + (typeof b === "number" ? 0 : 0), 0) : 0;
    const findings = latest
      ? (latest.counts.findings_high || 0) + (latest.counts.findings_medium || 0) + (latest.counts.findings_low || 0) + (latest.counts.findings_info || 0)
      : total;
    $("#count-findings").textContent = findings ? String(findings) : "";
    const newBtn = $("#new-scan-btn");
    if (newBtn) newBtn.hidden = name === "dashboard";
  }

  function routeName() {
    const raw = location.hash.replace(/^#\/?/, "");
    return raw.split("?")[0] || "dashboard";
  }

  function query() {
    const h = location.hash;
    const i = h.indexOf("?");
    return new URLSearchParams(i >= 0 ? h.slice(i + 1) : "");
  }

  async function refreshRuns() {
    try {
      S.runs = await api("/api/runs");
    } catch {}
  }

  // ------------------------------------------------------------- dashboard

  function quickStart() {
    const options = [`<option value="">Tylko ten cel</option>`]
      .concat(S.scopes.map((s) => `<option value="${esc(s.rules)}">${esc(s.name)}</option>`))
      .join("");
    const osint = !S.settings || S.settings.osint !== false;
    return `<section class="panel">
      <div class="panel__head"><h2>Nowy skan</h2><span class="meta">zakres egzekwowany przy starcie</span></div>
      <form id="quick-form" novalidate>
        <div class="form-grid">
          <div class="field"><label for="q-target">Cel</label>
            <input id="q-target" type="text" placeholder="example.com" autocomplete="off" spellcheck="false" required></div>
          <div class="field"><label for="q-scope">Zakres</label><select id="q-scope">${options}</select></div>
        </div>
        <div class="form-actions">
          <label class="check"><input type="checkbox" id="q-osint"${osint ? " checked" : ""}> OSINT</label>
          <label class="check"><input type="checkbox" id="q-brute"> Brute-force</label>
          <label class="check"><input type="checkbox" id="q-wayback"> Wayback</label>
          <button class="btn btn--primary" type="submit">Skanuj</button>
          <span class="hint">Puste pole zakresu = tylko ten cel. Limity z Ustawień.</span>
        </div>
        <p class="error" id="q-error" hidden></p>
      </form>
    </section>`;
  }

  function activePanel(job) {
    const findings = parseFindings(job.logs);
    const c = sevCounts(findings);
    const finished = job.status !== "running";
    const tail = (job.logs || []).slice(-4).join("\n");
    return `<section class="panel">
      <div class="run-head">
        <div><p class="run-head__target">${esc(job.target)}</p>
          <p class="meta">${finished ? STATUS[job.status] : "trwa"} · ${job.elapsed}s · ${num((job.logs || []).length)} linii logu</p></div>
        <div class="form-actions" style="margin:0">
          ${job.status === "running" ? `<button class="btn btn--danger" data-action="stop">Zatrzymaj</button>` : ""}
          ${job.report ? `<a class="btn btn--ghost" href="${esc(job.report)}" target="_blank" rel="noreferrer">Raport</a>` : ""}
          ${job.osint ? `<a class="btn btn--ghost" href="${esc(job.osint)}" target="_blank" rel="noreferrer">OSINT</a>` : ""}
          <a class="btn btn--ghost" href="#/live">Podgląd</a>
        </div>
      </div>
      ${stageStrip(job.stage, finished)}
      <p class="summary-line" style="margin-top:var(--space-4)">
        <span>wysokie <strong>${c.high}</strong></span><span>średnie <strong>${c.medium}</strong></span>
        <span>niskie <strong>${c.low}</strong></span><span>informacyjne <strong>${c.info}</strong></span>
      </p>
      ${tail ? `<pre class="log" style="margin-top:var(--space-4);max-height:90px">${esc(tail)}</pre>` : ""}
    </section>`;
  }

  function dashboardHtml() {
    const job = S.job;
    const active = job && job.status !== "done" ? job : null;
    return `${active ? `<div id="active-slot">${activePanel(active)}</div>` : ""}
      <div style="margin-block-start:${active ? "var(--space-4)" : "0"}">${quickStart()}</div>
      <div class="grid-2" style="margin-block-start:var(--space-4)">
        <section class="panel">
          <div class="panel__head"><h2>Ostatnie znaleziska</h2>${
            latestRun() ? `<a class="meta link" href="#/findings?run=${enc(latestRun().id)}">wszystkie</a>` : ""
          }</div>
          <div id="dash-findings"><p class="hint">Ładowanie…</p></div>
        </section>
        <section class="panel">
          <div class="panel__head"><h2>Skany</h2><a class="meta link" href="#/scans">historia</a></div>
          ${
            S.runs.length
              ? `<ul class="list">${S.runs
                  .slice(0, 5)
                  .map(
                    (r) => `<li class="list__row"><a href="#/findings?run=${enc(r.id)}">${esc(r.target || r.id)}</a>
                      <span class="list__meta">${esc(r.generated || "")}</span></li>`
                  )
                  .join("")}</ul>`
              : `<p class="hint">Brak przebiegów. Uruchom pierwszy skan.</p>`
          }
        </section>
      </div>`;
  }

  async function fillDashboard() {
    const run = latestRun();
    const slot = $("#dash-findings");
    if (!slot) return;
    if (!run) {
      slot.innerHTML = empty("Brak znalezisk", "Uruchom skan, żeby zobaczyć pierwsze ustalenia.", "");
      return;
    }
    try {
      const list = await loadFindings(run.id);
      const order = { high: 0, medium: 1, low: 2, info: 3 };
      const groups = new Map();
      for (const f of list) {
        const k = `${f.severity}|${f.title}`;
        const g = groups.get(k) || { ...f, hosts: new Set() };
        g.hosts.add(f.host);
        groups.set(k, g);
      }
      const top = [...groups.values()].sort((a, b) => order[a.severity] - order[b.severity]).slice(0, 6);
      slot.innerHTML = top.length
        ? `<ul class="list">${top
            .map(
              (g) => `<li class="list__row"><a href="#/findings?run=${enc(run.id)}&q=${enc(g.title)}">
              <span class="sev" data-sev="${esc(g.severity)}">${SEV[g.severity] || g.severity}</span>
              ${esc(g.title)}</a><span class="list__meta">${g.hosts.size} ${plural(g.hosts.size, "host", "hosty", "hostów")}</span></li>`
            )
            .join("")}</ul>`
        : `<p class="hint">Ten przebieg nie ma ustaleń.</p>`;
    } catch (e) {
      slot.innerHTML = `<p class="hint">${esc(e.message)}</p>`;
    }
  }

  // ------------------------------------------------------------- live

  function liveHtml() {
    const job = S.job;
    if (!job) {
      return `<section class="panel">${empty(
        "Nic nie jest uruchomione",
        "Uruchom skan z dashboardu, a etapy i dziennik pojawią się tutaj na żywo.",
        `<a class="btn btn--primary" href="#/dashboard">Nowy skan</a>`
      )}</section>`;
    }
    const findings = parseFindings(job.logs);
    const finished = job.status !== "running";
    return `<div id="live-root">
      <section class="panel">
        <div class="run-head">
          <div><p class="run-head__target">${esc(job.target)}</p>
            <p class="meta">${STATUS[job.status] || job.status} · ${job.elapsed}s</p></div>
          <div class="form-actions" style="margin:0">
            ${job.status === "running" ? `<button class="btn btn--danger" data-action="stop">Zatrzymaj</button>` : ""}
            ${job.report ? `<a class="btn btn--ghost" href="${esc(job.report)}" target="_blank" rel="noreferrer">Raport</a>` : ""}
            ${job.osint ? `<a class="btn btn--ghost" href="${esc(job.osint)}" target="_blank" rel="noreferrer">OSINT</a>` : ""}
          </div>
        </div>
        ${stageStrip(job.stage, finished)}
      </section>
      <div class="grid-2" style="margin-block-start:var(--space-4)">
        <section class="panel"><div class="panel__head"><h2>Dziennik</h2><span class="meta">${num((job.logs || []).length)} linii</span></div>
          <pre class="log" id="live-log">${esc((job.logs || []).join("\n"))}</pre></section>
        <section class="panel"><div class="panel__head"><h2>Znaleziska na żywo</h2><span class="meta">${findings.length}</span></div>
          ${findings.length ? `<ul class="list">${findings
            .slice(-14)
            .reverse()
            .map(
              (f) => `<li class="list__row"><span><span class="sev" data-sev="${esc(f.severity)}">${SEV[f.severity]}</span> ${esc(f.title)}</span>
              <span class="list__meta">${esc(f.url.replace(/^https?:\/\//, "").slice(0, 40))}</span></li>`
            )
            .join("")}</ul>` : `<p class="hint">Ustalenia pojawią się w miarę postępu.</p>`}
        </section>
      </div>
    </div>`;
  }

  function liveTick() {
    const root = $("#live-root");
    if (!root || !S.job) return;
    const log = $("#live-log");
    const atBottom = log && log.scrollTop + log.clientHeight >= log.scrollHeight - 40;
    root.outerHTML = liveHtml();
    const next = $("#live-log");
    if (next && (atBottom || !log)) next.scrollTop = next.scrollHeight;
  }

  // ------------------------------------------------------------- scans

  function scansHtml() {
    const job = S.job;
    const rows = S.runs
      .map(
        (r) => `<tr>
        <td><a href="#/findings?run=${enc(r.id)}">${esc(r.target || r.id)}</a></td>
        <td class="mono-cell">${esc(r.generated || "")}</td>
        <td class="num">${num(r.counts.live_hosts || 0)}</td>
        <td class="num">${num(
          (r.counts.findings_high || 0) + (r.counts.findings_medium || 0) + (r.counts.findings_low || 0) + (r.counts.findings_info || 0)
        )}</td>
        <td>${r.has_osint ? "tak" : "—"}</td>
        <td class="actions">
          <a href="#/findings?run=${enc(r.id)}">Znaleziska</a>
          <a href="/runs/${enc(r.id)}/report" target="_blank" rel="noreferrer">Raport</a>
          <a href="#/logs?run=${enc(r.id)}">Log</a>
        </td></tr>`
      )
      .join("");
    return `<section class="panel">
      <div class="panel__head"><h2>Przebiegi</h2><span class="meta">${S.runs.length}</span></div>
      ${job ? `<p class="summary-line" style="margin-block-end:var(--space-3)">
        <span>${esc(job.target)}</span><span>${STATUS[job.status] || job.status}</span><span>${job.elapsed}s</span>
        ${job.status === "running" ? `<button class="btn btn--sm btn--danger" data-action="stop">Zatrzymaj</button>` : ""}
      </p>` : ""}
      ${
        S.runs.length
          ? `<div class="table-wrap"><table class="table"><thead><tr><th>Cel</th><th>Data</th><th class="num">Hosty</th><th class="num">Ustalenia</th><th>OSINT</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
          : empty("Brak skanów", "Uruchom pierwszy skan, żeby zobaczyć historię.", `<a class="btn btn--primary" href="#/dashboard">Nowy skan</a>`)
      }
    </section>`;
  }

  // ------------------------------------------------------------- findings

  let findingsState = { run: null, all: [], triage: {}, loading: false };

  function findingsToolbar() {
    const f = S.filters;
    const sevChips = ["high", "medium", "low", "info"]
      .map(
        (s) => `<button class="chip" type="button" data-action="sev" data-sev="${s}" aria-pressed="${f.sev.has(s)}">${SEV[s]}</button>`
      )
      .join("");
    return `<div class="toolbar">
      <div class="field"><label for="f-run">Przebieg</label><select id="f-run">${runOptions(findingsState.run)}</select></div>
      <div class="field" style="flex:1"><label for="f-q">Szukaj</label><input id="f-q" type="text" placeholder="tytuł, host, URL" value="${esc(f.q)}"></div>
      <div class="field"><label for="f-status">Status</label>
        <select id="f-status">${["", "nowe", "zweryfikowane", "zgłoszone", "odrzucone"]
          .map((s) => `<option value="${s}"${f.status === s ? " selected" : ""}>${s || "wszystkie"}</option>`)
          .join("")}</select></div>
      <div class="form-actions" style="margin:0">${sevChips}</div>
    </div>`;
  }

  function findingsTable() {
    const f = S.filters;
    const q = f.q.trim().toLowerCase();
    const list = findingsState.all.filter((x) => {
      if (!f.sev.has(x.severity)) return false;
      const st = (findingsState.triage[fkey(x)] || {}).status || "nowe";
      if (f.status && st !== f.status) return false;
      if (!q) return true;
      return `${x.title} ${x.host} ${x.url}`.toLowerCase().includes(q);
    });
    if (!findingsState.all.length) {
      return empty("Brak ustaleń", "Ten przebieg nie zwrócił żadnych ustaleń.");
    }
    if (!list.length) {
      return empty("Nic nie pasuje", "Zmień filtry albo wyczyść wyszukiwanie.");
    }
    return `<div class="table-wrap table-wrap--tall"><table class="table">
      <thead><tr><th>Waga</th><th>Ustalenie</th><th>Host</th><th>Etap</th><th>Status</th></tr></thead>
      <tbody>${list
        .map(
          (x) => `<tr>
          <td><span class="sev" data-sev="${esc(x.severity)}">${SEV[x.severity] || x.severity}</span></td>
          <td><a href="#" data-action="finding" data-run="${esc(findingsState.run)}" data-key="${esc(fkey(x))}">${esc(x.title)}</a>
            <div class="mono-cell muted">${esc(x.url)}</div></td>
          <td class="mono-cell">${esc(x.host)}</td>
          <td class="mono-cell">${esc(x.stage || "")}</td>
          <td class="mono-cell">${esc((findingsState.triage[fkey(x)] || {}).status || "nowe")}</td></tr>`
        )
        .join("")}</tbody></table></div>`;
  }

  async function fillFindings() {
    const q = query();
    if (q.get("q") !== null) {
      S.filters.q = q.get("q");
      const input = $("#f-q");
      if (input) input.value = S.filters.q;
    }
    const run = q.get("run") || findingsState.run || (latestRun() && latestRun().id);
    findingsState.run = run;
    if (!run) return;
    findingsState.loading = true;
    try {
      const [all, triage] = await Promise.all([loadFindings(run), loadTriage(run)]);
      findingsState.all = all;
      findingsState.triage = triage;
    } catch (e) {
      toast(e.message, "error");
    }
    findingsState.loading = false;
    const table = $("#findings-table");
    if (table) table.innerHTML = findingsTable();
    const sel = $("#f-run");
    if (sel) sel.value = run;
  }

  function findingsHtml() {
    return `<section class="panel">
      <div class="panel__head"><h2>Znaleziska</h2><span class="meta">${esc(findingsState.run || "")}</span></div>
      ${findingsToolbar()}
      <div id="findings-table"><p class="hint">Ładowanie…</p></div>
    </section>`;
  }

  // ------------------------------------------------------------- targets

  function targetsHtml() {
    const editing = S.editingScope ? S.scopes.find((s) => s.id === S.editingScope) : null;
    const list = S.scopes.length
      ? `<ul class="list">${S.scopes
          .map(
            (s) => `<li class="list__row"><div>
              <a href="#" data-action="edit-scope" data-id="${esc(s.id)}">${esc(s.name)}</a>
              <div class="hint">${esc(s.rules.split("\n").filter(Boolean).slice(0, 3).join("  ·  "))}</div></div>
              <div class="list__meta">
                <button class="btn btn--sm btn--ghost" data-action="use-scope" data-id="${esc(s.id)}">Użyj</button>
                <button class="btn btn--sm btn--ghost" data-action="del-scope" data-id="${esc(s.id)}">Usuń</button>
              </div></li>`
          )
          .join("")}</ul>`
      : `<p class="hint">Brak zapisanych zakresów. Dodaj pierwszy po prawej.</p>`;
    return `<div class="grid-2">
      <section class="panel"><div class="panel__head"><h2>Zakresy</h2><span class="meta">${S.scopes.length}</span></div>${list}</section>
      <section class="panel"><div class="panel__head"><h2>${editing ? "Edytuj zakres" : "Nowy zakres"}</h2></div>
        <form id="scope-form">
          <div class="field"><label for="s-name">Nazwa</label><input id="s-name" type="text" value="${esc(editing ? editing.name : "")}" placeholder="np. gazeta.pl"></div>
          <div class="field" style="margin-block-start:var(--space-3)"><label for="s-rules">Reguły</label>
            <textarea id="s-rules" spellcheck="false" placeholder="example.com&#10;*.example.org&#10;!dev.example.com">${esc(editing ? editing.rules : "")}</textarea>
            <p class="hint">Jedna reguła na linię. <span class="mono">!host</span> wyklucza host z zakresu. Puste pole w skanie = tylko cel.</p></div>
          <div class="form-actions">
            <button class="btn btn--primary" type="submit">Zapisz zakres</button>
            ${editing ? `<button class="btn btn--ghost" type="button" data-action="cancel-scope">Anuluj</button>` : ""}
            <label class="btn btn--ghost" for="s-import">Import z pliku</label>
            <input id="s-import" type="file" accept=".txt,.list" hidden>
          </div>
        </form>
      </section>
    </div>`;
  }

  async function saveScopes() {
    const store = { scopes: S.scopes };
    await api("/api/scopes", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(store) });
  }

  // ------------------------------------------------------------- osint

  async function fillOsint() {
    const slot = $("#osint-body");
    if (!slot) return;
    const run = $("#o-run") ? $("#o-run").value : latestRun() && latestRun().id;
    if (!run) {
      slot.innerHTML = empty("Brak OSINT", "Uruchom skan z OSINT-em, żeby zobaczyć te dane.");
      return;
    }
    try {
      const d = await api(`/api/runs/${enc(run)}/osint`);
      const rdap = d.rdap
        ? `<section class="panel"><div class="panel__head"><h2>RDAP</h2></div>
            <dl class="kv"><dt>Rejestrator</dt><dd>${esc(d.rdap.registrar || "—")}</dd>
            <dt>Rejestracja</dt><dd>${esc(d.rdap.registered || "—")}</dd>
            <dt>Wygasa</dt><dd>${esc(d.rdap.expires || "—")}</dd>
            <dt>Nameservery</dt><dd>${esc((d.rdap.nameservers || []).join(", ") || "—")}</dd></dl></section>`
        : "";
      const asn = (d.asn || []).length
        ? `<section class="panel"><div class="panel__head"><h2>ASN i prefiksy</h2></div>
            <ul class="list">${d.asn
              .map((a) => `<li class="list__row"><span>AS${esc(a.asn)} ${esc(a.name)}</span><span class="list__meta">${esc(a.ip)} · ${esc((a.prefixes || []).join(", "))}</span></li>`)
              .join("")}</ul></section>`
        : "";
      const cloud = (d.cloud || []).length
        ? `<section class="panel"><div class="panel__head"><h2>Kandydaci chmury</h2><span class="meta">własność niepotwierdzona</span></div>
            <div class="table-wrap"><table class="table"><thead><tr><th>Dostawca</th><th>Nazwa</th><th>Status</th><th>Typ</th></tr></thead><tbody>
            ${d.cloud.map((h) => `<tr><td>${esc(h.provider)}</td><td class="mono-cell">${esc(h.name)}</td><td class="num">${h.status}</td><td>${esc(h.kind)}</td></tr>`).join("")}
            </tbody></table></div></section>`
        : "";
      const fav = (d.favicons || []).length
        ? `<section class="panel"><div class="panel__head"><h2>Favicony</h2></div>
            <ul class="list">${d.favicons.map((g) => `<li class="list__row"><span class="mono-cell">${esc(g.hash)}</span><span class="list__meta">${esc((g.hosts || []).join(", "))}</span></li>`).join("")}</ul></section>`
        : "";
      const dorks = (d.dorks || []).length
        ? `<section class="panel"><div class="panel__head"><h2>Dorki</h2></div>
            <ul class="list">${d.dorks.map((x) => `<li class="list__row"><a href="${esc(x.url)}" target="_blank" rel="noreferrer">${esc(x.engine)} — ${esc(x.label)}</a></li>`).join("")}</ul></section>`
        : "";
      const code = (d.code_hits || []).length
        ? `<section class="panel"><div class="panel__head"><h2>Kod publiczny</h2></div>
            <ul class="list">${d.code_hits.map((x) => `<li class="list__row"><a href="${esc(x.url)}" target="_blank" rel="noreferrer">${esc(x.repo)}</a><span class="list__meta">${esc(x.path)}</span></li>`).join("")}</ul></section>`
        : "";
      const notes = (d.notes || []).length
        ? `<section class="panel"><div class="panel__head"><h2>Uwagi</h2></div><ul class="list">${d.notes.map((n) => `<li class="list__row"><span>${esc(n)}</span></li>`).join("")}</ul></section>`
        : "";
      slot.innerHTML = [rdap, asn, cloud, fav, dorks, code, notes].filter(Boolean).join("") || empty("Pusto", "Ten przebieg nie ma danych OSINT.");
    } catch {
      slot.innerHTML = empty("Brak OSINT", "Ten przebieg nie zawiera danych OSINT.");
    }
  }

  // ------------------------------------------------------------- reports

  function reportsHtml() {
    const rows = S.runs
      .map(
        (r) => `<tr><td><a href="#/findings?run=${enc(r.id)}">${esc(r.target || r.id)}</a></td>
        <td class="mono-cell">${esc(r.generated || "")}</td>
        <td class="actions">
          <a href="/runs/${enc(r.id)}/report" target="_blank" rel="noreferrer">HTML</a>
          <a href="/runs/${enc(r.id)}/markdown" target="_blank" rel="noreferrer">Markdown</a>
          <a href="/api/runs/${enc(r.id)}/findings" target="_blank" rel="noreferrer">JSON</a>
          <button data-action="template" data-run="${esc(r.id)}">Szablon</button>
        </td></tr>`
      )
      .join("");
    return `<section class="panel"><div class="panel__head"><h2>Raporty</h2><span class="meta">${S.runs.length}</span></div>
      ${
        S.runs.length
          ? `<div class="table-wrap"><table class="table"><thead><tr><th>Cel</th><th>Data</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
             <p class="hint" style="margin-block-start:var(--space-3)">„Szablon” kopiuje markdown z czołowymi ustaleniami — wklejasz do HackerOne albo Bugcrowd.</p>`
          : empty("Brak raportów", "Raport powstaje po pierwszym skanie.")
      }</section>`;
  }

  async function copyTemplate(runId) {
    const run = runById(runId);
    const findings = await loadFindings(runId);
    const top = findings
      .filter((f) => f.severity === "high" || f.severity === "medium")
      .slice(0, 8)
      .map((f) => `- **${SEV[f.severity]}** — ${f.title}\n  - URL: ${f.url}\n  - Host: ${f.host}\n  - Dowód: ${String(f.evidence || "").slice(0, 300)}`)
      .join("\n");
    const md = `# ${run ? run.target : runId} — rekonesans\n\nZakres: ${run ? run.target : ""}\n\n## Ustalenia do potwierdzenia\n\n${top || "Brak ustaleń wysokich/średnich."}\n\n_Wygenerowane przez bbhunter. Wyniki wymagają ręcznego potwierdzenia._\n`;
    await navigator.clipboard.writeText(md);
    toast("Szablon skopiowany do schowka");
  }

  // ------------------------------------------------------------- modules

  function modulesHtml() {
    const s = S.settings || {};
    const on = (v) => (v === false ? "" : " checked");
    return `<div class="grid-2">
      <section class="panel"><div class="panel__head"><h2>Etapy</h2><span class="meta">domyślne dla nowych skanów</span></div>
        <form id="modules-form">
          <label class="check" style="min-height:44px"><input type="checkbox" id="m-osint"${on(s.osint)}> OSINT — RDAP, ASN, archiwa, chmura, favicony</label>
          <label class="check" style="min-height:44px"><input type="checkbox" id="m-recurse"${on(s.recursion)}> Rekurencja — nowe hosty wchodzą do kolejnej rundy</label>
          <label class="check" style="min-height:44px"><input type="checkbox" id="m-paths"${on(s.paths)}> Ścieżki — well-known pliki i katalogi</label>
          <div class="field" style="margin-block-start:var(--space-3)"><label for="m-extra">Własne ścieżki</label>
            <textarea id="m-extra" spellcheck="false" placeholder="/internal/debug&#10;/.well-known/security.txt">${esc((s.extra_paths || []).join("\n"))}</textarea>
            <p class="hint">Jedna ścieżka na linię, musi zaczynać się od <span class="mono">/</span>. Sprawdzane jednym GET-em, bez walidacji treści.</p></div>
          <div class="form-actions"><button class="btn btn--primary" type="submit">Zapisz moduły</button></div>
        </form>
      </section>
      <section class="panel"><div class="panel__head"><h2>Sygnatury i DSL</h2></div>
        <p class="hint">Silnik ma dziś stały zestaw sprawdzeń (nagłówki, cookies, CORS, well-known ścieżki, sekrety w JS). Własne ścieżki powyżej to pierwszy krok.</p>
        <p class="hint" style="margin-block-start:var(--space-3)">DSL reguł (match na odpowiedzi, ekstrakcja dowodu, waga) jest zaplanowany — nie udaję, że działa.</p>
      </section>
    </div>`;
  }

  async function saveModules() {
    const settings = {
      ...(S.settings || {}),
      osint: $("#m-osint").checked,
      recursion: $("#m-recurse").checked,
      paths: $("#m-paths").checked,
      extra_paths: $("#m-extra").value.split("\n").map((x) => x.trim()).filter((x) => x.startsWith("/")),
    };
    await putSettings(settings);
  }

  // ------------------------------------------------------------- settings

  function settingsHtml() {
    const s = S.settings || {};
    const keyRow = (label, ok) => `<li class="list__row"><span>${label}</span><span class="list__meta">${ok ? "ustawiony" : "brak"}</span></li>`;
    return `<div class="grid-2">
      <section class="panel"><div class="panel__head"><h2>Limity</h2></div>
        <form id="settings-form">
          <div class="form-grid">
            <div class="field"><label for="st-rate">Req/s</label><input id="st-rate" type="number" min="1" max="500" value="${s.rate ?? 25}"></div>
            <div class="field"><label for="st-conc">Współbieżność</label><input id="st-conc" type="number" min="1" max="200" value="${s.concurrency ?? 20}"></div>
            <div class="field"><label for="st-timeout">Timeout (s)</label><input id="st-timeout" type="number" min="1" max="120" value="${s.timeout ?? 10}"></div>
            <div class="field"><label for="st-pages">Stron na host</label><input id="st-pages" type="number" min="1" max="200" value="${s.max_pages ?? 30}"></div>
            <div class="field"><label for="st-hosts">Limit hostów</label><input id="st-hosts" type="number" min="1" max="5000" value="${s.max_hosts ?? 500}"></div>
            <div class="field"><label for="st-depth">Głębokość</label><input id="st-depth" type="number" min="0" max="5" value="${s.depth ?? 2}"></div>
          </div>
          <div class="field" style="margin-block-start:var(--space-3)"><label for="st-proxy">Proxy</label>
            <input id="st-proxy" type="text" placeholder="http://127.0.0.1:8080" value="${esc(s.proxy || "")}">
            <p class="hint">Puste = bez proxy. Wpisz adres Burpa, żeby oglądać ruch.</p></div>
          <div class="form-actions"><button class="btn btn--primary" type="submit">Zapisz ustawienia</button></div>
        </form>
      </section>
      <section class="panel"><div class="panel__head"><h2>Klucze API</h2><span class="meta">z env serwera</span></div>
        <ul class="list">
          ${keyRow("Shodan", S.keys.shodan)}
          ${keyRow("SecurityTrails", S.keys.securitytrails)}
          ${keyRow("VirusTotal", S.keys.virustotal)}
          ${keyRow("GitHub", S.keys.github)}
        </ul>
        <p class="hint" style="margin-block-start:var(--space-3)">Ustaw w środowisku, w którym startuje <span class="mono">bbhunter serve</span>: <span class="mono">SHODAN_API_KEY</span>, <span class="mono">SECURITYTRAILS_API_KEY</span>, <span class="mono">VT_API_KEY</span>, <span class="mono">GITHUB_TOKEN</span>.</p>
      </section>
    </div>`;
  }

  async function putSettings(settings) {
    S.settings = await api("/api/settings", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(settings) });
    toast("Ustawienia zapisane");
  }

  // ------------------------------------------------------------- logs

  async function fillLogs() {
    const pre = $("#logs-pre");
    if (!pre) return;
    const q = query();
    const run = q.get("run") || (latestRun() && latestRun().id);
    const sel = $("#l-run");
    if (sel && run) sel.value = run;
    if (S.job && S.job.status === "running" && $("#l-live") && $("#l-live").checked) {
      pre.textContent = (S.job.logs || []).join("\n");
      return;
    }
    if (!run) {
      pre.textContent = "Brak logów.";
      return;
    }
    try {
      pre.textContent = await api(`/api/runs/${enc(run)}/log`);
    } catch {
      pre.textContent = "Ten przebieg nie ma zapisanego logu (starsze skany).";
    }
  }

  function logsHtml() {
    return `<section class="panel">
      <div class="panel__head"><h2>Logi</h2><span class="meta">surowy przebieg</span></div>
      <div class="toolbar">
        <div class="field"><label for="l-run">Przebieg</label><select id="l-run">${runOptions("")}</select></div>
        <label class="check"><input type="checkbox" id="l-live"${S.job && S.job.status === "running" ? " checked" : ""}> bieżący skan</label>
      </div>
      <pre class="log" id="logs-pre" style="max-height:600px">Ładowanie…</pre>
    </section>`;
  }

  // ------------------------------------------------------------- drawer

  async function openFinding(runId, key, idx) {
    try {
      const [findings, triage] = await Promise.all([loadFindings(runId), loadTriage(runId)]);
      let f = null;
      if (key) f = findings.find((x) => fkey(x) === key);
      else if (idx != null) f = findings[idx];
      if (!f) {
        toast("Nie znaleziono ustalenia", "error");
        return;
      }
      const k = fkey(f);
      const entry = triage[k] || { status: "nowe", notes: "" };
      const drawer = $("#drawer");
      $("#drawer-title").textContent = f.title;
      $("#drawer-body").innerHTML = `
        <dl class="kv">
          <dt>Waga</dt><dd><span class="sev" data-sev="${esc(f.severity)}">${SEV[f.severity] || f.severity}</span></dd>
          <dt>Kategoria</dt><dd class="mono">${esc(f.category || "")}</dd>
          <dt>Host</dt><dd class="mono">${esc(f.host)}</dd>
          <dt>Etap</dt><dd class="mono">${esc(f.stage || "")}</dd>
          <dt>URL</dt><dd><a class="link" href="${esc(f.url)}" target="_blank" rel="noreferrer">${esc(f.url)}</a></dd>
        </dl>
        <div><p class="field__label" style="margin-block-end:var(--space-2)">Dowód</p>
          <div class="evidence">${esc(f.evidence || "—")}</div></div>
        <div class="form-grid">
          <div class="field"><label for="t-status">Status</label>
            <select id="t-status">${["nowe", "zweryfikowane", "zgłoszone", "odrzucone"]
              .map((s) => `<option value="${s}"${entry.status === s ? " selected" : ""}>${s}</option>`)
              .join("")}</select></div>
          <div class="field"><label for="t-notes">Notatki</label><textarea id="t-notes" rows="3">${esc(entry.notes || "")}</textarea></div>
        </div>
        <div class="form-actions">
          <button class="btn btn--primary" data-action="save-triage" data-run="${esc(runId)}" data-key="${esc(k)}">Zapisz triage</button>
          <button class="btn btn--ghost" data-action="copy-curl" data-url="${esc(f.url)}">Kopiuj curl</button>
          <button class="btn btn--ghost" data-action="copy-finding" data-run="${esc(runId)}" data-key="${esc(k)}">Kopiuj markdown</button>
        </div>`;
      drawer.hidden = false;
      $("#scrim").hidden = false;
      S.drawerFocus = document.activeElement;
      $("#drawer-close").focus();
    } catch (e) {
      toast(e.message, "error");
    }
  }

  function closeDrawer() {
    $("#drawer").hidden = true;
    $("#scrim").hidden = true;
    if (S.drawerFocus && S.drawerFocus.focus) S.drawerFocus.focus();
  }

  async function saveTriage(runId, key) {
    const status = $("#t-status").value;
    const notes = $("#t-notes").value;
    const map = (await loadTriage(runId)) || {};
    map[key] = { status, notes };
    S.triage[runId] = map;
    await api(`/api/runs/${enc(runId)}/triage`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(map),
    });
    toast("Triage zapisany");
    if (routeName() === "findings") {
      findingsState.triage = map;
      const table = $("#findings-table");
      if (table) table.innerHTML = findingsTable();
    }
  }

  // ------------------------------------------------------------- render

  function render() {
    const name = routeName();
    const view = $("#view");
    const html = {
      dashboard: dashboardHtml,
      live: liveHtml,
      scans: scansHtml,
      targets: targetsHtml,
      findings: findingsHtml,
      osint: () =>
        `<section class="panel"><div class="panel__head"><h2>OSINT</h2><div class="field" style="min-width:260px"><label for="o-run">Przebieg</label><select id="o-run">${runOptions(
          latestRun() ? latestRun().id : ""
        )}</select></div></div><div id="osint-body"><p class="hint">Ładowanie…</p></div></section>`,
      reports: reportsHtml,
      modules: modulesHtml,
      settings: settingsHtml,
      logs: logsHtml,
    }[name] || dashboardHtml;
    view.innerHTML = html();
    setChrome();
    if (name === "dashboard") fillDashboard();
    if (name === "findings") fillFindings();
    if (name === "osint") fillOsint();
    if (name === "logs") fillLogs();
    if (name === "dashboard" && S.pendingScope) {
      const sel = $("#q-scope");
      if (sel) sel.value = S.pendingScope;
      S.pendingScope = null;
    }
  }

  function renderRoute() {
    render();
    $("#view").focus({ preventScroll: true });
  }

  // ------------------------------------------------------------- events

  document.addEventListener("click", async (e) => {
    const t = e.target.closest("[data-action]");
    if (!t) return;
    const a = t.dataset.action;
    try {
      if (a === "stop") {
        await api("/api/scan/stop", { method: "POST" });
        toast("Zatrzymuję po bieżącym etapie");
        S.job = await api("/api/job");
        setChrome();
      } else if (a === "finding") {
        e.preventDefault();
        await openFinding(t.dataset.run, t.dataset.key || null, t.dataset.idx != null ? Number(t.dataset.idx) : null);
      } else if (a === "save-triage") {
        await saveTriage(t.dataset.run, t.dataset.key);
      } else if (a === "copy-curl") {
        await navigator.clipboard.writeText(`curl -sS -D - '${t.dataset.url}'`);
        toast("curl skopiowany");
      } else if (a === "copy-finding") {
        const f = (await loadFindings(t.dataset.run)).find((x) => fkey(x) === t.dataset.key);
        if (!f) return;
        await navigator.clipboard.writeText(
          `### ${f.title}\n\n- Waga: ${SEV[f.severity]}\n- Host: ${f.host}\n- URL: ${f.url}\n- Kategoria: ${f.category}\n\n${f.evidence || ""}\n`
        );
        toast("Ustalenie skopiowane");
      } else if (a === "template") {
        await copyTemplate(t.dataset.run);
      } else if (a === "edit-scope") {
        e.preventDefault();
        S.editingScope = t.dataset.id;
        render();
      } else if (a === "cancel-scope") {
        S.editingScope = null;
        render();
      } else if (a === "use-scope") {
        const s = S.scopes.find((x) => x.id === t.dataset.id);
        if (s) S.pendingScope = s.rules;
        location.hash = "#/dashboard?new=1";
      } else if (a === "del-scope") {
        const s = S.scopes.find((x) => x.id === t.dataset.id);
        if (!s || !confirm(`Usunąć zakres „${s.name}”?`)) return;
        S.scopes = S.scopes.filter((x) => x.id !== s.id);
        await saveScopes();
        if (S.editingScope === s.id) S.editingScope = null;
        render();
      }
    } catch (err) {
      toast(err.message, "error");
    }
  });

  document.addEventListener("submit", async (e) => {
    const form = e.target;
    try {
      if (form.id === "quick-form") {
        e.preventDefault();
        const target = $("#q-target").value.trim();
        const scope = $("#q-scope").value;
        const err = $("#q-error");
        err.hidden = true;
        if (!target) {
          err.textContent = "Podaj cel skanu.";
          err.hidden = false;
          $("#q-target").focus();
          return;
        }
        await api("/api/scan", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            target,
            scope,
            brute: $("#q-brute").checked,
            wayback: $("#q-wayback").checked,
            osint: $("#q-osint").checked,
          }),
        });
        S.job = await api("/api/job");
        toast("Skan uruchomiony");
        location.hash = "#/live";
      } else if (form.id === "scope-form") {
        e.preventDefault();
        const name = $("#s-name").value.trim();
        const rules = $("#s-rules").value.trim();
        if (!name || !rules) {
          toast("Nazwa i reguły są wymagane", "error");
          return;
        }
        const s = S.editingScope ? S.scopes.find((x) => x.id === S.editingScope) : { id: `s_${Date.now()}` };
        s.name = name;
        s.rules = rules;
        if (!S.scopes.some((x) => x.id === s.id)) S.scopes.push(s);
        await saveScopes();
        S.editingScope = null;
        toast("Zakres zapisany");
        render();
      } else if (form.id === "settings-form") {
        e.preventDefault();
        const settings = {
          ...(S.settings || {}),
          rate: Number($("#st-rate").value) || 25,
          concurrency: Number($("#st-conc").value) || 20,
          timeout: Number($("#st-timeout").value) || 10,
          max_pages: Number($("#st-pages").value) || 30,
          max_hosts: Number($("#st-hosts").value) || 500,
          depth: Number($("#st-depth").value) || 0,
          proxy: $("#st-proxy").value.trim() || null,
        };
        await putSettings(settings);
      } else if (form.id === "modules-form") {
        e.preventDefault();
        await saveModules();
      }
    } catch (err) {
      toast(err.message, "error");
    }
  });

  document.addEventListener("change", async (e) => {
    const t = e.target;
    try {
      if (t.id === "f-run") {
        location.hash = `#/findings?run=${enc(t.value)}`;
      } else if (t.id === "o-run") {
        fillOsint();
      } else if (t.id === "l-run" || t.id === "l-live") {
        fillLogs();
      } else if (t.id === "s-import" && t.files && t.files[0]) {
        const text = await t.files[0].text();
        $("#s-rules").value = text.trim();
      }
    } catch (err) {
      toast(err.message, "error");
    }
  });

  document.addEventListener("input", (e) => {
    if (e.target.id === "f-q") {
      S.filters.q = e.target.value;
      clearTimeout(window._fq);
      window._fq = setTimeout(() => {
        const table = $("#findings-table");
        if (table) table.innerHTML = findingsTable();
      }, 160);
    }
  });

  document.addEventListener("click", (e) => {
    const chip = e.target.closest('[data-action="sev"]');
    if (!chip) return;
    const sev = chip.dataset.sev;
    if (S.filters.sev.has(sev)) S.filters.sev.delete(sev);
    else S.filters.sev.add(sev);
    chip.setAttribute("aria-pressed", S.filters.sev.has(sev));
    const table = $("#findings-table");
    if (table) table.innerHTML = findingsTable();
  });

  document.addEventListener("change", (e) => {
    if (e.target.id === "f-status") {
      S.filters.status = e.target.value;
      const table = $("#findings-table");
      if (table) table.innerHTML = findingsTable();
    }
  });

  $("#drawer-close").addEventListener("click", closeDrawer);
  $("#scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !$("#drawer").hidden) closeDrawer();
  });
  window.addEventListener("hashchange", renderRoute);

  // ------------------------------------------------------------- polling

  async function poll() {
    try {
      const next = await api("/api/job");
      const before = S.job;
      S.job = next;
      setChrome();
      const running = next && next.status === "running";
      if (running && routeName() === "live") liveTick();
      if (running && routeName() === "dashboard") {
        const slot = $("#active-slot");
        if (slot) slot.innerHTML = activePanel(next);
        else render();
      }
      if (before && before.status === "running" && next && next.status !== "running") {
        await refreshRuns();
        render();
        const label = { done: "Skan zakończony", stopped: "Skan zatrzymany", error: "Skan zakończył się błędem" }[next.status] || "Skan zakończony";
        toast(label, next.status === "error" ? "error" : "");
      }
    } catch {}
  }

  // ------------------------------------------------------------- boot

  async function boot() {
    try {
      const [settings, scopes, runs, job, keys] = await Promise.all([
        api("/api/settings"),
        api("/api/scopes"),
        api("/api/runs"),
        api("/api/job"),
        api("/api/keys"),
      ]);
      S.settings = settings;
      S.scopes = (scopes && scopes.scopes) || [];
      S.runs = runs || [];
      S.job = job;
      S.keys = keys || {};
    } catch (e) {
      toast(`Nie mogę połączyć się z serwerem: ${e.message}`, "error");
    }
    renderRoute();
    setInterval(poll, 1000);
  }

  boot();
})();
