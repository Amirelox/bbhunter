// bbhunter — aplikacja. Bez frameworka, hash routing, dane z /api.
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
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
    dashboard: {
      title: "Przegląd",
      sub: "Postawa, zasięg i kolejka ostatnich przebiegów.",
      crumb: "workspace / przegląd",
    },
    live: { title: "Skan na żywo", sub: "Etapy, dziennik i ustalenia w trakcie przebiegu.", crumb: "workspace / skan na żywo" },
    scans: { title: "Skany", sub: "Historia przebiegów, hosty i ustalenia.", crumb: "workspace / skany" },
    targets: { title: "Cele i zakres", sub: "Zapisane zakresy i reguły, które blokują każdy request.", crumb: "workspace / cele" },
    findings: { title: "Znaleziska", sub: "Kolejka triage’u: waga, host, etap i status.", crumb: "workspace / znaleziska" },
    osint: { title: "OSINT", sub: "RDAP, ASN, favicony, powiązania i źródła publiczne.", crumb: "workspace / osint" },
    reports: { title: "Raporty", sub: "Gotowe raporty offline w HTML, Markdown i JSON.", crumb: "workspace / raporty" },
    modules: { title: "Moduły i reguły", sub: "Porty, TLS, wirtualne hosty, discovery i stały zestaw sprawdzeń.", crumb: "workspace / system" },
    settings: { title: "Ustawienia", sub: "Limity, proxy i klucze źródeł.", crumb: "workspace / system" },
    logs: { title: "Logi", sub: "Surowy przebieg skanu, linia po linii.", crumb: "workspace / system" },
  };

  const STAGES = [
    ["osint", "OSINT"],
    ["subs", "Subdomeny"],
    ["probe", "Probe"],
    ["crawl", "Crawl"],
    ["paths", "Ścieżki"],
    ["modules", "Moduły"],
  ];
  const SEV = { high: "wysokie", medium: "średnie", low: "niskie", info: "informacyjne" };
  const STAGE = { probe: "sonda", crawl: "crawl", paths: "ścieżki", ports: "porty", tls: "TLS", vhosts: "vhosty", discovery: "discovery" };
  const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
  const STATUS = { running: "w toku", done: "gotowe", error: "błąd", stopped: "zatrzymany" };
  const FIND_RE = /^\[!\]\s+(high|medium|low|info)\s{2,}(.+?)\s{2,}(\S+)\s*$/;

  const ICON = {
    shield:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M12 3 5 6v5c0 4.4 2.8 7.9 7 10 4.2-2.1 7-5.6 7-10V6l-7-3Z"/><path d="M9 12l2 2 4-4"/></svg>',
    server:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="4" y="4" width="16" height="7" rx="1"/><rect x="4" y="13" width="16" height="7" rx="1"/><path d="M8 7.5h.01M8 16.5h.01"/></svg>',
    activity:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M3 12h4l2.5-6 5 12 2.5-6h4"/></svg>',
    radar:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 12l5.6-5.6"/></svg>',
    check:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M4 12.5 9 17.5 20 6.5"/></svg>',
    alert:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M12 4 3 20h18L12 4Z"/><path d="M12 10v4M12 17.5h.01"/></svg>',
    search:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4.5 4.5"/></svg>',
    scope:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M4 8V5a1 1 0 0 1 1-1h3M20 8V5a1 1 0 0 0-1-1h-3M4 16v3a1 1 0 0 0 1 1h3M20 16v3a1 1 0 0 1-1 1h-3"/><circle cx="12" cy="12" r="3"/></svg>',
    report:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="M6 3h8l4 4v14H6V3Z"/><path d="M14 3v4h4M9 12h6M9 16h6"/></svg>',
  };

  const S = {
    settings: null,
    scopes: [],
    runs: [],
    job: null,
    keys: {},
    cache: {},
    triage: {},
    editingScope: null,
    filters: { sev: new Set(["high", "medium", "low", "info"]), status: "", q: "" },
    drawerFocus: null,
    scanQueue: [],
    scanTotal: 0,
    scanOpts: null,
    scanAbort: false,
    scanFailed: 0,
    scanError: "",
  };

  let findingsState = { run: null, all: [], triage: {}, loading: false, visible: 0, error: "" };

  // ------------------------------------------------------------- helpers

  function toast(message, kind = "") {
    const el = $("#toast");
    if (!el) return;
    el.textContent = message;
    el.dataset.kind = kind;
    el.hidden = false;
    el.style.animation = "none";
    void el.offsetWidth;
    el.style.animation = "";
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
  const fkey = (f) => `${f.url}|${f.title}`;
  const totalFindings = (c) =>
    ["findings_high", "findings_medium", "findings_low", "findings_info"].reduce((a, k) => a + Number((c || {})[k] || 0), 0);

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

  function pct(part, whole) {
    if (!whole) return 0;
    return Math.max(0, Math.min(100, Math.round((part / whole) * 100)));
  }

  function dateShort(value) {
    const m = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})/.exec(String(value || ""));
    return m ? `${m[3]}.${m[2]} · ${m[4]}:${m[5]}` : value || "—";
  }

  function dayShort(value) {
    const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(value || ""));
    return m ? `${m[3]}.${m[2]}` : "—";
  }

  function stageLabel(stage) {
    const found = STAGES.find(([k]) => k === stage);
    return found ? found[1] : "start";
  }

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

  function sevMix(counts) {
    const c = {
      high: Number(counts?.findings_high || 0),
      medium: Number(counts?.findings_medium || 0),
      low: Number(counts?.findings_low || 0),
      info: Number(counts?.findings_info || 0),
    };
    const total = c.high + c.medium + c.low + c.info;
    if (!total) return '<div class="kpi__mix" aria-hidden="true"></div>';
    return `<div class="kpi__mix" aria-hidden="true">${["high", "medium", "low", "info"]
      .filter((s) => c[s])
      .map((s) => `<span data-sev="${s}" style="width:${(c[s] / total) * 100}%"></span>`)
      .join("")}</div>`;
  }

  function severityStack(counts) {
    const c = {
      high: Number(counts?.findings_high || 0),
      medium: Number(counts?.findings_medium || 0),
      low: Number(counts?.findings_low || 0),
      info: Number(counts?.findings_info || 0),
    };
    if (!c.high && !c.medium && !c.low && !c.info) return '<span class="meta">—</span>';
    return `<div class="sev-stack">${["high", "medium", "low", "info"]
      .filter((s) => c[s])
      .map((s) => `<span class="sevnum" data-sev="${s}" title="${SEV[s]}: ${c[s]}">${c[s]}</span>`)
      .join("")}</div>`;
  }

  function empty(title, body, action = "", icon = "check") {
    return `<div class="empty"><span class="empty__icon">${ICON[icon] || ICON.check}</span>
      <p class="empty__title">${esc(title)}</p><p class="empty__body">${esc(body)}</p>
      ${action ? `<div class="empty__actions">${action}</div>` : ""}</div>`;
  }

  function runOptions(selected) {
    return S.runs
      .map(
        (r) =>
          `<option value="${esc(r.id)}"${r.id === selected ? " selected" : ""}>${esc(r.target || r.id)} — ${esc(dateShort(r.generated))}</option>`
      )
      .join("");
  }

  function pipeline(stage, finished) {
    const idx = STAGES.findIndex(([k]) => k === stage);
    return `<ol class="pipeline" aria-label="Etapy skanu">${STAGES.map(([k, label], i) => {
      const state = finished || (idx > -1 && i < idx) ? "done" : idx === i ? "current" : "";
      return `<li class="stage" data-state="${state}"><span class="stage__n">${String(i + 1).padStart(2, "0")}</span><span class="stage__label">${label}</span></li>`;
    }).join("")}</ol>`;
  }

  function statusBadge(status) {
    const cls = status === "running" || status === "done" ? " is-on" : status === "error" ? " is-error" : "";
    return `<span class="badge${cls}">${STATUS[status] || status}</span>`;
  }

  // ------------------------------------------------------------- shell

  function routeName() {
    const raw = location.hash.replace(/^#\/?/, "");
    return raw.split("?")[0] || "dashboard";
  }

  function query() {
    const h = location.hash;
    const i = h.indexOf("?");
    return new URLSearchParams(i >= 0 ? h.slice(i + 1) : "");
  }

  function updateJobPill() {
    const p = $("#job-pill");
    if (!p) return;
    const job = S.job;
    const state = job ? job.status : "idle";
    const label = !job
      ? "bezczynny"
      : job.status === "running"
        ? `w toku · ${job.elapsed}s`
        : STATUS[job.status] || job.status;
    p.dataset.state = state;
    p.innerHTML = `<span class="pill__dot" aria-hidden="true"></span>${esc(label)}`;
    p.title = job ? `${job.target} · ${STATUS[job.status] || job.status}` : "Brak aktywnego skanu";
  }

  function setChrome() {
    const name = routeName();
    const meta = TITLES[name] || TITLES.dashboard;
    const title = $("#page-title");
    const sub = $("#page-sub");
    const crumb = $("#page-crumb");
    if (title) title.textContent = meta.title;
    if (sub) sub.textContent = meta.sub;
    if (crumb) crumb.textContent = meta.crumb;
    document.title = `bbhunter — ${meta.title.toLowerCase()}`;

    $$("[data-route]").forEach((a) => {
      if (a.dataset.route === name) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    const more = $("#more");
    if (more) more.classList.toggle("is-active", ["live", "modules", "settings", "logs"].includes(name));

    updateJobPill();

    const newBtn = $('.subbar__right [data-action="new-scan"]');
    if (newBtn) {
      const busy = !!S.job && S.job.status === "running";
      newBtn.disabled = busy;
      newBtn.title = busy ? "Poczekaj na zakończenie bieżącego skanu" : "Uruchom nowy skan";
    }
  }

  async function refreshRuns() {
    try {
      S.runs = await api("/api/runs");
    } catch {}
  }

  function syncFindingsUrl() {
    if (routeName() !== "findings") return;
    const params = new URLSearchParams();
    if (findingsState.run) params.set("run", findingsState.run);
    if (S.filters.q.trim()) params.set("q", S.filters.q);
    if (S.filters.status) params.set("status", S.filters.status);
    if (S.filters.sev.size < 4) {
      params.set("sev", ["high", "medium", "low", "info"].filter((s) => S.filters.sev.has(s)).join(","));
    }
    const next = `#/findings${params.toString() ? `?${params}` : ""}`;
    if (location.hash !== next) history.replaceState(null, "", next);
  }

  function refreshFindingsChrome() {
    const table = $("#findings-table");
    if (!table) return;
    table.innerHTML = findingsTable();
    const count = $("#findings-count");
    if (count) {
      count.textContent = findingsState.all.length
        ? `${findingsState.visible} / ${findingsState.all.length}`
        : "0";
    }
    syncFindingsUrl();
  }

  // ------------------------------------------------------------- scan flow

  function scanScopeOptions(selected) {
    return [`<option value="">Tylko podane cele</option>`]
      .concat(
        S.scopes.map(
          (s) => `<option value="${esc(s.rules)}"${s.rules === selected ? " selected" : ""}>${esc(s.name)}</option>`
        )
      )
      .join("");
  }

  function openScan({ scope = "", target = "" } = {}) {
    const dialog = $("#scan-dialog");
    if (!dialog) return;
    if (S.job && S.job.status === "running") {
      toast("Skan już trwa. Poczekaj albo zatrzymaj bieżący przebieg.", "error");
      return;
    }
    $("#scan-scope").innerHTML = scanScopeOptions(scope);
    $("#scan-target").value = target;
    $("#scan-error").hidden = true;
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
    setTimeout(() => $("#scan-target")?.focus(), 30);
  }

  function closeScan() {
    const dialog = $("#scan-dialog");
    if (!dialog) return;
    if (typeof dialog.close === "function") dialog.close();
    else dialog.removeAttribute("open");
  }

  async function startNextScan() {
    if (S.scanAbort || !S.scanOpts || !S.scanQueue.length) return false;
    const target = S.scanQueue.shift();
    try {
      await api("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...S.scanOpts, target }),
      });
      S.job = await api("/api/job");
      if (routeName() !== "live") location.hash = "#/live";
      else render();
      if (S.scanTotal > 1) toast(`Skan ${S.scanTotal - S.scanQueue.length + 1}/${S.scanTotal}: ${target}`);
      return true;
    } catch (e) {
      S.scanError = `${target}: ${e.message}`;
      S.scanFailed += 1;
      toast(S.scanError, "error");
      if (S.scanQueue.length) return startNextScan();
      return false;
    }
  }

  // ------------------------------------------------------------- dashboard

  function kpiCards() {
    const run = latestRun();
    const c = run?.counts || {};
    const findings = totalFindings(c);
    const high = Number(c.findings_high || 0);
    const medium = Number(c.findings_medium || 0);
    const liveHosts = Number(c.live_hosts || 0);
    const subs = Number(c.subdomains || 0);
    const urls = Number(c.urls || 0);
    const osintRuns = S.runs.filter((r) => r.has_osint).length;
    const targets = new Set(S.runs.map((r) => r.target).filter(Boolean)).size;
    const osintPct = pct(osintRuns, S.runs.length);

    return `<div class="kpis" id="kpis">
      <article class="kpi kpi--attention">
        <div class="kpi__top"><span class="kpi__label" title="Wszystkie wagi z ostatniego przebiegu">Ustalenia <span class="kpi__period">/ ostatni</span></span><span class="kpi__icon">${ICON.shield}</span></div>
        <p class="kpi__value">${num(findings)}</p>
        <p class="kpi__foot"><span><strong>${num(high)}</strong> wysokich · <strong>${num(medium)}</strong> średnich</span>${
          run ? `<a class="link" href="#/findings?run=${enc(run.id)}">przejdź</a>` : ""
        }</p>
        ${sevMix(c)}
      </article>
      <article class="kpi">
        <div class="kpi__top"><span class="kpi__label">Hosty na żywo</span><span class="kpi__icon">${ICON.server}</span></div>
        <p class="kpi__value">${num(liveHosts)}</p>
        <p class="kpi__foot"><span>z ${num(subs)} subdomen</span><span>${num(urls)} URL</span></p>
      </article>
      <article class="kpi">
        <div class="kpi__top"><span class="kpi__label">Przebiegi</span><span class="kpi__icon">${ICON.activity}</span></div>
        <p class="kpi__value">${num(S.runs.length)}</p>
        <p class="kpi__foot"><span>${num(targets)} ${plural(targets, "cel", "cele", "celów")}</span><span>${num(osintRuns)} z OSINT</span></p>
      </article>
      <article class="kpi">
        <div class="kpi__top"><span class="kpi__label">Zasięg OSINT</span><span class="kpi__icon">${ICON.radar}</span></div>
        <p class="kpi__value">${num(osintPct)}<small>%</small></p>
        <p class="kpi__foot"><span>z danymi pasywnymi</span><span>${num(osintRuns)}/${num(S.runs.length)}</span></p>
      </article>
    </div>`;
  }

  function trendPanel() {
    const rows = [...S.runs].slice(0, 8).reverse();
    const max = Math.max(1, ...rows.map((r) => totalFindings(r.counts)));
    const body = rows.length
      ? `<div class="chart">${rows
          .map((r, i) => {
            const c = r.counts || {};
            const counts = {
              info: Number(c.findings_info || 0),
              low: Number(c.findings_low || 0),
              medium: Number(c.findings_medium || 0),
              high: Number(c.findings_high || 0),
            };
            const total = totalFindings(c);
            const segments = ["info", "low", "medium", "high"]
              .filter((s) => counts[s] > 0)
              .map((s) => `<span class="seg--${s}" style="height:${(counts[s] / max) * 100}%" title="${SEV[s]}: ${counts[s]}"></span>`)
              .join("");
            return `<div class="chart__col" title="${esc(r.target)} · ${esc(dateShort(r.generated))} · ${num(total)} ustaleń">
              <span class="chart__total">${total ? num(total) : ""}</span>
              <div class="chart__track"><div class="chart__stack" style="--i:${i}">${segments || '<span class="seg--info" style="height:2px;opacity:.35"></span>'}</div></div>
              <span class="chart__label">${dayShort(r.generated)}</span>
            </div>`;
          })
          .join("")}</div>
        <div class="chart__legend">
          ${["high", "medium", "low", "info"]
            .map((s) => `<span class="legend__item"><span class="legend__dot seg--${s}"></span>${SEV[s]}</span>`)
            .join("")}
        </div>`
      : `<div class="chart__empty">Wykres pojawi się po pierwszym przebiegu.</div>`;

    return `<section class="panel">
      <div class="panel__head">
        <div><p class="eyebrow">Aktywność</p><h2>Ustalenia w czasie</h2></div>
        <span class="meta">${rows.length ? `ostatnie ${rows.length} ${plural(rows.length, "przebieg", "przebiegi", "przebiegów")}` : "brak danych"}</span>
      </div>
      <div class="panel__body">${body}</div>
    </section>`;
  }

  function coveragePanel() {
    const run = latestRun();
    const c = run?.counts || {};
    const subs = Number(c.subdomains || 0);
    const live = Number(c.live_hosts || 0);
    const ratio = pct(live, subs);
    const dash = ((302 * ratio) / 100).toFixed(1);
    const secrets = Number(c.secrets || 0);
    return `<section class="panel">
      <div class="panel__head">
        <div><p class="eyebrow">Ostatni przebieg</p><h2>Zasięg powierzchni</h2></div>
        <span class="meta">${run ? esc(run.target || run.id) : "—"}</span>
      </div>
      <div class="panel__body">
        <div class="coverage">
          <div class="ring">
            <svg viewBox="0 0 120 120" aria-hidden="true">
              <circle class="ring__bg" cx="60" cy="60" r="48"></circle>
              <circle class="ring__fg" cx="60" cy="60" r="48" stroke-dasharray="${dash} 302"></circle>
            </svg>
            <div class="ring__center"><strong>${ratio}%</strong><span>hostów odpowiada</span></div>
          </div>
          <div class="cov-stats">
            <div class="cov-stat"><span class="cov-stat__label">Subdomeny</span><span class="cov-stat__value">${num(subs)}</span></div>
            <div class="cov-stat"><span class="cov-stat__label">Endpointy</span><span class="cov-stat__value">${num(c.endpoints || 0)}</span></div>
            <div class="cov-stat"><span class="cov-stat__label">Pliki JS</span><span class="cov-stat__value">${num(c.js_files || 0)}</span></div>
            <div class="cov-stat"><span class="cov-stat__label">Sekrety</span><span class="cov-stat__value${secrets ? " is-hot" : ""}">${num(secrets)}</span></div>
          </div>
        </div>
        <p class="panel__note">${run ? `${esc(run.target || run.id)} · ${esc(dateShort(run.generated))} · zakres egzekwowany` : "Brak przebiegów. Uruchom skan, żeby zobaczyć zasięg."}</p>
      </div>
    </section>`;
  }

  function attentionPanel() {
    const run = latestRun();
    return `<section class="panel">
      <div class="panel__head">
        <div><p class="eyebrow">Kolejka</p><h2>Wymaga uwagi</h2></div>
        ${run ? `<a class="meta link" href="#/findings?run=${enc(run.id)}">wszystkie →</a>` : ""}
      </div>
      <div class="panel__body" id="dash-attention">
        <div class="loading"><span></span><span></span><span></span><span></span></div>
      </div>
      <p class="panel__note">Wysokie przed średnimi. Status pochodzi z triage’u.</p>
    </section>`;
  }

  function activityPanel() {
    const rows = S.runs.slice(0, 5);
    const body = rows.length
      ? `<table class="mini-table">
          <thead><tr><th>Cel</th><th>Data</th><th>Ustalenia</th></tr></thead>
          <tbody>${rows
            .map(
              (r) => `<tr>
                <td><a href="#/findings?run=${enc(r.id)}">${esc(r.target || r.id)}</a></td>
                <td class="meta">${esc(dateShort(r.generated))}</td>
                <td>${severityStack(r.counts)}</td>
              </tr>`
            )
            .join("")}</tbody>
        </table>`
      : empty("Brak przebiegów", "Pierwszy skan uruchomisz przyciskiem w nagłówku.", `<button class="btn btn--primary btn--sm" data-action="new-scan">Nowy skan</button>`, "activity");
    return `<section class="panel">
      <div class="panel__head"><div><p class="eyebrow">Historia</p><h2>Ostatnie przebiegi</h2></div><a class="meta link" href="#/scans">skany →</a></div>
      <div class="panel__body">${body}</div>
    </section>`;
  }

  function scanBanner(job) {
    return `<div class="scan-banner">
      <span class="scan-banner__pulse" aria-hidden="true"></span>
      <span class="scan-banner__target">${esc(job.target)}</span>
      <span class="scan-banner__meta">${esc(stageLabel(job.stage))} · ${job.elapsed}s · ${num((job.logs || []).length)} linii</span>
      <div class="scan-banner__actions">
        <a class="btn btn--ghost btn--sm" href="#/live">Podgląd</a>
        <button class="btn btn--danger btn--sm" type="button" data-action="stop">Zatrzymaj</button>
      </div>
    </div>`;
  }

  function dashboardHtml() {
    const running = S.job && S.job.status === "running";
    return `<section class="dash" aria-label="Przegląd">
      ${running ? `<div id="active-scan">${scanBanner(S.job)}</div>` : ""}
      ${kpiCards()}
      <div class="dash__row">${trendPanel()}${coveragePanel()}</div>
      <div class="dash__row">${attentionPanel()}${activityPanel()}</div>
    </section>`;
  }

  async function fillDashboard() {
    const slot = $("#dash-attention");
    if (!slot) return;
    const run = latestRun();
    if (!run) {
      slot.innerHTML = empty("Brak ustaleń", "Uruchom pierwszy skan, żeby zobaczyć kolejkę triage’u.", "", "shield");
      return;
    }
    try {
      const [list, triage] = await Promise.all([loadFindings(run.id), loadTriage(run.id)]);
      if (!$("#dash-attention")) return;
      const groups = new Map();
      for (const f of list) {
        if (f.severity !== "high" && f.severity !== "medium") continue;
        const key = `${f.severity}|${f.title}`;
        const g = groups.get(key) || { ...f, hosts: new Set() };
        g.hosts.add(f.host);
        groups.set(key, g);
      }
      const top = [...groups.values()]
        .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))
        .slice(0, 5);
      if (!top.length) {
        slot.innerHTML = empty("Brak pilnych ustaleń", "Ostatni przebieg nie zwrócił nic wysokiego ani średniego.", "", "check");
        return;
      }
      slot.innerHTML = `<div class="attention">${top
        .map((g) => {
          const entry = triage[fkey(g)] || { status: "nowe" };
          const status = entry.status || "nowe";
          return `<a class="attention__row" href="#" data-action="finding" data-run="${esc(run.id)}" data-key="${esc(fkey(g))}">
            <span class="attention__rail" data-sev="${esc(g.severity)}"></span>
            <span class="attention__main"><span class="attention__title">${esc(g.title)}</span>
              <span class="attention__host">${esc(g.host)}${g.hosts.size > 1 ? ` +${g.hosts.size - 1}` : ""} · ${esc(g.category || g.stage || "")}</span></span>
            <span class="status" data-status="${esc(status)}">${esc(status)}</span>
          </a>`;
        })
        .join("")}</div>`;
    } catch (e) {
      if ($("#dash-attention")) {
        slot.innerHTML = empty("Nie udało się wczytać kolejki", e.message, `<button class="btn btn--ghost btn--sm" type="button" data-action="refresh-dashboard">Spróbuj ponownie</button>`, "alert");
      }
    }
  }

  // ------------------------------------------------------------- live

  function liveHtml() {
    const job = S.job;
    if (!job) {
      return `<section class="panel">${empty(
        "Nic nie jest uruchomione",
        "Uruchom skan, a etapy, dziennik i ustalenia pojawią się tutaj na żywo.",
        `<button class="btn btn--primary" data-action="new-scan">Nowy skan</button>`,
        "activity"
      )}</section>`;
    }
    const findings = parseFindings(job.logs);
    const finished = job.status !== "running";
    const endLabel = { done: "zakończono", stopped: "zatrzymano", error: "błąd" }[job.status];
    const counts = job.counts;
    const total = counts ? totalFindings(counts) : findings.length;
    return `<div id="live-root">
      <section class="panel">
        <div class="live-head">
          <div>
            <p class="eyebrow">przebieg</p>
            <div class="live-target"><strong>${esc(job.target)}</strong>${statusBadge(job.status)}</div>
            <div class="live-meta"><span>${endLabel ? esc(endLabel) : `etap: ${esc(stageLabel(job.stage))}`}</span><span>${job.elapsed}s</span><span>${num((job.logs || []).length)} linii</span><span>${num(total)} ustaleń</span></div>
          </div>
          <div class="form-actions" style="margin:0">
            ${job.status === "running" ? `<button class="btn btn--danger" type="button" data-action="stop">Zatrzymaj</button>` : ""}
            ${job.report ? `<a class="btn btn--ghost" href="${esc(job.report)}" target="_blank" rel="noreferrer">Raport</a>` : ""}
            ${job.osint ? `<a class="btn btn--ghost" href="${esc(job.osint)}" target="_blank" rel="noreferrer">OSINT</a>` : ""}
          </div>
        </div>
        ${pipeline(job.stage, finished)}
        ${job.error ? `<p class="error" style="margin-top:16px">${esc(job.error)}</p>` : ""}
      </section>
      <div class="live-grid">
        <section class="panel"><div class="panel__head"><h2>Dziennik</h2><span class="meta">${num((job.logs || []).length)} linii</span></div>
          <pre class="log" id="live-log">${esc((job.logs || []).join("\n")) || "Oczekiwanie na pierwsze linie…"}</pre></section>
        <section class="panel"><div class="panel__head"><h2>Ustalenia na żywo</h2><span class="meta">${num(findings.length)}</span></div>
          ${findings.length ? `<ul class="list">${findings
            .slice(-14)
            .reverse()
            .map(
              (f) => `<li class="list__row"><span><span class="sev" data-sev="${esc(f.severity)}">${SEV[f.severity]}</span> ${esc(f.title)}</span>
              <span class="list__meta">${esc(f.url.replace(/^https?:\/\//, "").slice(0, 46))}</span></li>`
            )
            .join("")}</ul>` : empty("Cisza", "Ustalenia pojawią się w miarę postępu.", "", "search")}
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
    const rows = S.runs
      .map(
        (r) => `<tr>
        <td class="target-cell"><a href="#/findings?run=${enc(r.id)}">${esc(r.target || r.id)}</a><span class="meta">#${esc(r.id.slice(0, 6))}</span></td>
        <td class="mono-cell">${esc(dateShort(r.generated))}</td>
        <td class="num">${num(r.counts.live_hosts || 0)}</td>
        <td>${severityStack(r.counts)}</td>
        <td>${r.has_osint ? '<span class="badge is-on">tak</span>' : '<span class="badge">—</span>'}</td>
        <td class="actions">
          <a href="#/findings?run=${enc(r.id)}">Znaleziska</a>
          ${r.has_osint ? `<a href="#/osint?run=${enc(r.id)}">OSINT</a>` : ""}
          ${r.has_report ? `<a href="/runs/${enc(r.id)}/report" target="_blank" rel="noreferrer">Raport</a>` : ""}
          <a href="#/logs?run=${enc(r.id)}">Log</a>
        </td></tr>`
      )
      .join("");
    const all = S.runs.reduce((a, r) => a + totalFindings(r.counts), 0);
    const hosts = S.runs.reduce((a, r) => a + Number(r.counts.live_hosts || 0), 0);
    const reports = S.runs.filter((r) => r.has_report).length;
    return `<section class="panel">
      <div class="panel__head"><div><p class="eyebrow">Archiwum</p><h2>Wszystkie przebiegi</h2></div><span class="meta">${S.runs.length} zapisanych</span></div>
      <div class="statline">
        <div class="statline__item"><span class="statline__value">${num(S.runs.length)}</span><span class="statline__label">przebiegów</span></div>
        <div class="statline__item"><span class="statline__value">${num(hosts)}</span><span class="statline__label">hostów łącznie</span></div>
        <div class="statline__item"><span class="statline__value">${num(all)}</span><span class="statline__label">ustaleń łącznie</span></div>
        <div class="statline__item"><span class="statline__value">${num(reports)}</span><span class="statline__label">raportów</span></div>
      </div>
      ${
        S.runs.length
          ? `<div class="table-wrap"><table class="table table--scans"><thead><tr><th>Cel</th><th>Data</th><th class="num">Hosty</th><th>Ustalenia</th><th>OSINT</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
          : empty("Brak skanów", "Uruchom pierwszy skan, żeby zobaczyć historię.", `<button class="btn btn--primary" data-action="new-scan">Nowy skan</button>`, "activity")
      }
    </section>`;
  }

  // ------------------------------------------------------------- findings

  function findingsToolbar() {
    const f = S.filters;
    const sevChips = ["high", "medium", "low", "info"]
      .map(
        (s) => `<button class="chip" type="button" data-action="sev" data-sev="${s}" aria-pressed="${f.sev.has(s)}">${SEV[s]}</button>`
      )
      .join("");
    return `<div class="toolbar">
      <div class="field" style="min-width:220px"><label for="f-run">Przebieg</label><select id="f-run">${runOptions(findingsState.run)}</select></div>
      <div class="field field--grow"><label for="f-q">Szukaj</label><input id="f-q" type="text" placeholder="tytuł, host, URL" value="${esc(f.q)}" autocomplete="off" spellcheck="false"></div>
      <div class="field" style="min-width:140px"><label for="f-status">Status</label>
        <select id="f-status">${["", "nowe", "zweryfikowane", "zgłoszone", "odrzucone"]
          .map((s) => `<option value="${s}"${f.status === s ? " selected" : ""}>${s || "wszystkie"}</option>`)
          .join("")}</select></div>
      <div class="chips">${sevChips}</div>
    </div>`;
  }

  function findingsTable() {
    if (findingsState.error) {
      findingsState.visible = 0;
      return empty("Nie udało się wczytać ustaleń", findingsState.error, `<button class="btn btn--ghost btn--sm" type="button" data-action="refresh-findings">Spróbuj ponownie</button>`, "alert");
    }
    const f = S.filters;
    const q = f.q.trim().toLowerCase();
    const list = findingsState.all.filter((x) => {
      if (!f.sev.has(x.severity)) return false;
      const st = (findingsState.triage[fkey(x)] || {}).status || "nowe";
      if (f.status && st !== f.status) return false;
      if (!q) return true;
      return `${x.title} ${x.host} ${x.url} ${x.category || ""}`.toLowerCase().includes(q);
    });
    findingsState.visible = list.length;
    if (!findingsState.all.length) {
      return empty("Brak ustaleń", "Ten przebieg nie zwrócił żadnych ustaleń.", "", "shield");
    }
    if (!list.length) {
      return empty("Nic nie pasuje", "Zmień filtry albo wyczyść wyszukiwanie.", `<button class="btn btn--ghost btn--sm" type="button" data-action="clear-filters">Wyczyść filtry</button>`, "search");
    }
    return `<div class="table-wrap table-wrap--tall"><table class="table table--findings">
      <thead><tr><th>Waga</th><th>Ustalenie</th><th>Host</th><th>Etap</th><th>Status</th></tr></thead>
      <tbody>${list
        .map(
          (x) => `<tr>
          <td><span class="sev" data-sev="${esc(x.severity)}">${SEV[x.severity] || x.severity}</span></td>
          <td><a class="finding-title" href="#" data-action="finding" data-run="${esc(findingsState.run)}" data-key="${esc(fkey(x))}">${esc(x.title)}</a>
            <span class="finding-url">${esc(x.url)}</span><span class="finding-host">${esc(x.host)} · ${esc(x.stage || "")}</span></td>
          <td class="mono-cell">${esc(x.host)}</td>
          <td class="mono-cell">${esc(STAGE[x.stage] || x.stage || "")}</td>
          <td><span class="status" data-status="${esc((findingsState.triage[fkey(x)] || {}).status || "nowe")}">${esc((findingsState.triage[fkey(x)] || {}).status || "nowe")}</span></td></tr>`
        )
        .join("")}</tbody></table></div>`;
  }

  async function fillFindings() {
    const q = query();
    S.filters.q = q.get("q") || "";
    const status = q.get("status") || "";
    S.filters.status = ["nowe", "zweryfikowane", "zgłoszone", "odrzucone"].includes(status) ? status : "";
    if (q.has("sev")) {
      S.filters.sev = new Set(
        q.get("sev").split(",").filter((s) => ["high", "medium", "low", "info"].includes(s))
      );
    } else {
      S.filters.sev = new Set(["high", "medium", "low", "info"]);
    }
    $$('[data-action="sev"]').forEach((chip) => {
      chip.setAttribute("aria-pressed", String(S.filters.sev.has(chip.dataset.sev)));
    });
    const statusSel = $("#f-status");
    if (statusSel) statusSel.value = S.filters.status;
    const run = q.get("run") || findingsState.run || (latestRun() && latestRun().id);
    if (findingsState.run !== run) {
      findingsState.all = [];
      findingsState.triage = {};
    }
    findingsState.run = run;
    if (!run) {
      const table = $("#findings-table");
      if (table) table.innerHTML = empty("Brak przebiegów", "Uruchom skan, żeby zbierać ustalenia.", `<button class="btn btn--primary" data-action="new-scan">Nowy skan</button>`, "shield");
      return;
    }
    findingsState.loading = true;
    findingsState.error = "";
    try {
      const [all, triage] = await Promise.all([loadFindings(run), loadTriage(run)]);
      findingsState.all = all;
      findingsState.triage = triage;
    } catch (e) {
      findingsState.all = [];
      findingsState.triage = {};
      findingsState.error = e.message;
      toast(e.message, "error");
    }
    findingsState.loading = false;
    const table = $("#findings-table");
    if (table) table.innerHTML = findingsTable();
    const count = $("#findings-count");
    if (count) count.textContent = findingsState.all.length ? `${findingsState.visible} / ${findingsState.all.length}` : "0";
    const sel = $("#f-run");
    if (sel) sel.value = run;
    const input = $("#f-q");
    if (input && input.value !== S.filters.q) input.value = S.filters.q;
    syncFindingsUrl();
  }

  function findingsHtml() {
    const runId = query().get("run") || findingsState.run || (latestRun() && latestRun().id) || "";
    const run = runById(runId);
    return `<section class="panel">
      <div class="panel__head"><div><p class="eyebrow">Triage</p><h2>Ustalenia</h2></div>
        <span class="meta" id="findings-count">${run ? esc(run.target || run.id) : "—"}</span></div>
      ${S.runs.length ? findingsToolbar() : ""}
      <div id="findings-table">${S.runs.length ? '<div class="loading"><span></span><span></span><span></span></div>' : empty("Brak przebiegów", "Uruchom skan, żeby zbierać ustalenia.", `<button class="btn btn--primary" data-action="new-scan">Nowy skan</button>`, "shield")}</div>
    </section>`;
  }

  // ------------------------------------------------------------- targets

  function targetsHtml() {
    const editing = S.editingScope ? S.scopes.find((s) => s.id === S.editingScope) : null;
    const list = S.scopes.length
      ? `<div class="scope-list">${S.scopes
          .map((s) => {
            const rules = s.rules.split("\n").map((x) => x.trim()).filter(Boolean);
            return `<article class="scope">
              <div class="scope__main">
                <h3><a href="#" data-action="edit-scope" data-id="${esc(s.id)}">${esc(s.name)}</a></h3>
                <p class="scope__meta">${rules.length} ${plural(rules.length, "reguła", "reguły", "reguł")} · zakres egzekwowany</p>
                <div class="scope__rules">${rules.slice(0, 3).map((r) => `<span>${esc(r)}</span>`).join("")}${rules.length > 3 ? `<span>+${rules.length - 3} więcej</span>` : ""}</div>
              </div>
              <div class="scope__actions">
                <button class="btn btn--sm btn--ghost" data-action="use-scope" data-id="${esc(s.id)}">Użyj</button>
                <button class="btn btn--sm btn--ghost" data-action="edit-scope" data-id="${esc(s.id)}">Edytuj</button>
                <button class="btn btn--sm btn--danger" data-action="del-scope" data-id="${esc(s.id)}">Usuń</button>
              </div>
            </article>`;
          })
          .join("")}</div>`
      : empty("Brak zakresów", "Dodaj pierwszy zakres po prawej, żeby wielokrotnie używać tych samych reguł.", "", "scope");
    return `<div class="split">
      <section class="panel"><div class="panel__head"><div><p class="eyebrow">Allowlist</p><h2>Zapisane zakresy</h2></div><span class="meta">${S.scopes.length}</span></div>${list}</section>
      <section class="panel"><div class="panel__head"><div><p class="eyebrow">Edycja</p><h2>${editing ? "Edytuj zakres" : "Nowy zakres"}</h2></div></div>
        <form id="scope-form">
          <div class="field"><label for="s-name">Nazwa</label><input id="s-name" type="text" value="${esc(editing ? editing.name : "")}" placeholder="np. acme.test" autocomplete="off"></div>
          <div class="field" style="margin-block-start:12px"><label for="s-rules">Reguły</label>
            <textarea id="s-rules" spellcheck="false" placeholder="example.com&#10;*.example.org&#10;!dev.example.com">${esc(editing ? editing.rules : "")}</textarea>
            <p class="hint">Jedna reguła na linię. <span class="mono">!host</span> wyklucza host. Puste pole w skanie = tylko cel.</p></div>
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
    const sel = $("#o-run");
    const run = sel ? sel.value : query().get("run") || (latestRun() && latestRun().id);
    if (!run) {
      slot.innerHTML = `<section class="panel panel--wide">${empty("Brak OSINT", "Uruchom skan z OSINT-em, żeby zobaczyć dane pasywne.", `<button class="btn btn--primary" data-action="new-scan">Nowy skan</button>`, "radar")}</section>`;
      return;
    }
    try {
      const d = await api(`/api/runs/${enc(run)}/osint`);
      const rdap = d.rdap
        ? `<section class="panel"><div class="panel__head"><h2>RDAP</h2><span class="meta">rejestracja</span></div>
            <dl class="kv"><dt>Rejestrator</dt><dd>${esc(d.rdap.registrar || "—")}</dd>
            <dt>Rejestracja</dt><dd>${esc(d.rdap.registered || "—")}</dd>
            <dt>Wygasa</dt><dd>${esc(d.rdap.expires || "—")}</dd>
            <dt>Nameservery</dt><dd>${esc((d.rdap.nameservers || []).join(", ") || "—")}</dd></dl></section>`
        : "";
      const asn = (d.asn || []).length
        ? `<section class="panel"><div class="panel__head"><h2>ASN i prefiksy</h2><span class="meta">${d.asn.length}</span></div>
            <ul class="list">${d.asn
              .map((a) => `<li class="list__row"><span>AS${esc(a.asn)} ${esc(a.name)}</span><span class="list__meta">${esc(a.ip)} · ${esc((a.prefixes || []).join(", "))}</span></li>`)
              .join("")}</ul></section>`
        : "";
      const cloud = (d.cloud || []).length
        ? `<section class="panel panel--wide"><div class="panel__head"><h2>Kandydaci chmury</h2><span class="meta">własność niepotwierdzona</span></div>
            <div class="table-wrap"><table class="table table--cloud"><thead><tr><th>Dostawca</th><th>Nazwa</th><th class="num">Status</th><th>Typ</th><th>Domena</th></tr></thead><tbody>
            ${d.cloud.map((h) => `<tr><td>${esc(h.provider)}</td><td class="mono-cell">${esc(h.name)}</td><td class="num">${esc(h.status)}</td><td>${esc(h.kind)}</td><td>${h.mentions_domain ? "tak" : "—"}</td></tr>`).join("")}
            </tbody></table></div></section>`
        : "";
      const related = (d.related || []).length
        ? `<section class="panel"><div class="panel__head"><h2>Powiązane hosty</h2><span class="meta">reverse IP + SAN</span></div>
            <ul class="list">${d.related
              .map((r) => `<li class="list__row"><span class="mono">${esc(r.name)}</span><span class="list__meta">${esc(r.source)}${r.in_scope ? " · w zakresie" : ""}</span></li>`)
              .join("")}</ul></section>`
        : "";
      const fav = (d.favicons || []).length
        ? `<section class="panel"><div class="panel__head"><h2>Favicony</h2><span class="meta">${d.favicons.length}</span></div>
            <ul class="list">${d.favicons.map((g) => `<li class="list__row"><span class="mono-cell">${esc(g.hash)}</span><span class="list__meta">${esc((g.hosts || []).join(", "))}</span></li>`).join("")}</ul></section>`
        : "";
      const dorks = (d.dorks || []).length
        ? `<section class="panel"><div class="panel__head"><h2>Dorki</h2><span class="meta">${d.dorks.length}</span></div>
            <ul class="list">${d.dorks.map((x) => `<li class="list__row"><a href="${esc(x.url)}" target="_blank" rel="noreferrer">${esc(x.engine)} — ${esc(x.label)}</a></li>`).join("")}</ul></section>`
        : "";
      const code = (d.code_hits || []).length
        ? `<section class="panel"><div class="panel__head"><h2>Kod publiczny</h2><span class="meta">${d.code_hits.length}</span></div>
            <ul class="list">${d.code_hits.map((x) => `<li class="list__row"><a href="${esc(x.url)}" target="_blank" rel="noreferrer">${esc(x.repo)}</a><span class="list__meta">${esc(x.path)}</span></li>`).join("")}</ul></section>`
        : "";
      const notes = (d.notes || []).length
        ? `<section class="panel panel--wide"><div class="panel__head"><h2>Uwagi</h2></div><ul class="list">${d.notes.map((n) => `<li class="list__row"><span>${esc(n)}</span></li>`).join("")}</ul></section>`
        : "";
      const summary = `<section class="panel panel--wide"><div class="statline" style="margin:0;padding:0;border:0">
        <div class="statline__item"><span class="statline__value">${num((d.subdomains || []).length)}</span><span class="statline__label">subdomen</span></div>
        <div class="statline__item"><span class="statline__value">${num((d.new_subdomains || []).length)}</span><span class="statline__label">nowych</span></div>
        <div class="statline__item"><span class="statline__value">${num((d.asn || []).length)}</span><span class="statline__label">${plural((d.asn || []).length, "wiersz ASN", "wiersze ASN", "wierszy ASN")}</span></div>
        <div class="statline__item"><span class="statline__value">${num((d.related || []).length)}</span><span class="statline__label">powiązanych hostów</span></div>
      </div></section>`;
      const body = [summary, rdap, asn, cloud, related, fav, dorks, code, notes].filter(Boolean).join("");
      slot.innerHTML = body || `<section class="panel panel--wide">${empty("Pusto", "Ten przebieg nie ma danych OSINT.", "", "radar")}</section>`;
    } catch {
      slot.innerHTML = `<section class="panel panel--wide">${empty("Brak OSINT", "Ten przebieg nie zawiera danych OSINT albo źródła nie odpowiedziały.", `<button class="btn btn--ghost btn--sm" type="button" data-action="refresh-osint">Spróbuj ponownie</button>`, "radar")}</section>`;
    }
  }

  // ------------------------------------------------------------- reports

  function reportsHtml() {
    const rows = S.runs
      .map(
        (r) => `<tr>
        <td class="target-cell"><a href="#/findings?run=${enc(r.id)}">${esc(r.target || r.id)}</a><span class="meta">#${esc(r.id.slice(0, 6))}</span></td>
        <td class="mono-cell">${esc(dateShort(r.generated))}</td>
        <td>${severityStack(r.counts)}</td>
        <td>${r.has_osint ? '<span class="badge is-on">OSINT</span>' : '<span class="badge">—</span>'}</td>
        <td class="actions">
          <a href="/runs/${enc(r.id)}/report" target="_blank" rel="noreferrer">HTML</a>
          <a href="/runs/${enc(r.id)}/markdown" target="_blank" rel="noreferrer">Markdown</a>
          <a href="/api/runs/${enc(r.id)}/findings" target="_blank" rel="noreferrer">JSON</a>
          <button type="button" data-action="template" data-run="${esc(r.id)}">Szablon</button>
        </td></tr>`
      )
      .join("");
    return `<section class="panel">
      <div class="panel__head"><div><p class="eyebrow">Dokumenty</p><h2>Biblioteka raportów</h2></div><span class="meta">${S.runs.length} przebiegów</span></div>
      ${
        S.runs.length
          ? `<div class="table-wrap"><table class="table table--reports"><thead><tr><th>Cel</th><th>Data</th><th>Ustalenia</th><th>OSINT</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
             <p class="hint" style="margin-block-start:12px">HTML jest pojedynczym plikiem offline. „Szablon” kopiuje markdown z czołowymi ustaleniami do HackerOne albo Bugcrowd.</p>`
          : empty("Brak raportów", "Raport powstaje po pierwszym skanie.", `<button class="btn btn--primary" data-action="new-scan">Nowy skan</button>`, "report")
      }
    </section>`;
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
    const onByDefault = (v) => (v === false ? "" : " checked");
    const row = (id, title, desc, checked, badge = "") => {
      const tag = badge ? "div" : "label";
      return `<${tag} class="module"><div class="module__text"><strong>${title}</strong><span>${desc}</span></div>${
        badge ? `<span class="badge is-on">${badge}</span>` : `<input class="switch" type="checkbox" id="${id}" role="switch" aria-label="${title}"${checked}>`
      }</${tag}>`;
    };
    return `<div class="split">
      <section class="panel"><div class="panel__head"><div><p class="eyebrow">Nowe skany</p><h2>Moduły zbierania</h2></div><span class="meta">zapisywane</span></div>
        <form id="modules-form">
          <div class="module-list">
            ${row("m-ports", "Skan portów i usług", "Async TCP connect na wspólnym zestawie portów, banner grabbing dla HTTP, SSH, FTP, SMTP i baz danych. To connect scan, nie surowy SYN — nie wymaga roota.", onByDefault(s.ports))}
            ${row("m-tls", "TLS i certyfikaty", "SAN, wystawca, ważność, negocjowana wersja i szyfr. Osobno sprawdzane przestarzałe TLS 1.0/1.1 oraz słabe szyfry.", onByDefault(s.tls))}
            ${row("m-vhosts", "Wirtualne hosty", "Host header na wspólnym IP: typowe etykiety, porównanie statusu, tytułu i rozmiaru z odpowiedzią bazową. Tylko hosty w zakresie.", onByDefault(s.vhosts))}
            ${row("m-discovery", "Content discovery", "Brute-force katalogów i plików z soft-404, rozszerzeniami backupów i limitem hostów. Osobny od stałej listy well-known.", onByDefault(s.discovery))}
            ${row("m-shots", "Zrzuty ekranu", "Headless Chromium na żywych hostach; miniatury trafiają do raportu, pełne PNG do katalogu screenshots/. Wymaga Chromium.", onByDefault(s.screenshots))}
          </div>
          <div class="form-grid" style="margin-block-start:16px">
            <div class="field"><label for="m-ports-list">Porty</label><input id="m-ports-list" type="text" value="${esc(s.ports_list || "")}" placeholder="puste = wspólny zestaw 34 portów" autocomplete="off" spellcheck="false"><p class="hint">Zakresy dozwolone: <span class="mono">80,443,8000-8100</span>.</p></div>
            <div class="field"><label for="m-extra">Własne ścieżki well-known</label><textarea id="m-extra" spellcheck="false" placeholder="/internal/debug&#10;/.well-known/security.txt">${esc((s.extra_paths || []).join("\n"))}</textarea><p class="hint">Jedna ścieżka na linię, musi zaczynać się od <span class="mono">/</span>.</p></div>
          </div>
          <div class="field" style="margin-block-start:12px"><label for="m-discovery-paths">Własna lista content discovery</label>
            <textarea id="m-discovery-paths" spellcheck="false" placeholder="/admin/&#10;/backup.zip&#10;api/docs">${esc((s.discovery_paths || []).join("\n"))}</textarea>
            <p class="hint">Puste = wbudowana lista. Wpisy bez <span class="mono">/</span> dostaną go automatycznie.</p></div>
          <p class="eyebrow" style="margin-block-start:18px">Fundament</p>
          <div class="module-list">
            ${row("m-osint", "OSINT", "RDAP, ASN, archiwa, chmura, favicony i dorki. Startuje przed probe, wzbogacanie po probe.", onByDefault(s.osint))}
            ${row("m-recurse", "Rekurencja", "Nowe hosty wchodzą do kolejnej rundy, dopóki mieszczą się w limicie.", onByDefault(s.recursion))}
            ${row("m-paths", "Ścieżki well-known", "Stała lista bezpiecznych plików i katalogów sprawdzana jednym GET-em.", onByDefault(s.paths))}
          </div>
          <p class="eyebrow" style="margin-block-start:18px">Pasywne, zawsze aktywne</p>
          <div class="module-list">
            ${row("", "Fingerprinting technologii", "Nagłówki, cookies, wzorce HTML oraz pliki JS/CSS i ścieżki statyczne z crawla.", "", "zawsze")}
            ${row("", "WAF / CDN", "Cloudflare, Akamai, CloudFront, Imperva, Fastly, Azure Front Door, F5 i inne — po nagłówkach, cookies i treści.", "", "zawsze")}
          </div>
          <div class="form-actions"><button class="btn btn--primary" type="submit">Zapisz moduły</button></div>
        </form>
      </section>
      <section class="panel"><div class="panel__head"><div><p class="eyebrow">Silnik</p><h2>Stałe sprawdzenia</h2></div><span class="meta">aktywne</span></div>
        <ul class="rule-list">
          <li>Nagłówki bezpieczeństwa i konfiguracja CSP</li>
          <li>Cookies bez flag oraz CORS</li>
          <li>Wystawione pliki well-known i konfiguracje</li>
          <li>Sekrety w publicznym JavaScripcie</li>
          <li>Technologie i wersje w odpowiedziach</li>
          <li>WAF/CDN po sygnaturach odpowiedzi</li>
        </ul>
        <div class="section-note"><strong>Wszystkie moduły są domyślnie włączone.</strong> Wyłącz je w razie potrzeby — port scan to connect scan, więc nie wymaga raw sockets. Zrzuty ekranu uruchamiają Chromium dla stron w zakresie, ale przeglądarka ładuje też ich zasoby — traktuj to jak wizytę w przeglądarce. DSL własnych reguł jest nadal zaplanowany.</div>
      </section>
    </div>`;
  }

  async function saveModules() {
    const lines = (id) => $(id).value.split("\n").map((x) => x.trim()).filter(Boolean);
    const settings = {
      ...(S.settings || {}),
      ports: $("#m-ports").checked,
      ports_list: $("#m-ports-list").value.trim(),
      tls: $("#m-tls").checked,
      vhosts: $("#m-vhosts").checked,
      discovery: $("#m-discovery").checked,
      discovery_paths: lines("#m-discovery-paths"),
      screenshots: $("#m-shots").checked,
      osint: $("#m-osint").checked,
      recursion: $("#m-recurse").checked,
      paths: $("#m-paths").checked,
      extra_paths: lines("#m-extra").filter((x) => x.startsWith("/")),
    };
    await putSettings(settings);
  }

  // ------------------------------------------------------------- settings

  function settingsHtml() {
    const s = S.settings || {};
    const keyRow = (label, ok) => `<li class="key-row"><span>${label}</span><span class="key-row__state${ok ? " is-on" : ""}">${ok ? "ustawiony" : "brak"}</span></li>`;
    return `<div class="split">
      <section class="panel"><div class="panel__head"><div><p class="eyebrow">Wydajność</p><h2>Limity przebiegu</h2></div><span class="meta">egzekwowane przez silnik</span></div>
        <form id="settings-form">
          <div class="field" style="margin-block-end:12px"><label for="st-profile">Profil szybkości</label>
            <select id="st-profile">
              <option value="">własny</option>
              <option value="fast">szybki — 100 req/s, 10 stron, głębokość 1</option>
              <option value="balanced">zbalansowany — 25 req/s, 30 stron, głębokość 2</option>
              <option value="deep">głęboki — 20 req/s, 80 stron, głębokość 3</option>
            </select>
            <p class="hint">Profil wypełnia limity; zapisz przyciskiem. Profil nie omija zakresu.</p></div>
          <div class="form-grid">
            <div class="field"><label for="st-rate">Req/s</label><input id="st-rate" type="number" min="1" max="500" value="${s.rate ?? 25}"></div>
            <div class="field"><label for="st-conc">Współbieżność</label><input id="st-conc" type="number" min="1" max="200" value="${s.concurrency ?? 20}"></div>
            <div class="field"><label for="st-timeout">Timeout (s)</label><input id="st-timeout" type="number" min="1" max="120" value="${s.timeout ?? 10}"></div>
            <div class="field"><label for="st-pages">Stron na host</label><input id="st-pages" type="number" min="1" max="200" value="${s.max_pages ?? 30}"></div>
            <div class="field"><label for="st-hosts">Limit hostów</label><input id="st-hosts" type="number" min="1" max="5000" value="${s.max_hosts ?? 500}"></div>
            <div class="field"><label for="st-depth">Głębokość</label><input id="st-depth" type="number" min="0" max="5" value="${s.depth ?? 2}"></div>
          </div>
          <div class="field" style="margin-block-start:12px"><label for="st-proxy">Proxy</label>
            <input id="st-proxy" type="text" placeholder="http://127.0.0.1:8080" value="${esc(s.proxy || "")}">
            <p class="hint">Puste = bez proxy. Wpisz adres Burpa, żeby oglądać ruch.</p></div>
          <div class="form-actions"><button class="btn btn--primary" type="submit">Zapisz ustawienia</button></div>
        </form>
      </section>
      <div class="stack">
        <section class="panel"><div class="panel__head"><div><p class="eyebrow">Źródła</p><h2>Klucze API</h2></div><span class="meta">env serwera</span></div>
          <ul class="key-list">
            ${keyRow("Shodan", S.keys.shodan)}
            ${keyRow("SecurityTrails", S.keys.securitytrails)}
            ${keyRow("VirusTotal", S.keys.virustotal)}
            ${keyRow("GitHub", S.keys.github)}
          </ul>
          <p class="hint">Ustaw przed startem <span class="mono">bbhunter serve</span>: <span class="mono">SHODAN_API_KEY</span>, <span class="mono">SECURITYTRAILS_API_KEY</span>, <span class="mono">VT_API_KEY</span>, <span class="mono">GITHUB_TOKEN</span>.</p>
        </section>
        <section class="panel"><div class="panel__head"><h2>Bezpieczeństwo</h2></div>
          <ul class="rule-list">
            <li>Zakres sprawdzany przed każdym requestem</li>
            <li>Serwer słucha tylko na localhost</li>
            <li>Dane skanów zostają w katalogu wyjściowym</li>
            <li>Brak zewnętrznego API poza jawnymi źródłami OSINT</li>
          </ul>
        </section>
      </div>
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
    const live = $("#l-live");
    if (S.job && S.job.status === "running" && live && live.checked) {
      pre.textContent = (S.job.logs || []).join("\n") || "Oczekiwanie na pierwsze linie…";
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
    if (!S.runs.length && !S.job) {
      return `<section class="panel">${empty("Brak logów", "Log pojawi się po pierwszym skanie.", `<button class="btn btn--primary" data-action="new-scan">Nowy skan</button>`, "report")}</section>`;
    }
    const selected = query().get("run") || (latestRun() && latestRun().id) || "";
    return `<section class="panel">
      <div class="panel__head"><div><p class="eyebrow">Surowy przebieg</p><h2>Logi</h2></div><span class="meta">run.log</span></div>
      <div class="toolbar">
        <div class="field field--wide"><label for="l-run">Przebieg</label><select id="l-run">${runOptions(selected)}</select></div>
        <label class="check"><input type="checkbox" id="l-live"${S.job && S.job.status === "running" ? " checked" : ""}> bieżący skan</label>
      </div>
      <pre class="log" id="logs-pre">Ładowanie…</pre>
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
          <dt>Kategoria</dt><dd class="mono">${esc(f.category || "—")}</dd>
          <dt>Host</dt><dd class="mono">${esc(f.host)}</dd>
          <dt>Etap</dt><dd class="mono">${esc(STAGE[f.stage] || f.stage || "—")}</dd>
          <dt>URL</dt><dd><a class="link" href="${esc(f.url)}" target="_blank" rel="noreferrer">${esc(f.url)}</a></dd>
        </dl>
        <div><p class="field__label" style="margin-block-end:8px">Dowód</p>
          <div class="evidence">${esc(f.evidence || "—")}</div></div>
        <div class="form-grid">
          <div class="field"><label for="t-status">Status</label>
            <select id="t-status">${["nowe", "zweryfikowane", "zgłoszone", "odrzucone"]
              .map((s) => `<option value="${s}"${entry.status === s ? " selected" : ""}>${s}</option>`)
              .join("")}</select></div>
          <div class="field"><label for="t-notes">Notatki</label><textarea id="t-notes" rows="3">${esc(entry.notes || "")}</textarea></div>
        </div>
        <div class="form-actions">
          <button class="btn btn--primary" type="button" data-action="save-triage" data-run="${esc(runId)}" data-key="${esc(k)}">Zapisz triage</button>
          <button class="btn btn--ghost" type="button" data-action="copy-curl" data-url="${esc(f.url)}">Kopiuj curl</button>
          <button class="btn btn--ghost" type="button" data-action="copy-finding" data-run="${esc(runId)}" data-key="${esc(k)}">Kopiuj markdown</button>
        </div>`;
      drawer.hidden = false;
      $("#scrim").hidden = false;
      document.body.classList.add("drawer-open");
      S.drawerFocus = document.activeElement;
      $("#drawer-close").focus();
    } catch (e) {
      toast(e.message, "error");
    }
  }

  function closeDrawer(restore = true) {
    const drawer = $("#drawer");
    if (!drawer || drawer.hidden) return;
    drawer.hidden = true;
    $("#scrim").hidden = true;
    document.body.classList.remove("drawer-open");
    if (restore && S.drawerFocus && S.drawerFocus.focus) S.drawerFocus.focus();
    S.drawerFocus = null;
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
      refreshFindingsChrome();
    }
    if (routeName() === "dashboard") fillDashboard();
  }

  // ------------------------------------------------------------- render

  function render() {
    const name = routeName();
    const view = $("#view");
    if (!view) return;
    const html = {
      dashboard: dashboardHtml,
      live: liveHtml,
      scans: scansHtml,
      targets: targetsHtml,
      findings: findingsHtml,
      osint: () => {
        const selected = query().get("run") || (latestRun() && latestRun().id) || "";
        return `<section class="panel osint-toolbar">
          <div class="osint-bar">
            <div class="field"><label for="o-run">Przebieg</label><select id="o-run">${runOptions(selected)}</select></div>
            <span class="meta">${S.runs.length ? "pasywne + wzbogacanie" : "brak danych"}</span>
          </div>
        </section>
        <div id="osint-body" class="osint-grid"><section class="panel panel--wide"><div class="loading"><span></span><span></span><span></span></div></section></div>`;
      },
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
  }

  function renderRoute() {
    closeDrawer(false);
    const more = $("#more");
    if (more) more.open = false;
    setMenu(false);
    render();
    const view = $("#view");
    if (view) {
      view.classList.remove("route-in");
      void view.offsetWidth;
      view.classList.add("route-in");
      view.focus({ preventScroll: true });
    }
    window.scrollTo(0, 0);
  }

  // ------------------------------------------------------------- menu

  function setMenu(open) {
    const btn = $("#menu-toggle");
    if (!btn) return;
    document.body.classList.toggle("menu-open", open);
    btn.setAttribute("aria-expanded", String(open));
    btn.textContent = open ? "Zamknij" : "Menu";
  }

  // ------------------------------------------------------------- events

  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-action]");
    if (!t) return;
    const a = t.dataset.action;
    (async () => {
      try {
        if (a === "new-scan") {
          openScan();
        } else if (a === "stop") {
          S.scanAbort = true;
          S.scanQueue = [];
          S.scanTotal = 0;
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
        } else if (a === "refresh-dashboard") {
          await fillDashboard();
        } else if (a === "refresh-osint") {
          await fillOsint();
        } else if (a === "refresh-findings") {
          await fillFindings();
        } else if (a === "clear-filters") {
          S.filters.q = "";
          S.filters.status = "";
          S.filters.sev = new Set(["high", "medium", "low", "info"]);
          refreshFindingsChrome();
          const input = $("#f-q");
          if (input) {
            input.value = "";
            input.focus();
          }
          const status = $("#f-status");
          if (status) status.value = "";
          $$('[data-action="sev"]').forEach((chip) => chip.setAttribute("aria-pressed", "true"));
        } else if (a === "edit-scope") {
          e.preventDefault();
          S.editingScope = t.dataset.id;
          render();
        } else if (a === "cancel-scope") {
          S.editingScope = null;
          render();
        } else if (a === "use-scope") {
          const s = S.scopes.find((x) => x.id === t.dataset.id);
          if (!s) return;
          const looksLikeDomain = /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s.name.trim());
          openScan({ scope: s.rules, target: looksLikeDomain ? s.name.trim() : "" });
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
    })();
  });

  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-close]")) closeScan();
  });

  document.addEventListener("submit", async (e) => {
    const form = e.target;
    try {
      if (form.id === "scan-form") {
        e.preventDefault();
        const target = $("#scan-target").value.trim();
        const err = $("#scan-error");
        err.hidden = true;
        if (!target) {
          err.textContent = "Podaj cel skanu.";
          err.hidden = false;
          $("#scan-target").focus();
          return;
        }
        const targets = [...new Set(target.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean))];
        S.scanQueue = targets;
        S.scanTotal = targets.length;
        S.scanFailed = 0;
        S.scanAbort = false;
        S.scanError = "";
        S.scanOpts = {
          scope: $("#scan-scope").value,
          brute: $("#scan-brute").checked,
          wayback: $("#scan-wayback").checked,
          osint: $("#scan-osint").checked,
        };
        const ok = await startNextScan();
        if (ok) {
          closeScan();
        } else {
          err.textContent = S.scanError || "Nie udało się uruchomić skanu.";
          err.hidden = false;
        }
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
      } else if (t.id === "st-profile") {
        const presets = {
          fast: { rate: 100, conc: 64, timeout: 6, pages: 10, hosts: 500, depth: 1 },
          balanced: { rate: 25, conc: 20, timeout: 10, pages: 30, hosts: 500, depth: 2 },
          deep: { rate: 20, conc: 24, timeout: 15, pages: 80, hosts: 1000, depth: 3 },
        };
        const p = presets[t.value];
        if (!p) return;
        $("#st-rate").value = p.rate;
        $("#st-conc").value = p.conc;
        $("#st-timeout").value = p.timeout;
        $("#st-pages").value = p.pages;
        $("#st-hosts").value = p.hosts;
        $("#st-depth").value = p.depth;
      } else if (t.id === "s-import" && t.files && t.files[0]) {
        $("#s-rules").value = (await t.files[0].text()).trim();
      }
    } catch (err) {
      toast(err.message, "error");
    }
  });

  document.addEventListener("input", (e) => {
    if (e.target.id === "f-q") {
      S.filters.q = e.target.value;
      clearTimeout(window._fq);
      window._fq = setTimeout(refreshFindingsChrome, 160);
    }
  });

  document.addEventListener("click", (e) => {
    const chip = e.target.closest('[data-action="sev"]');
    if (!chip) return;
    const sev = chip.dataset.sev;
    if (S.filters.sev.has(sev)) S.filters.sev.delete(sev);
    else S.filters.sev.add(sev);
    chip.setAttribute("aria-pressed", String(S.filters.sev.has(sev)));
    refreshFindingsChrome();
  });

  document.addEventListener("change", (e) => {
    if (e.target.id === "f-status") {
      S.filters.status = e.target.value;
      refreshFindingsChrome();
    }
  });

  $("#scan-dialog").addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closeScan();
  });
  $("#drawer-close").addEventListener("click", () => closeDrawer());
  $("#scrim").addEventListener("click", () => closeDrawer());
  $("#menu-toggle").addEventListener("click", () => setMenu(!document.body.classList.contains("menu-open")));

  document.addEventListener("click", (e) => {
    const more = $("#more");
    if (more && !e.target.closest("#more")) more.open = false;
    if (document.body.classList.contains("menu-open") && e.target.closest(".mainnav a")) setMenu(false);
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if ($("#drawer") && !$("#drawer").hidden) closeDrawer();
      if (document.body.classList.contains("menu-open")) setMenu(false);
    }
  });

  window.addEventListener("resize", () => {
    if (innerWidth > 860) setMenu(false);
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
        const slot = $("#active-scan");
        if (slot) slot.innerHTML = scanBanner(next);
        else render();
      }
      if (before && before.status === "running" && next && next.status !== "running") {
        await refreshRuns();
        if (["dashboard", "live", "scans", "reports"].includes(routeName())) render();
        else setChrome();
        const label = { done: "Skan zakończony", stopped: "Skan zatrzymany", error: "Skan zakończył się błędem" }[next.status] || "Skan zakończony";
        toast(label, next.status === "error" ? "error" : "");
        if (S.scanQueue.length) {
          if (next.status !== "stopped" && !S.scanAbort) setTimeout(() => startNextScan(), 500);
          else S.scanQueue = [];
        } else if (S.scanTotal > 1) {
          const failed = S.scanFailed;
          const total = S.scanTotal;
          S.scanTotal = 0;
          setTimeout(() => {
            toast(failed ? `Ukończono ${total} skanów, ${failed} błędów` : `Ukończono ${total} skanów`);
            location.hash = "#/scans";
          }, 700);
        }
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
