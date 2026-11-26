# bbhunter

All-in-one recon toolkit for bug bounty and pentests, **on targets you are allowed to test**.
One binary: passive subdomains → HTTP probe → crawl/JS → well-known paths → triage → report
(Markdown + HTML + JSON), plus a local browser app and an OSINT stage.

> This is not an exploit framework. It does recon and low-impact configuration checks
> (single GETs on well-known paths, headers, cookies, CORS). Every result is a lead for
> manual verification, not a confirmed vulnerability.

## Safety and scope

Every request goes through an allowlist (`--scope`). Without a scope file the tool **refuses to
run**, unless you explicitly pass `--no-scope-check` (lab/localhost only).

```txt
# scope.txt
example.com          # example.com and every subdomain
*.example.org        # glob
api-*.lab.net
!dev.example.com     # exclusion wins over an allow rule
```

Hosts outside the list are rejected before the request is sent, and passive enumeration results are
filtered again at the end. On top of that: a global rate limit, a concurrency cap, timeouts and hard
response size limits.

## Build

```bash
cargo build --release          # binary: target/release/bbhunter
cargo install --path .         # or into ~/.cargo/bin
```

Stable Rust (tested on 1.94). Network access to crt.sh, hackertarget, OTX, urlscan and
web.archive.org is required; some sources may be temporarily unavailable while the rest still work.

## Quick start

```bash
# browser app (dashboard, live log, report)
bbhunter serve --port 8080        # → http://127.0.0.1:8080

# full pipeline from the terminal
bbhunter recon -d example.com --scope scope.txt --brute --wayback -o ./out

# several domains: one report per domain, one shared rate limit
bbhunter recon -d example.com -d example.org --scope scope.txt
bbhunter recon -l targets.txt --scope scope.txt

# quick pass (higher rate, shallow crawl)
bbhunter recon -d example.com --scope scope.txt --profile fast

# single stages
bbhunter subs  -d example.com --scope scope.txt > subs.txt
bbhunter probe -l subs.txt --scope scope.txt
bbhunter crawl -l live_hosts.txt --scope scope.txt --max-pages 50
bbhunter paths -u https://example.com --scope scope.txt --limit 20
bbhunter urls  -d example.com --scope scope.txt > wayback.txt
```

Speed profiles: `--profile fast` (100 req/s, 64 workers, 10 pages, depth 1), `balanced` (the
defaults), `deep` (80 pages, depth 3). Explicit non-default flags win. Every run ends with a
per-stage timing line:

```
czasy: OSINT 1.2s · DNS 0.4s · probe 8.1s · crawl 24.0s · paths 6.3s · enrich 2.0s · razem 42.0s
```

Global flags: `--concurrency` (20), `--rate` req/s (25), `--timeout` (10 s), `-o/--out`, `-q`,
`--show-secrets`, `--proxy` (e.g. Burp) and `-H "Name: Value"` (auth/cookies, repeatable;
`BBHUNTER_PROXY` also works).

```bash
# through Burp, with a session
bbhunter recon -d example.com --scope scope.txt \
  --proxy http://127.0.0.1:8080 \
  -H "Cookie: session=..." -H "Authorization: Bearer ..."
```

## What `recon` does

| Stage | Module | Description |
|---|---|---|
| 1. Subdomains | `subs.rs` | crt.sh, hackertarget, AlienVault OTX, urlscan + optional brute force (built-in ~230-word list plus your own) with wildcard DNS detection |
| 2. Probe | `probe.rs` | HTTPS→HTTP fallback, status, title, tech fingerprint, IP/CNAME, header audit, cookies, CORS, error/stack-trace leaks |
| 3. Crawl | `crawl.rs` | same-host BFS, links/iframes/forms, JS bundles, endpoint extraction, secret regexes (AWS, Stripe, Google, GitHub, JWT, private keys, generic `api_key=`) |
| 4. Paths | `paths.rs` | fixed well-known list, one GET each: `.git`, `.env`, `.DS_Store`, `.svn`, `robots.txt`, `sitemap.xml`, `security.txt`, `server-status`, `phpinfo`, `actuator/*`, `metrics`, swagger/openapi, GraphQL, OIDC |
| 5. Wayback | `wayback.rs` | CDX API → historical URLs (filtered to scope) |
| 6. Triage | `triage.rs` | buckets: admin-panels, debug-staging, auth-endpoints, api-endpoints, payment-checkout, file-upload, redirect-params, urls-with-params, user-account |
| 7. Recursion | `pipeline.rs` | A host found in a link, JS file, robots/sitemap or redirect joins the next round and goes through the same stages. Bounded by `--depth` (2), `--max-hosts` (500); `--no-recurse` disables it |
| 8. Report | `report.rs` | `report.md`, `report.html`, `findings.json`, `hosts.jsonl`, per-bucket files |

Performance notes: pages inside a site are fetched in parallel batches, path checks run four at a
time per host, passive sources are concurrent and cached for 24 h, aliases are crawled once, and
OSINT enrichment (ASN/favicons) is parallel. Body reads are capped (512 KB for probe, 1 MB for
pages and JS).

Crawl and path checks **prioritise** dev/staging/admin/api hosts, and `--paths-hosts` /
`--crawl-hosts` cap the expensive work per round.

**Recursion.** A newly discovered host is not just appended to the report — it enters the next
round: probe → crawl → paths, and its own findings feed the following round. Every host still has
to pass the allowlist, while `--max-hosts` and `--depth` keep the scan bounded. Disable with
`--no-recurse` (the UI exposes the same switch).

**Aliases and duplicates.** Hosts that end up on the same final URL with the same title are one
asset: the first becomes primary, the rest are reported as aliases and are not crawled or
path-checked again. Findings with the same title and category are grouped in the report
(“Brak CSP — 23 hosty”), so the ledger shows signal instead of repetition. Hosts that answer on
21/25/143 but not on HTTP are counted as non-HTTP services, not as “no response”.

## Output layout

Every registrable domain gets its own directory and report, even when `recon` receives a mixed
list of domains and subdomains. A run with `-d a.com -d b.org` writes `out/a.com/` and `out/b.org/`
separately and prints a `cel 1/2` header per target.

```
out/<target>/
├── report.md / report.html      # human-readable report
├── findings.json                # machine-readable: severity, category, host, url, evidence
├── manifest.json                # metadata and counters
├── hosts.jsonl                  # one JSON per live host
├── subdomains.txt
├── live_hosts.txt               # host, status, tech, title, final_url
├── urls.txt
├── endpoints.txt                # endpoints extracted from HTML/JS
├── js_files.txt
├── forms.txt
├── secrets.txt                  # redacted by default (--show-secrets for full values)
├── run.log                      # raw log (web scans)
├── triage.json                  # finding status and notes (web app)
├── osint/                       # when OSINT ran
│   ├── osint.md / osint.json
│   ├── subdomains.txt
│   ├── cloud.txt
│   ├── dorks.txt
│   └── favicons.txt
└── interesting/
    ├── admin-panels.txt
    ├── debug-staging.txt
    ├── auth-endpoints.txt
    ├── api-endpoints.txt
    ├── payment-checkout.txt
    ├── file-upload.txt
    ├── redirect-params.txt
    ├── urls-with-params.txt
    └── user-account.txt
```

## Browser app

`bbhunter serve` starts a local server (default `127.0.0.1:8080`) with a top-nav, dark security workspace:

| View | What it does |
|---|---|
| Dashboard | posture KPIs, findings trend, last-run surface coverage, prioritized queue, recent runs |
| Targets | saved scopes with `!exclusion` rules, file import, reuse in a scan |
| Scans | run history, hosts, finding counts, OSINT, report and log links |
| Live scan | five stages, log, findings as they arrive, stop |
| Findings | severity/status filters, search, detail drawer with evidence, triage and notes |
| OSINT | RDAP, ASN, cloud candidates, favicons, dorks, public code |
| Reports | HTML/Markdown/JSON, A4 print, issue template copied to the clipboard |
| Modules | stage toggles and custom paths; a rule DSL is planned |
| Settings | rate, concurrency, timeout, limits, proxy, API key status |
| Logs | raw log of the latest or selected run |

App state lives in `bbhunter-out/`: `settings.json`, `scopes.json`, and per target a `run.log` and
`triage.json` (finding statuses and notes). Settings apply to the next scan; API keys are read from
the server environment.

```bash
bbhunter serve --port 8080
xdg-open http://127.0.0.1:8080
```

- **The scope is entered per scan** and enforced exactly like the CLI. An empty field means that
  target only.
- **Several targets in one go**: enter them separated by commas or spaces (`a.com, b.org`). The app
  runs them sequentially — one scan at a time, each with its own report and run directory — and
  moves to `Scans` when the queue finishes.
- **One scan at a time.** A second request gets `409` so two runs cannot mix logs.
- The server binds to `127.0.0.1` only and has no auth — it is a local tool, not a network service.
- The UI is embedded in the binary (`src/ui/` via `include_str!`), so there is no frontend build.
- `GET /report/{id}` serves the generated HTML report; `GET /api/scan/{id}` returns state and logs
  (polling). Historical runs are exposed under `/api/runs/{id}/…`.

## OSINT

A separate command alongside the scan: it collects what probe/crawl cannot see and sends no traffic
to the target's application beyond HEADs for bucket names and public API queries.

```bash
bbhunter osint -d example.com --scope scope.txt -l live_hosts.txt
# artefacts: bbhunter-out/example.com/osint/{osint.md,osint.json,subdomains.txt,cloud.txt,dorks.txt,favicons.txt}
```

OSINT is also a scan stage, **enabled by default** in every `recon` and in the UI. It runs in two
phases:

- **pre-scan** — extra passive sources, RDAP, cloud candidates and dorks; new subdomains join the
  first scan round;
- **post-probe** — ASN/prefixes and Shodan InternetDB for every live host, favicon clusters for all
  of them (including `<link rel="icon">`), reverse-IP and certificate SANs for related hosts.

Artefacts land in `bbhunter-out/example.com/osint/`; the report gains a full **OSINT** section
(RDAP, ASN, clouds, favicons, related hosts, dorks) and a summary block in the sidebar. Disable
with `--no-osint` or by unchecking the box in the UI.

| Area | Source | Key |
|---|---|---|
| Passive subdomains | crt.sh, hackertarget, OTX, urlscan | no |
| Archives | Common Crawl index (latest), Wayback (via `--wayback` in recon) | no |
| WHOIS / RDAP | rdap.org | no |
| ASN, prefixes | RIPE Stat, hackertarget fallback | no |
| Shodan without a key | internetdb.shodan.io (ports, hostnames, vulns) | no |
| Public code | grep.app (often blocks bots), GitHub/GitLab/Google dorks | no |
| SecurityTrails | API v1 subdomains | `SECURITYTRAILS_API_KEY` |
| VirusTotal | API v3 subdomains | `VT_API_KEY` |
| GitHub code search | `/search/code` | `GITHUB_TOKEN` |
| Favicon → other hosts | mmh3 hash + `http.favicon.hash` | `SHODAN_API_KEY` |
| Cloud | S3 / GCS / Azure Blob over name permutations | no |

**Bucket names are candidates, not confirmed assets.** `403` means “the name exists”, `200` means a
public listing; those buckets may belong to someone else. For `200` the tool also reports whether
the target domain appears in the first 200 KB of the listing, which is a weak ownership hint, not
proof. It never claims ownership.

A missing key never aborts a run — that source is skipped and the reason is written to “Notes”.
Dorks are generated as links (no Google scraping), so they do not break ToS.

Passive sources are cached for 24 hours in `~/.cache/bbhunter` (override with `BBHUNTER_CACHE`),
retried twice with backoff, and fall back where possible: crt.sh → certspotter → RapidDNS,
Wayback split into year ranges, Common Crawl with a previous-index retry. Re-running a scan is
therefore much faster and gentler on the APIs.

## Product site

The landing page and the app share one dark workspace language: ink surfaces, signal lime and
Instrument Sans/JetBrains Mono telemetry. The report switches to paper for reading and A4 print,
with the same typography and severity hues.

```
site/
├── index.html                 # hero, pipeline, report, OSINT, scope, install
├── site.css                   # one section per screen, product-first layout
├── site.js                    # mobile menu, copy command, one hero scan sequence
└── assets/
    └── przyklad-raportu.html  # full, working offline report (embedded in the page)
```

The page shows the product rather than screenshots: a live HTML console runs a demo scan once on
load, the report section embeds the real report, and the OSINT section is a small SVG map with
animated pulses. Motion is limited to the hero entrance, that scan, the map and hover states; all
of it is disabled under `prefers-reduced-motion`.

```bash
xdg-open site/index.html
# or, from the repo root:
python3 -m http.server 8081 --bind 127.0.0.1   # → http://127.0.0.1:8081/site/
```

Serve it from the repo root: the page links `../design/fonts.css` and `site.css`. For a real
deployment, replace the data-URI fonts with `woff2` files and bundle `site.css`.

## Architecture

```
src/
├── main.rs      # CLI, command dispatch
├── cli.rs       # clap, target validation
├── pipeline.rs  # full recon run, shared by CLI and web
├── web.rs       # local axum server: UI, /api/scan, /api/runs, reports
├── ui/          # index.html + ui.css + ui.js (embedded via include_str!)
├── scope.rs     # allowlist and exclusions (globset), hard gate
├── http.rs      # client, pool, semaphore, rate limiter, body cap
├── dnsx.rs      # hickory-resolver, wildcard detection
├── subs.rs      # passive sources and brute force
├── probe.rs     # probe and audits (headers/cookies/CORS/disclosure)
├── tech.rs      # fingerprints (headers, body, cookies)
├── crawl.rs     # crawler, endpoint extraction, secrets
├── paths.rs     # well-known and custom paths with response validation
├── osint.rs     # RDAP, ASN, archives, cloud names, favicons, dorks
├── triage.rs    # URL/host classification into buckets
├── cache.rs     # 24 h response cache for passive sources
├── wayback.rs   # CDX
├── findings.rs  # Finding model, dedupe, sort, stages
├── report.rs    # Markdown/HTML/JSON/JSONL
├── log.rs       # coloured stderr output and capture for the UI
└── util.rs      # host/port/registrable-domain normalisation
```

### Extending

- **New fingerprint** — add an entry to `HEADER_RULES` / `BODY_RULES` in `tech.rs`.
- **New built-in path** — add it to `CHECKS` and validate the response in `classify()` (`paths.rs`).
  Content validation matters: a 200 on `/.env` is often a soft-404.
- **New secret pattern** — add a regex to `SECRET_RULES` in `crawl.rs`.
- **New subdomain source** — write `async fn source(http, root) -> Vec<String>` and add it to the
  source list.
- **New triage bucket** — a constant plus a rule in `Triage::add_url`; outputs appear automatically.
- **New OSINT source** — a function returning `(Vec<String>, Option<String>)` (values + skip reason)
  and a row in the report.
- **Custom paths** — UI → Modules; they are checked with a single GET and a soft-404 guard.
- **Custom wordlist** — `--wordlist file.txt` (one label per line).

## Design system

The HTML report is a separate system kept outside Rust — `src/report.rs` only assembles semantic
markup and includes CSS via `include_str!`. Restyling never touches scan logic. The report uses the
semantic paper tokens and ships with an A4 print stylesheet; the dark app and landing keep their own
workspace tokens but reuse the type scale, severity hues and signal-lime accent.

```
design/
├── direction.md     # product, character, world, moments, signature
├── foundations.md   # palette, measured contrast, type scale, grid, breakpoints
├── tokens.css       # paper/ink/cover tokens used by the report
├── report.css       # report components + A4 print stylesheet
├── fonts.css        # Instrument Sans + JetBrains Mono, latin/latin-ext, offline
├── review.md        # audit: findings, fixes, verification, verdict
├── closure.md       # consistency with the direction, deliberate omissions
└── screens/         # 1440 / 720 / 320 shots, empty and partial states
```

Rules: no gradients, glows or coloured shadows; severity colour is never the only carrier of
meaning; small radii (6 px panels, 4 px controls); a single accent (signal lime) reserved for
actions and structural markers; the report is paper with a dark cover and an A4 print stylesheet.
The report and the app UI are in Polish; the CLI stays in English (identifiers, flags, logs).

## Known limitations

- No JS rendering — SPAs only expose what is in the source HTML/JS. Wire headless Chrome
  (`chromiumoxide`) as another stage for full coverage.
- No intrusive testing: no payloads, parameter fuzzing, auth bypass or uploads. That is left to
  Burp/ffuf/nuclei — `urls.txt` and `interesting/*` are the input for them.
- `paths` is a known-path list, not directory brute force.
- TLS: no certificate chain or JA3 inspection (possible as a `rustls` extension).
- IPv6 with a port (`[::1]:8080`) is not fully handled in authority parsing.
- The browser app is local-only, single-scan, and has no history database: runs are directories.
- A custom signature DSL is planned; today only custom paths are executed.
- Reverse-IP and CT lookups are capped (3 IPs / 3 hosts) to keep a scan bounded; raise the caps in
  `osint.rs` if you need deeper graph work.

## Tips

- `bbhunter subs ... | httpx -silent` — logs go to stderr, hosts to stdout.
- Before `--brute` on a large domain, set `--rate 10` so you do not hammer the resolver.
- `--show-secrets` only locally; by default the report shows `AKIAIO…MPLE (20 chars)`.
- Start with `interesting/auth-endpoints.txt` and `api-endpoints.txt`, then `redirect-params.txt`.
- A secret in JS is a lead. Check whether the key is live and what its scope is before reporting.
- The cache makes repeat scans cheap: delete `~/.cache/bbhunter` to force fresh passive data.

## License / responsibility

Use only within bug bounty programs, your own systems, or with written permission. The author is not
responsible for use outside the authorised scope.
