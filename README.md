# bbhunter

All-in-one recon toolkit do bug bounty / pentestów **na cele, na które masz zgodę**.
Jeden binarny plik: passive subdomeny → DNS → probe HTTP → crawl/JS → low-hanging checks → triage → raport (MD + HTML + JSON).

> To nie jest exploit framework. Narzędzie robi rekonesans i niskoszkodliwe testy konfiguracji
> (GET na well-known ścieżki, nagłówki, CORS, cookies). Każdy wynik to trop do ręcznej weryfikacji,
> nie potwierdzona podatność.

## Bezpieczeństwo / scope

Każdy request przechodzi przez allowlistę (`--scope`). Bez pliku scope narzędzie **odmówi pracy**,
chyba że jawnie podasz `--no-scope-check` (tylko lab / localhost).

```txt
# scope.txt
example.com          # example.com + wszystkie subdomeny
*.example.org        # glob
api-*.lab.net
```

Hosty spoza listy są odrzucane jeszcze przed wysłaniem requestu, a wyniki passive enum są
filtrowane końcowo. Dodatkowo: globalny rate limit, cap współbieżności, timeouty i twarde limity
rozmiaru odpowiedzi.

## Build

```bash
cargo build --release          # binarka: target/release/bbhunter
cargo install --path .         # albo do ~/.cargo/bin
```

Wymaga stabilnego Rusta (testowane na 1.94). Sieć: wymagany dostęp do crt.sh, hackertarget,
OTX, urlscan i web.archive.org (część źródeł może być chwilowo niedostępna — reszta działa).

## Szybki start

```bash
# aplikacja w przeglądarce (formularz + live log + raport)
bbhunter serve --port 8080        # → http://127.0.0.1:8080

# pełny pipeline z terminala
bbhunter recon -d example.com --scope scope.txt --brute --wayback -o ./out

# pojedyncze etapy
bbhunter subs  -d example.com --scope scope.txt > subs.txt
bbhunter probe -l subs.txt --scope scope.txt
bbhunter crawl -l live_hosts.txt --scope scope.txt --max-pages 50
bbhunter paths -u https://example.com --scope scope.txt --limit 20
bbhunter urls  -d example.com --scope scope.txt > wayback.txt
```

Globalne flagi: `--concurrency` (domyślnie 20), `--rate` req/s (25), `--timeout` (10 s),
`-o/--out`, `-q`, `--show-secrets`, `--proxy` (np. Burp) oraz `-H "Name: Value"` (auth/cookies,
można powtarzać; działa też `BBHUNTER_PROXY`).

```bash
# przez Burpa, z sesją
bbhunter recon -d example.com --scope scope.txt \
  --proxy http://127.0.0.1:8080 \
  -H "Cookie: session=..." -H "Authorization: Bearer ..."
```

## Co robi `recon`

| Etap | Moduł | Opis |
|---|---|---|
| 1. Subdomeny | `subs.rs` | crt.sh, hackertarget, AlienVault OTX, urlscan + opcjonalny brute-force (wbudowana lista ~230 słów + własny wordlist) z detekcją wildcard DNS |
| 2. Probe | `probe.rs` | HTTPS→HTTP fallback, status, title, tech fingerprint, IP/CNAME, audyt nagłówków, cookies, CORS, błędy/stack trace |
| 3. Crawl | `crawl.rs` | BFS w obrębie hosta, linki/iframe/formularze, bundle JS, ekstrakcja endpointów, regex na sekrety (AWS, Stripe, Google, GitHub, JWT, klucze prywatne, generyczne `api_key=`) |
| 4. Paths | `paths.rs` | stała lista well-known ścieżek, po jednym GET: `.git`, `.env`, `.DS_Store`, `.svn`, `robots.txt`, `sitemap.xml`, `security.txt`, `server-status`, `phpinfo`, `actuator/*`, `metrics`, swagger/openapi, GraphQL, OIDC |
| 5. Wayback | `wayback.rs` | CDX API → historyczne URL-e (filtrowane do scope) |
| 6. Triage | `triage.rs` | buckety: admin-panels, debug-staging, auth-endpoints, api-endpoints, payment-checkout, file-upload, redirect-params, urls-with-params, user-account |
| 7. Rekurencja | `pipeline.rs` | Host odkryty w linku, JS, robots/sitemap albo przekierowaniu wchodzi do kolejnej rundy i przechodzi te same etapy. Limity: `--depth` (domyślnie 2), `--max-hosts` (500), `--no-recurse` wyłącza |
| 8. Raport | `report.rs` | `report.md`, `report.html`, `findings.json`, `hosts.jsonl`, pliki per-bucket |

Ważne: `paths` i crawl dostają **priorytetowo** hosty oznaczone jako dev/staging/admin/api,
a liczbę hostów do kosztownych sprawdzeń ograniczają `--paths-hosts` i `--crawl-hosts`.

**Rekurencja.** Nowy host nie jest tylko dopisywany do raportu — trafia do kolejnej rundy:
probe → crawl → paths, a jego własne odkrycia zasilają następną rundę. Każdy host nadal musi
przejść przez allowlistę, a budżet (`--max-hosts`) i głębokość (`--depth`) trzymają skan w ryzach.
Żeby to wyłączyć: `--no-recurse`. W UI odpowiada za to checkbox „Skanuj odkryte hosty".

## Struktura outputu

```
out/<target>/
├── report.md / report.html      # raport dla człowieka
├── findings.json                # maszynowo: severity, category, host, url, evidence
├── manifest.json                # metadane + liczniki
├── hosts.jsonl                  # jeden JSON na live host
├── subdomains.txt
├── live_hosts.txt               # host, status, tech, title, final_url
├── urls.txt
├── endpoints.txt                # endpointy wyciągnięte z HTML/JS
├── js_files.txt
├── forms.txt
├── secrets.txt                  # domyślnie zredagowane (--show-secrets = pełne)
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

## Warstwa wizualna

Raport HTML to osobny system, trzymany poza Rustem — `src/report.rs` tylko składa semantyczny
markup i włącza CSS przez `include_str!`. Zmiana wyglądu nie wymaga dotykania logiki skanu.

```
design/
├── direction.md     # kierunek: produkt, charakter, świat, momenty, sygnatura
├── foundations.md   # paleta, zmierzone kontrasty, skala typu, siatka, breakpointy
├── tokens.css       # jedyne źródło wartości (kolory, odstępy, typografia, ruch)
├── report.css       # komponenty raportu, wyłącznie na tokenach semantycznych
├── fonts.css        # Instrument Sans + JetBrains Mono, subset latin/latin-ext, offline
├── review.md        # przegląd: znaleziska, poprawki, weryfikacja, werdykt
├── closure.md       # spójność z kierunkiem, świadome pominięcia, kolejne kroki
└── screens/         # zrzuty 1440 / 720 / 320, stan pusty i częściowy, szkielet
```

Zasady: zero gradientów, poświat i cieni kolorowych; kolor wagi nigdy nie jest jedynym nośnikiem
znaczenia; panele płaskie (promień 0), zaokrąglenie tylko na znaczniku; jeden akcent (miedź) i tylko
tam, gdzie wskazuje strukturę. Raport jest po polsku, CLI zostaje po angielsku (identyfikatory,
flagi, logi).

## Aplikacja w przeglądarce

`bbhunter serve` uruchamia lokalny serwer (domyślnie `127.0.0.1:8080`) z aplikacją w przeglądarce:
lewą nawigacją i dziesięcioma widokami.

| Widok | Co robi |
|---|---|
| Dashboard | aktywny skan, szybki start, ostatnie znaleziska (grupowane po tytule), historia |
| Cele | zapisane zakresy z regułami `!wykluczenie`, import z pliku, użycie w skanie |
| Skany | historia przebiegów, hosty, liczba ustaleń, OSINT, linki do raportu i logu |
| Skan na żywo | pięć etapów, dziennik, napływające znaleziska, stop |
| Znaleziska | filtry wagi/statusu/szukanie, drawer z dowodem, triage i notatki |
| OSINT | RDAP, ASN, chmura, favicony, dorki, kod |
| Raporty | HTML/Markdown/JSON, szablon zgłoszenia do schowka |
| Moduły i reguły | przełączniki etapów i własne ścieżki; DSL jest zaplanowany |
| Ustawienia | rate, współbieżność, timeout, limity, proxy, status kluczy API |
| Logi | surowy log ostatniego lub wybranego przebiegu |

Dane aplikacji leżą w `bbhunter-out/`: `settings.json`, `scopes.json`, a przy każdym celu
`run.log` i `triage.json` (statusy i notatki znalezisk). `--proxy` z Ustawień obowiązuje przy
następnym skanie; klucze API są czytane ze środowiska serwera.

```bash
bbhunter serve --port 8080
xdg-open http://127.0.0.1:8080
```

- **Zakres jest wpisywany przy skanie** i egzekwowany tak samo jak w CLI. Puste pole = tylko ten cel.
- **Jeden skan naraz.** Drugi request dostaje `409`, żeby dwa przebiegi nie mieszały logów.
- Serwer słucha tylko na `127.0.0.1` i nie ma autoryzacji — to narzędzie lokalne, nie usługa sieciowa.
- Interfejs jest wbudowany w binarkę (`src/ui/` przez `include_str!`), więc nie ma builda frontendu.
- `GET /report/{id}` serwuje wygenerowany raport HTML; `GET /api/scan/{id}` to stan i logi (polling).

## OSINT

Osobna komenda obok skanu: zbiera to, czego nie widzi sam probe/crawl, i nie wysyła ruchu do
aplikacji poza scope (poza HEAD-ami do nazw bucketów i zapytaniami do publicznych API).

```bash
bbhunter osint -d example.com --scope scope.txt -l live_hosts.txt
# artefakty: bbhunter-out/example.com/osint/{osint.md,osint.json,subdomains.txt,cloud.txt,dorks.txt,favicons.txt}
```

OSINT jest też etapem skanu:

```bash
OSINT jest **domyślnie włączony** w każdym `recon` i w UI. Nowe subdomeny wchodzą do pierwszej
rundy skanu, artefakty lądują w `bbhunter-out/example.com/osint/`, a w raporcie pojawia się blok
„OSINT” w szynie. Wyłączenie: `--no-osint` w CLI albo odznaczenie checkboxa w UI.

Co robi:

| Obszar | Źródło | Klucz |
|---|---|---|
| Pasywne subdomeny | crt.sh, hackertarget, OTX, urlscan | nie |
| Archiwa | Common Crawl index (najnowszy), Wayback (przez `--wayback` w recon) | nie |
| WHOIS / RDAP | rdap.org | nie |
| ASN, prefiksy | RIPE Stat, fallback hackertarget | nie |
| Shodan bez klucza | internetdb.shodan.io (porty, hosty, podatności) | nie |
| Publiczny kod | grep.app (często blokuje boty), dorki GitHub/GitLab/Google | nie |
| SecurityTrails | API v1 subdomeny | `SECURITYTRAILS_API_KEY` |
| VirusTotal | API v3 subdomeny | `VT_API_KEY` |
| GitHub code search | `/search/code` | `GITHUB_TOKEN` |
| Favicon → inne hosty | hash mmh3 + `http.favicon.hash` | `SHODAN_API_KEY` |
| Chmura | S3 / GCS / Azure Blob po permutacjach nazwy | nie |

Ważne: **nazwy bucketów to kandydaci**, a nie potwierdzone zasoby. `403` znaczy „nazwa istnieje”,
`200` — publiczna lista; to mogą być cudze buckety. Narzędzie nie pobiera zawartości, tylko nagłówki,
i nie twierdzi, że należą do celu.

Brak klucza nie wywala przebiegu — źródło jest pomijane, a powód trafia do sekcji „Uwagi”.
Dorki są generowane jako linki (bez scrapowania Google), więc nie łamią ToS.

## Strona produktu

Landing page leży w `site/` i korzysta z tych samych tokenów co raport.

```
site/
├── index.html                 # jeden ekran: hero, etapy, raport, bezpieczeństwo, instalacja
├── site.css                   # komponenty strony
├── tokens-site.css            # skala presentacyjna (hero 64 px, rytm sekcji)
└── assets/
    ├── raport-preview.png     # realny zrzut raportu (przycięty)
    └── przyklad-raportu.html  # pełny, działający raport offline
```

Otwarcie lokalnie:

```bash
xdg-open site/index.html
```

Strona linkuje `../design/fonts.css` i `../design/tokens.css`, więc działa z wnętrza repo. Przy
wdrożeniu na serwer zamień data-URI w fontach na pliki `woff2` i przenieś tokeny do jednego arkusza.

## Architektura

```
src/
├── main.rs      # CLI, dispatch komend
├── cli.rs       # clap, walidacja targetów
├── pipeline.rs  # pełny przebieg recon, wspólny dla CLI i web
├── web.rs       # lokalny serwer axum: /, /api/scan, /report, UI w binarce
├── ui/          # index.html + ui.css + ui.js (wbudowane przez include_str!)
├── scope.rs     # allowlista (globset) + twarda bramka
├── http.rs      # klient, connection pool, semafor, rate limiter, cap body
├── dnsx.rs      # hickory-resolver, wildcard detection
├── subs.rs      # źródła passive + brute
├── probe.rs     # probe + audyty (headers/cookies/CORS/disclosure)
├── tech.rs      # fingerprinty (nagłówki, body, cookies)
├── crawl.rs     # crawler + ekstrakcja endpointów + sekrety
├── paths.rs     # well-known paths z walidacją odpowiedzi
├── triage.rs    # klasyfikacja URL/hostów do bucketów
├── wayback.rs   # CDX
├── findings.rs  # model Findingu + dedupe + sort
├── report.rs    # MD/HTML/JSON/JSONL
├── log.rs       # kolorowy output na stderr (dane na stdout)
└── util.rs      # normalizacja hostów, portów, domen rejestrowalnych
```

### Rozszerzanie

- **Nowy fingerprint** — dopisz wpis do `HEADER_RULES` / `BODY_RULES` w `tech.rs`.
- **Nowa ścieżka** — dodaj do `CHECKS` i obsłuż walidację w `classify()` (`paths.rs`).
  Walidacja treści jest kluczowa: 200 na `/.env` bywa soft-404.
- **Nowy sekret** — regex do `SECRET_RULES` w `crawl.rs`.
- **Nowe źródło subdomen** — funkcja `async fn source(http, root) -> Vec<String>` + wpis w tablicy `sources`.
- **Nowy bucket triage** — stała + reguła w `Triage::add_url`, output pojawi się automatycznie.
- **Własny wordlist** — `--wordlist plik.txt` (jedna etykieta na linię).

## Ograniczenia (świadome)

- Brak renderowania JS — strony SPA dają tylko to, co jest w HTML/JS źródłowym.
  Dla pełnego pokrycia podłącz headless Chrome (`chromiumoxide`) jako kolejny etap.
- Brak testów inwazyjnych: żadnych payloadów, fuzzowania parametrów, auth bypassu, uploadów.
  To zostaje dla Burpa/ffuf/nuclei — `urls.txt` i `interesting/*` są do nich wejściem.
- `paths` to znane ścieżki, nie brute-force katalogów.
- TLS: brak inspekcji łańcucha certyfikatów / JA3 (możliwe jako rozszerzenie na `rustls`).
- IPv6 z portem (`[::1]:8080`) nie jest w pełni obsłużony w parsowaniu authority.

## Tips

- `bbhunter subs ... | httpx -silent` — logi idą na stderr, hosty na stdout.
- Zanim odpalisz `--brute` na dużej domenie, ustaw `--rate 10`, żeby nie zabić resolvera.
- `--show-secrets` tylko lokalnie; domyślnie raport pokazuje `AKIAIO…MPLE (20 chars)`.
- Zacznij od `interesting/auth-endpoints.txt` i `api-endpoints.txt`, potem `redirect-params.txt`.
- Sekret w JS = trop. Sprawdź, czy klucz żyje i jaki ma scope, zanim zgłosisz.

## Licencja / odpowiedzialność

Używaj wyłącznie w ramach programów bug bounty, własnych systemów lub pisemnej zgody.
Autor nie odpowiada za użycie poza zakresem upoważnienia.
