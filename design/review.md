> **Historyczny audyt.** Ten plik opisuje poprzednią, ciemną iterację raportu (grafit + miedź).
> Aktualny system to atrament + papier + sygnałowa limonka — patrz `direction.md` i `foundations.md`.

# Przegląd interfejsu — raport HTML bbhunter

**Zakres:** jeden ekran — `report.html` generowany przez `src/report.rs`. Stany: pełny (15 ustaleń),
pusty (0 ustaleń), częściowy (`--skip-paths`, notatka w szynie). Szerokości: 320, 720 (200% zoomu
z 1440), 1440. Poza zakresem: output CLI, `report.md`, pliki `.txt`/`.json` (to dane, nie UI).

**Stack:** Rust → jeden statyczny HTML z wbudowanym CSS (`design/fonts.css`, `design/tokens.css`,
`design/report.css` przez `include_str!`). Brak JS, brak builda CSS. Przegląd robiony na zbudowanym
artefakcie w Chromium 158, nie na kodzie.

**Dokumentacja projektu:** brak `CONTRIBUTING.md` / design-systemu. Konwencją jest ten raport:
`design/direction.md` (kierunek) i `design/foundations.md` (tokeny, pomiary).

## Werdykt

**Approve po poprawkach.** Wszystkie pozycje HIGH i MEDIUM naprawione i zweryfikowane ponownie.
Nie zostało nic, co blokuje zadanie albo ukrywa treść.

## Znaleziska (przed poprawkami, wg wpływu)

| # | Waga | Znalezisko | Dowód | Poprawka |
|---|---|---|---|---|
| 1 | HIGH | Tytuły i dowody ustaleń po angielsku w polskim UI — ten sam ekran mówi dwoma językami | `src/probe.rs`, `src/paths.rs`, `src/main.rs`, `src/crawl.rs` (nazwy sekretów) | Przetłumaczone 40+ stringów; nazwy kategorii przez `category_label()` (`src/report.rs:221`) |
| 2 | HIGH | Etykieta „informacyjne” wychodziła z kolumny i nachodziła na tytuł, gubiąc pierwsze znaki | zrzut stanu pustego, `design/report.css:393` (`width: 104px`) | Kolumna 124 px + `white-space: nowrap` + padding końcowy (`report.css:393–406`) |
| 3 | MEDIUM | Linki URL w rejestrze miały 16 px wysokości — poniżej progu 24×24 (WCAG 2.5.8) | pomiar CDP: `h:16` na 10 linkach | `inline-block`, `padding-block: 4px`, `margin-block: -4px` → 25 px bez zmiany rytmu (`report.css:434`) |
| 4 | MEDIUM | Nagłówek gubił port: `127.0.0.1` zamiast `127.0.0.1:8765` — błędna tożsamość celu | `src/main.rs`, `target: target_name` | `display_target` z wejścia; port w `target__port` (`src/report.rs`, `split_port`) |
| 5 | MEDIUM | Figura pokazywała „łącznie ustalenie” bez liczby | zrzut stanu pustego | `format!("łącznie {} {}", total, …)` |
| 6 | MEDIUM | Data ISO w polskim raporcie (`2026-11-24 20:25:52`) | nagłówek i stopka | `pl_datetime()` → `24 lis 2026, 20:43` |
| 7 | MEDIUM | Przy 720 px (200% zoomu) tytuł ustalenia miał ~254 px i URL-e łamały się w środku tokenu | zrzut 720 przed zmianą | Układ blokowy rejestru od 820 px, nie od 640 (`report.css:773`) |
| 8 | LOW | Linia severity w śladzie mogła rozdzielić liczbę od przymiotnika („1 / informacyjne”) | zrzut 320/720 | Każda para w `<span class="sevpart">` z `nowrap` (`report.css:288`) |
| 9 | LOW | Tytuł ustalenia powtarzał ścieżkę w nawiasie, a URL był linijkę niżej | rejestr, wiersze `paths` | Usunięty sufiks `[{path}]` (`src/paths.rs`) |
| 10 | LOW | 7 martwych tokenów (m.in. `--radius-2`, `--dur-2`, `--space-24`) | `grep` definicji vs użyć | Usunięte z `design/tokens.css`; `foundations.md` zaktualizowane |
| 11 | LOW | „Leady wg rodzaju” — skrót w etykiecie sekcji | nagłówek sekcji | „Leady według rodzaju” |
| 12 | LOW | Kolumna „Etap” mieszała identyfikatory (`paths`) z polskimi nazwami w śladzie (`ścieżek`) | rejestr vs ślad | `stage_label()` → `sonda` / `crawl` / `ścieżki` (`src/report.rs:221`) |
| 13 | INFO | Stan pusty: „w 1 host i 28 ścieżek” — zły przypadek | blok pusty | Miejscownik: „w 1 hoście i 28 ścieżkach” |

## Weryfikacja (po poprawkach)

| Sprawdzenie | Metoda | Wynik |
|---|---|---|
| Reflow 320 px bez poziomego scrolla (1.4.10) | CDP, `Emulation.setDeviceMetricsOverride` 320 | `innerWidth 320`, `scrollWidth 305`, 0 elementów poza kadrem |
| 200% zoom | 720 px CSS (1440 / 2) | 0 przepełnień, rejestr w układzie blokowym |
| 1440 px | CDP | 0 przepełnień |
| Tekst < 12 px | CDP, computed `font-size` liści | 0 |
| Cele dotykowe (2.5.8) | CDP, wszystkie `a, summary` | 42 cele, **0 poniżej 24 px**; 15 poniżej 44 px (inline linki URL — wyjątek „inline” z 2.5.8, świadoma gęstość) |
| Widoczny focus (2.4.7) | prawdziwy Tab przez CDP, 6 przystanków | `solid 2px #cf8b5b`, offset 2 px, widoczny na każdym; skip link pierwszy (46 px) |
| Kontrast tekstu (1.4.3) | pomiar par w `design/foundations.md` | minimum 4.77:1 (meta na `--color-raised`), reszta 5.1–14.9:1 |
| Kontrast obwódki focusu (1.4.11) | akcent na tle | 6.46:1 (próg 3:1) |
| Znaczenie nie tylko kolorem (1.4.1) | inspekcja | Waga ma słowo, status ma kod, pasek ma liczbę — kolor tylko wzmacnia |
| `prefers-reduced-motion` (2.3.3) | `report.css:939` | Wszystkie przejścia wyzerowane; brak animacji wejścia i pętli |
| Struktura | CDP | 1 × `h1`, 4 × `h2` (w tym `sr-only` dla śladu), `lang="pl"`, tytuł dokumentu ustawiony |
| Nazwy dostępne | CDP | 0 linków bez tekstu; tabele mają `caption` i `scope="col"` |
| Klawiatura | Tab przez cały dokument | Tylko elementy natywne (`a`, `summary`); brak pułapek focusu |
| Ucięta treść | inspekcja | Brak `line-clamp` i `ellipsis`; długie URL-e zawijają się (`overflow-wrap: anywhere`) |
| Akcja niszcząca | — | Nie dotyczy: raport jest tylko do czytania |

**Nie zweryfikowano:** czytniki ekranu (NVDA/VoiceOver) — brak w środowisku; tryb wysokiego kontrastu
Windows (forced-colors) — brak; wydruk/PDF — poza zakresem.

## Co zostało celowo

- **43 px zamiast 44 px** w linkach URL rejestru: próg 44 px jest heurystyką, 24 px jest wymogiem AA.
  Podnoszenie do 44 px rozwaliłoby rytm 15-wierszowej tabeli i zwiększyło jej wysokość o ~300 px.
- **Rejestr blokowy od 820 px**, nie od 640: przy 720 px tytuł miał 254 px i URL-e pękały w środku
  tokenu. Wcześniejsze przejście kosztuje trochę gęstości, ale ratuje czytelność przy 200% zoomu.
- **Zero ikon.** Świat przyrządu ma etykiety i liczby; jedyny znak to miedziany tick.
- **Brak animacji wejścia.** Dokument ma być nieruchomy; jedyny ruch to 120 ms na hover/focus.

## Diff wizualny

| Przed | Po |
|---|---|
| `design/screens/skeleton-1440.png` (sam szkielet semantyczny, bez CSS) | `design/screens/report-1440.png` |
| `design/screens/skeleton-320.png` | `design/screens/report-320.png` |
| — | `design/screens/report-720.png` (200% zoomu) |
| — | `design/screens/report-empty-1440.png` (0 ustaleń) |
| — | `design/screens/report-partial-1440.png` (`--skip-paths`, notatka) |
