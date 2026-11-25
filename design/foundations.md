# Fundamenty — kolory, typografia, układ

Etap 2. Wszystkie wartości żyją w `design/tokens.css`; komponenty (`design/report.css`)
sięgają wyłącznie po tokeny semantyczne. Ten plik dokumentuje pomiar i uzasadnienia.

## 1. Kolor

Jeden neutralny, ciepły grafit (OKLCH hue 84–92°) + jeden akcent (miedź, H 55.3°)
+ trzy kolory znaczeniowe wagi. Zero gradientów, zero poświat, zero cieni kolorowych.

### Primitywy → role

| Primityw | Wartość | Rola semantyczna |
|---|---|---|
| `--graphite-950` | `#171614` | `--color-bg` |
| `--graphite-900` | `#1d1c19` | `--color-surface` (bloki, pasek, stopka) |
| `--graphite-800` | `#262420` | `--color-raised` (hover wiersza) |
| `--paper-100` | `#efe9de` | `--color-text` |
| `--paper-300` | `#a9a29a` | `--color-text-secondary` |
| `--paper-500` | `#948e84` | `--color-text-muted` (tylko meta) |
| `--copper-400` | `#cf8b5b` | `--color-accent`, `--color-focus` |
| `--copper-500` | `#b9744a` | `--color-accent-strong` |
| `--vermillion-400` | `#e8786b` | `--color-sev-high` |
| `--ochre-300` | `#d8b45e` | `--color-sev-medium` |
| `--slate-400` | `#8aa3b8` | `--color-sev-low` |

### Zmierzone pary (WCAG 2.x, sRGB, bez alfy)

| Para | Tło | Wynik | Próg |
|---|---|---|---|
| text na bg | `#171614` | 14.97:1 | 4.5:1 |
| text na surface | `#1d1c19` | 14.10:1 | 4.5:1 |
| text-secondary na surface | `#1d1c19` | 6.75:1 | 4.5:1 |
| text-secondary na raised | `#262420` | 6.14:1 | 4.5:1 |
| text-muted na surface | `#1d1c19` | 5.24:1 | 4.5:1 |
| text-muted na raised | `#262420` | 4.77:1 | 4.5:1 |
| accent na surface | `#1d1c19` | 6.08:1 | 4.5:1 |
| accent na raised | `#262420` | 5.53:1 | 4.5:1 |
| sev-high na surface | `#1d1c19` | 5.95:1 | 4.5:1 |
| sev-high na raised | `#262420` | 5.41:1 | 4.5:1 |
| sev-medium na surface | `#1d1c19` | 8.61:1 | 4.5:1 |
| sev-medium na raised | `#262420` | 7.83:1 | 4.5:1 |
| sev-low na surface | `#1d1c19` | 6.50:1 | 4.5:1 |
| sev-low na raised | `#262420` | 5.91:1 | 4.5:1 |
| on-accent (`#171614`) na accent | `#cf8b5b` | 6.46:1 | 4.5:1 |

Najniższa para w całym UI to 4.77:1 (meta na podniesionej powierzchni) — powyżej progu
dla tekstu normalnego. Każdy kolor wagi jest **dodatkowo** opisany słowem
(`wysokie`, `średnie`, …), więc znaczenie nie zależy od koloru.

### Rozdzielenie odcieni (reguła 15°)

| Kolor | OKLCH H | Różnica do akcentu (55.3°) |
|---|---|---|
| sev-high | 28.1° | 27.2° |
| sev-medium | 86.9° | 31.6° |
| sev-low | 243.7° | 171.6° |

Akcent i żaden kolor znaczeniowy nie leżą w jednej rodzinie. Akcent nigdy nie jest
kolorem wagi; kolory wagi nigdy nie są kolorem struktury.

## 2. Typografia

Dwie rodziny, obie wbudowane jako subset `latin` + `latin-ext` (polskie znaki),
zapisane w `design/fonts.css` jako data URI, żeby raport działał offline.

- **Instrument Sans** — UI, tytuły, treść. Wagi 400 i 500 (obie załadowane).
- **JetBrains Mono** — hosty, ścieżki, kody statusów, liczby, etykiety techniczne.
  Wagi 400 i 500. `font-variant-numeric: tabular-nums` wszędzie, gdzie jest liczba.

### Skala

| Rola | Token | px | line-height | waga |
|---|---|---|---|---|
| Meta, etykiety mono, liczby w tabelach | `--size-12` | 12 | 1.4 | 400 |
| Treść tabel, opisy | `--size-13` | 13 | 1.4–1.5 | 400 |
| Treść podstawowa | `--size-14` | 14 | 1.5 | 400 |
| Tytuł wiersza / akapit | `--size-16` | 16 | 1.5 | 400 |
| Nagłówek sekcji | `--size-20` | 20 | 1.25 | 500 |
| Tytuł strony (domena) | `--size-30` | 30 | 1.1 | 500 |
| Figura (liczba ustaleń) | `--size-44` | 44 | 1 | 500 |

Zasady: `line-height` bez jednostek; `letter-spacing: -0.02em` tylko ≥ 24 px;
zero uppercase; zero kursywy; zero tracking na małym tekście; waga maks. 500;
miara tekstu ciągłego `--measure: 68ch`.

## 3. Układ

- Siatka: `1180px` max, gutter `32px` (mobile `20px`), kolumny `minmax(0,1fr) 300px`,
  odstęp `48px`. `minmax(0, 1fr)` chroni przed rozpychaniem przez długie URL-e.
- Rytm: skala 4 px (`--space-1` … `--space-24`). W grupie 4–8 px, między grupami
  12–24 px, między sekcjami 48–64 px.
- Wyrównania: jedna krawędź startowa dla wszystkich treści, liczby do prawej
  w kolumnie mono, tytuły sekcji na tej samej osi co tabela.
- Breakpointy wynikają z treści: `960px` (szyna schodzi pod treść — przy 200% zoomu
  z 1440 px dostajemy 720 px CSS), `640px` (tabele stają się blokami),
  `380px` (śledzenie pokrycia w jedną kolumnę). Wspierane minimum: `320px`.
- Gęstość: wiersz rejestru 13 px + padding 12 px; wiersz nawigacji/kubełka min. 44 px
  (cel dotykowy); tabela hostów 13 px.
- Promienie: panele i tabele `0`, znacznik wagi i obwódka focusu `--radius-1` (2 px).
  Keycapów nie ma, więc nie ma tokenu na nie. Zagnieżdżenie: 2 px wewnątrz 0 px = 0.

## 4. Ruch

`--dur-1: 120ms` dla hover/focus/zmiany stanu, jedna krzywa `cubic-bezier(0.2, 0, 0, 1)`.
Panel `details` rozwija się natywnie, bez animacji wysokości. Zero animacji przy starcie,
zero pętli, zero animowania wymiarów. Wszystko wyłączone pod `prefers-reduced-motion`.

## 5. Świadomie poza tokenami

- Wartości `@media` (media queries nie czytają custom properties) — wpisane w
  `report.css` z komentarzem.
- Szerokości kolumn tabel (`104px`, `190px`, `88px`) — geometria treści, nie system.
- Szerokości pasków w szynie (`--v`) — dane, liczone w Rust i wstawiane inline.
