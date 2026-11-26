# Fundamenty — kolor, typografia, układ

Wspólna rodzina dla aplikacji, landingu i raportu. Raport ma własne tokeny papierowe
(`design/tokens.css`); aplikacja i landing trzymają ciemne wartości w swoich arkuszach, ale
powtarzają ten sam sygnał, typografię i skalę wagi.

## 1. Kolor

Dwa stany pracy: **atrament** (kokpit) i **papier** (dokument). Jeden akcent, sygnałowa limonka,
zarezerwowany dla akcji i aktywnego stanu. Waga ustalenia ma osobne, ciemniejsze odcienie na
papierze i jaśniejsze na okładce.

| Rola | Ciemna powierzchnia | Papier | Kontrast |
|---|---|---|---|
| tło | `#070a09` | `#f2efe5` | — |
| panel | `#0b100d` | `#fbf8f0` | — |
| tekst | `#edf3e6` | `#171a15` | 16.97 / 15.27 |
| tekst wtórny | `#b8c4b2` | `#4f584a` | 10.58 / 6.46 |
| meta | `#8c9988` | `#626c5d` | 6.42 / 4.78 |
| sygnał | `#c8f36a` | `#4b6600` (tekst) | 15.07 / 5.70 |
| wysoka waga | `#ff7b6b` | `#a52a22` | 7.58 / 6.18 |
| średnia waga | `#e8b45c` | `#7a5200` | 10.16 / 6.02 |
| niska waga | `#7fb9d6` | `#2f5d76` | 8.97 / 6.19 |

Okładka raportu: tło `#151a13`, tekst `#edf3e7` (15.62:1), meta `#99a690` (6.91:1),
sygnał `#c8f36a` (13.86:1). Kolor nigdy nie jest jedynym nośnikiem wagi — zawsze towarzyszy mu
słowo, liczba albo pozycja wiersza. Zero gradientów, poświat i kolorowych cieni.

## 2. Typografia

- **Instrument Sans** — tekst, nagłówki, liczby metryk. Wagi 400/500.
- **JetBrains Mono** — etykiety, hosty, URL-e, logi, znaczniki etapów. Ligatury wyłączone.
- Skala: 10, 11, 12, 13, 14, 20, 22, 30, 34, 48, 68 px. Bez pośrednich rozmiarów „na oko”.
- Nagłówki: `line-height` 1.1–1.22, `letter-spacing` −0.02 do −0.05 em tylko dla display.
- Treść: 14–16 px, `line-height` 1.5–1.6, miara 45–80 znaków.
- Liczby w tabelach i metrykach: `font-variant-numeric: tabular-nums`.
- Pola formularzy na telefonie: 16 px, żeby iOS nie powiększał widoku.

## 3. Przestrzeń i promienie

Skala 4 px: 4, 8, 12, 16, 20, 24, 32, 40, 48, 64. Odstęp wewnątrz grupy mniejszy niż między
grupami. Panele 6 px, kontrolki 4 px, znaczniki 1–2 px. Cień wyłącznie na warstwach unoszących się:
dialog, drawer, ramka raportu. Reszta głębi z hairline i kroku powierzchni.

## 4. Układ

- **Raport:** maks. 1180 px, 8/4 — treść plus przyklejona szyna 280 px. Poniżej 960 px szyna schodzi
  pod treść; poniżej 820 px rejestr staje się blokami; poniżej 640 px okładka i tabele przechodzą
  w jedną kolumnę.
- **Aplikacja:** górna nawigacja 64 px, widok maks. 1440 px, gęste tabele z przyklejonym nagłówkiem.
  Poniżej 860 px nawigacja jest pełnoekranowym menu; tabele zamieniają się w karty.
- **Landing:** jedna sekcja na ekran przy 1440×900, wspólna linia 1240 px, hero 832 px pod nawigacją.
  Poniżej 900 px sekcje rosną z treścią, nic nie wystaje poza szerokość.

## 5. Ruch

- Wejście widoku 280 ms, `transform` + `opacity`, raz na zmianę trasy.
- Hover 120–180 ms; podkreślenia rysowane, wiersze podświetlane, ramka raportu unosi się 2 px.
- Jeden przebieg konsoli na landingu, jedna sekwencja impulsów na mapie OSINT.
- `prefers-reduced-motion` wyłącza animacje i przejścia; nic nie zostaje ukryte.

## 6. Dostępność

- Kontrast tekstu min. 4.5:1; meta 4.73:1 (najniższa para w systemie). Fokus 2 px w sygnale.
- Każda akcja ma nazwę słowną; ikony dekoracyjne są `aria-hidden`.
- Dialog i drawer zamykają się `Esc`, focus wraca do wyzwalacza; menu mówi `aria-expanded`.
- Tabele mają `th scope`, nagłówki sekcji tworzą jedną hierarchię, wykresy mają tekstowe odpowiedniki
  w legendzie i liczbach.
- Wydruk raportu: A4, jasny wariant okładki, powtarzany nagłówek tabeli, brak podziału wiersza.
