# Kierunek — bbhunter, raport rekonesansu

Pięć linijek z etapu „Direction” (unslop). Powierzchnia: **raport HTML** (`report.html`) — jedyny
ekran, który widzi człowiek. CLI dziedziczy te same tokeny (miedź na etapy, te same kolory severity).

- **Produkt** — bbhunter zamienia jedną domenę w uporządkowaną mapę tego, co odpowiada, gdzie są
  endpointy i co jest źle skonfigurowane; dla jednej osoby pracującej program nocą.
- **Charakter** — dokładny, nocny, oschły.
- **Świat / materiał** — stanowisko pomiarowe w ciemnym pokoju: grafitowe panele, ryta hairline,
  siatka działowa, jedna miedziana kontrolka. Wszystko zmierzone, nic nie świeci.
- **Momenty** — dwa. (1) **Ślad pokrycia** na górze: linia działowa z czterema stacjami
  (subdomeny → probe → crawl → paths) i znaczkami severity nad nimi; jedyne miejsce z pełnym
  kolorem. (2) **Rejestr ustaleń**: rządkowa tabela bez kart, severity jako 3 px brzeg wiersza,
  liczby wyrównane do prawej w mono — czyta się jak log pomiarów, nie jak lista issue.
- **Signature** — miedziany tick 1 × 6 px przed każdą etykietą, liczbą i nagłówkiem sekcji, zawsze
  w tej samej 10 px rynnie.

**Układ, który z tego wynika:** masthead z domeną i jedną figurą (liczba wysokich), pod nim ślad
pokrycia pełnej szerokości, niżej 8/4 — rejestr ustaleń plus przyklejona szyna z licznościami.
Dlaczego: pomiar najpierw (co uruchomiono i co z tego wyszło), dowód potem (wiersze), a liczności
z boku, żeby nie konkurowały z rejestrem. Karty i siatka równych kafelków odpadają, bo to język
dashboardu, nie przyrządu.

## Pięć pułapek „AI UI”, których ten projekt unika

1. **Kopia palety GitHuba / granatowo-fioletowy dashboard.** Obecny raport używa 1:1 `#0e1116`,
   `#161b22`, `#8b949e`, `#4c9aff`. Zamiennik: ciepły grafit + miedź, zero niebieskiego w chrome.
2. **Rząd równych kart z liczbą i podpisem.** Siatka `auto-fit minmax(140px)` z 10 kafelkami.
   Zamiennik: jedna figura w mastheadzie + rządkowy ślad pokrycia + szyna z listami.
3. **Uppercase z rozstrzelaniem** (`text-transform: uppercase; letter-spacing: .08em` na `th`).
   Zamiennik: sentence case, mono 11 px, tracking 0.
4. **Kolorowe pigułki jako jedyny nośnik znaczenia** (chipy severity w 4 odcieniach, w tym dwa
   niebieskie). Zamiennik: 3 px brzeg + tekstowa etykieta + liczba; kolor tylko wzmacnia.
5. **Zaokrąglenie wszędzie takie samo** (`radius: 10px` na kartach, tabelach, `details`).
   Zamiennik: panele i tabele 0, znacznik severity 2, keycap 4 — z jawną logiką zagnieżdżenia.
