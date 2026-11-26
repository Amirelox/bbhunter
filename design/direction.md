# Kierunek — bbhunter

Pięć linijek dla trzech powierzchni: **raportu HTML**, **aplikacji** i **landingu**. Jedna rodzina:
atrament, papier, sygnałowa limonka, Instrument Sans + JetBrains Mono.

- **Produkt** — bbhunter zamienia domenę w uporządkowaną mapę tego, co odpowiada, gdzie są endpointy
  i co jest źle skonfigurowane; dla jednej osoby pracującej nocą, która rano ma oddać dowód.
- **Charakter** — dokładny, nocny, oschły. Instrument pomiarowy, nie „platforma AI”.
- **Świat / materiał** — dwa stany tej samej pracy: ciemny kokpit (aplikacja, landing) i jasna
  kartka z dowodami (raport). Grafit z zielonym podtonem, papier, hairline, jeden sygnał limonki.
  Zero gradientów, poświat i kolorowych cieni.
- **Momenty** — (1) **okładka raportu**: ciemny pas z domeną, jedną figurą i rozkładem wag, który
  przechodzi w papier; (2) **rejestr ustaleń**: rządkowa tabela z 3 px brzegiem wagi, bez kart, bez
  pigułek; (3) **żywy konsola** na landingu, która rozgrywa jeden przebieg i milknie.
- **Signature** — sygnałowa limonka jako znacznik systemu: 2 px linia na górze, kwadrat 9 × 9 przed
  nagłówkiem, aktywna nawigacja, jedna główna akcja. Nigdy dekoracyjne tło.

**Układ, który z tego wynika:** ciemna okładka z domeną i liczbą wysokich, pod nią rozkład wag i ślad
pokrycia, niżej 8/4 — rejestr ustaleń plus przyklejona szyna z licznościami. Aplikacja powtarza ten
porządek: postawa i trend najpierw, triage potem. Landing prowadzi przez ten sam pipeline, a raport
pokazuje jako prawdziwy dokument w ramce. Karty i siatka równych kafelków odpadają.

## Pięć pułapek „AI UI”, których ten projekt unika

1. **Granatowo-fioletowy dashboard SaaS.** Zamiennik: atrament z zielonym podtonem + sygnałowa
   limonka; fiolet nie występuje nigdzie w chrome.
2. **Rząd równych kart z liczbą i podpisem.** Zamiennik: figura na okładce, rządkowy ślad pokrycia,
   rejestr i szyna. KPI w aplikacji mają różne role, nie są sześcioma kopiami.
3. **Uppercase z rozstrzelaniem** (`text-transform: uppercase; letter-spacing: .08em` na `th`).
   Zamiennik: sentence case, mono 10–11 px, tracking 0.
4. **Kolorowe pigułki jako jedyny nośnik znaczenia.** Zamiennik: 3 px brzeg + słowna etykieta +
   liczba; kolor tylko wzmacnia. Statusy mają własne kolory, akcent został zarezerwowany dla akcji.
5. **Zaokrąglenie wszędzie takie samo.** Zamiennik: panele 6 px, kontrolki 4 px, znaczniki 1–2 px,
   papier bez cieni; cień tylko dla warstw unoszących się (dialog, drawer, ramka raportu).
