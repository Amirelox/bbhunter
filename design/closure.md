# Domknięcie

## Spójność z kierunkiem (etap 1)

Jeden ekran, więc sprawdzenie jest krótkie: każdy element musi dać się wyprowadzić z pięciu linijek
z `design/direction.md`.

| Element ekranu | Z czego wynika |
|---|---|
| Masthead: domena + jedna figura | „Produkt: mapa tego, co odpowiada”; figura to liczba najwyższej wagi, bo to jedyna liczba, która decyduje o kolejności pracy |
| Ślad pokrycia (4 stacje, miedziana linia) | „Moment 1” i „świat: stanowisko pomiarowe”; stacje to etapy pipeline'u, liczby to realny wolumen |
| Rejestr bez kart, 3 px brzeg wagi | „Moment 2”; czyta się jak log pomiarów, nie jak lista issue |
| Miedziany tick przed etykietami | „Signature” — jeden detal, zawsze w tej samej rynnie |
| Płaskie panele, zero cieni i poświat | „nic nie świeci”; głębia z hairline i kroku powierzchni |
| Waga jako słowo + kolor | „dokładny”: kolor nie może nieść znaczenia sam |
| Copy oschłe, bez wykrzykników | „charakter: oschły” |

Nic nie zostało dodane poza kierunkiem. Jedyne odstępstwo: `<details>` w leadach jest natywne i nie
ma własnego obramowania — świadomie, bo obramowanie byłoby czwartą ramką na tym samym ekranie.

## Świadomie pominięte

- **Jasny motyw.** Raport jest ciemny z założenia (praca nocna, ekran), a nie z braku tokenów.
  Paleta jest przygotowana pod jeden motyw; przełączenie to osobna decyzja, nie ustawienie.
- **Wydruk / PDF.** Brak `@media print`; przy druku tło zniknie i kontrast spadnie. Poza zakresem.
- **Ikonografia.** Zero ikon — to decyzja z kierunku, nie brak czasu.
- **Animacja rozwinięcia `details`.** Natywne `details` nie animuje wysokości bez JS; animowanie
  wysokości jest zresztą zabronione przez `better-motion`. Zostaje natychmiastowa zmiana stanu.
- **44 px na linkach URL w rejestrze.** 25 px (powyżej progu AA 24 px); podniesienie do 44 px
  wydłużyłoby tabelę o ~300 px i rozbiło rytm wierszy. Wyjątek „inline” z WCAG 2.5.8.
- **Warianty loading / disabled.** Raport jest statycznym artefaktem bez JS, więc te stany nie
  istnieją. Pokryte są realne odpowiedniki: pusty (0 ustaleń) i częściowy (notatka w szynie).
- **Tłumaczenie CLI.** Logi i `--help` zostają po angielsku (interfejs narzędzia); polski jest
  językiem produktu — raportu. To granica, nie niedokończenie.

## Co warto uruchomić ręcznie

- **`state-machine`** — pełna macierz stanów komponentów: `details` (zamknięty/otwarty/focus/hover),
  wiersz rejestru (domyślny/hover/focus/ostatni), pasek statusu (0/1/większość), ślad (0/1/dużo
  ustaleń, wszystkie wagi na 0). Ja sprawdziłem trzy stany całego ekranu, nie macierz komponentów.
- **`break`** — skrajne przypadki danych: 0 hostów, 1 ustalenie, 500 ustaleń, host 63 znaki, URL
  300 znaków bez separatorów, tytuł z 3 linii, same informacyjne, 90% 5xx. Warto zobaczyć, gdzie
  pęka rytm śladu i czy rejestr nie robi się nieczytelny.
- **`variant`** — dwa warianty układu do porównania: (a) szyna po lewej, rejestr po prawej;
  (b) ślad jako pionowa lista przy krawędzi zamiast poziomego pasa. Mam wątpliwość, czy przy
  20+ hostach poziomy ślad nadal jest najlepszym podsumowaniem.
