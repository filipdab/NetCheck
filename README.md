# NetCheck

Skrypt diagnostyczny sieci LAN dla Linuksa (np. Raspberry Pi). Wykrywa pętle L2, burze broadcastowe, problemy ze STP, nieautoryzowane serwery DHCP / routery IPv6, konflikty IP, problemy z MTU, DNS i pętle routingu.

## Wymagania

- Linux, uprawnienia root
- Python 3.8+
- [scapy](https://scapy.net/)
- `iputils-ping`, `iproute2`

```bash
pip install scapy        # albo: sudo apt install python3-scapy
```

## Użycie

```bash
sudo ./netcheck.py -i eth0                          # pełny test: 60 s nasłuchu + testy aktywne
sudo ./netcheck.py -i eth0 -d 120 --json raport.json
sudo ./netcheck.py -i eth0 --passive-only           # tylko nasłuch, nic nie wysyła
```

Bez `-i` skrypt użyje interfejsu z trasą domyślną.

### Opcje

| Opcja | Domyślnie | Opis |
|---|---|---|
| `-i`, `--iface` | interfejs trasy domyślnej | interfejs do testów |
| `-d`, `--duration` | `60` | czas nasłuchu pasywnego [s] |
| `-t`, `--target` | `1.1.1.1` | cel testów internetu, MTU i traceroute |
| `--passive-only` | — | tylko nasłuch, bez wysyłania pakietów |
| `--force-scan` | — | skanuj ARP także podsieci większe niż /22 |
| `--no-trace` | — | pomiń traceroute |
| `--storm-warn` | `300` | próg WARN dla broadcastu [pps] |
| `--storm-crit` | `2000` | próg CRIT dla broadcastu [pps] |
| `--loop-repeats` | `5` | ile identycznych ramek w oknie oznacza pętlę |
| `--loop-window` | `1.0` | okno wykrywania pętli [s] |
| `--json PLIK` | — | zapisz raport do JSON |
| `--no-color` | — | wyłącz kolory |

## Co sprawdza

### Faza 1 — pasywna (nasłuch)

- **Pętle L2:** ta sama ramka broadcast/multicast widziana wielokrotnie w krótkim oknie. To najpewniejszy objaw pętli.
- **Burze broadcast/multicast:** szczyt i średnia pps oraz najgłośniejsze źródła.
- **STP:** brak BPDU, kilka różnych root bridge, zmiany topologii (flagi TC / TCN), BPDU od kilku mostów na jednym segmencie.
- **ARP:** jeden adres IP ogłaszany przez kilka MAC (konflikt, spoofing, VRRP/HSRP). Dla bramy i własnego IP zgłaszane jako krytyczne.
- **DHCP:** więcej niż jeden serwer DHCP (rogue DHCP).
- **IPv6 RA:** więcej niż jeden router ogłaszający się (rogue RA).
- **LLDP:** lista sąsiadów (informacyjnie).

### Faza 2 — aktywna

- konflikt własnego adresu IP (ARP probe)
- skan ARP podsieci — duplikaty IP, MAC obsługujące wiele adresów
- DHCP DISCOVER — liczba odpowiadających serwerów
- ping do bramy — straty, opóźnienie, jitter
- ping do internetu
- Path MTU
- DNS — czas odpowiedzi i błędy
- traceroute z wykrywaniem pętli routingu

### Zawsze

- liczniki błędów interfejsu (CRC, frame, drop, kolizje) i ich przyrost w czasie testu
- duplex, prędkość linku, flapy linku (`carrier_changes`)

## Wynik

Raport w konsoli z poziomami `CRIT` / `WARN` / `INFO` / `OK`, opcjonalnie w JSON.

Kod wyjścia:

| Kod | Znaczenie |
|---|---|
| `0` | wszystko OK |
| `1` | ostrzeżenia |
| `2` | problemy krytyczne |

Dzięki temu skrypt nadaje się do crona, np.:

```cron
0 * * * * /opt/netcheck/netcheck.py -i eth0 -d 30 --no-color --json /var/log/netcheck.json > /dev/null || logger -t netcheck "problemy w sieci"
```

## Uwagi

- Testy pętli i STP mają sens tylko na połączeniu kablowym. Przez Wi-Fi interfejs widzi niewielką część ruchu L2.
- Przy prawdziwej burzy broadcastowej Python może nie nadążać z analizą ramek. Wynik i tak wskaże problem, ale liczby pps mogą być zaniżone.
- Faza aktywna wysyła DHCP DISCOVER i skanuje ARP. Port security, DHCP snooping i systemy IDS mogą na to zareagować. W cudzej sieci zacznij od `--passive-only` albo uzgodnij test z administratorem.
- Kilka MAC dla jednego IP bywa poprawne (VRRP/HSRP, proxy ARP). Takie wyniki trzeba zweryfikować ręcznie.
