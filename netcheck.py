#!/usr/bin/env python3
"""
netcheck.py — diagnostyka sieci LAN pod kątem typowych problemów, z podglądem na żywo.

  Faza 1 (pasywna, nasłuch na interfejsie):
    * pętle L2      – te same ramki broadcast/multicast krążące wielokrotnie
    * burze broadcast/multicast (pps), najgłośniejsze źródła
    * STP           – brak BPDU, wiele root bridge, zmiany topologii (TC/TCN)
    * ARP           – jeden IP z wieloma MAC (konflikt / spoofing / VRRP)
    * DHCP          – kilka serwerów DHCP (rogue DHCP), podgląd wymiany DHCP
    * IPv6 RA       – kilka routerów ogłaszających się (rogue RA)
    * LLDP          – sąsiedzi (informacyjnie)
  Faza 2 (aktywna):
    * konflikt własnego IP (ARP probe)
    * skan ARP podsieci – duplikaty IP
    * DHCP DISCOVER – liczba serwerów DHCP
    * ping do bramy (straty, opóźnienie, jitter) i do internetu
    * Path MTU, DNS, traceroute z wykrywaniem pętli routingu
  Zawsze:
    * liczniki błędów interfejsu (CRC, drop, kolizje), duplex, flapy linku

Podgląd na żywo: co sekundę (lub co --interval) linia ze statystykami ruchu,
a każde istotne zdarzenie (pętla, BPDU TC, nowy serwer DHCP, konflikt ARP,
błąd interfejsu, odpowiedź na ping, hop traceroute...) wypisywane od razu.

Wymaga: Linux, root, Python 3.8+, scapy >= 2.5 (pip install scapy), iputils-ping, iproute2.

Użycie:
    sudo ./netcheck.py -i eth0
    sudo ./netcheck.py -i eth0 -d 120 --json raport.json
    sudo ./netcheck.py -i eth0 --passive-only --interval 0.5
    sudo ./netcheck.py -i eth0 --quiet            # bez podglądu, tylko raport (np. cron)
    sudo ./netcheck.py -i eth0 --log /var/log/netcheck.log

Przerywanie: Ctrl+C = pomiń bieżący krok, 2× Ctrl+C w ciągu 2 s = zakończ i pokaż raport.
Log: wszystko co na ekranie trafia od razu do pliku (domyślnie netcheck_<data>.log).

Kod wyjścia: 0 = OK, 1 = ostrzeżenia, 2 = problemy krytyczne (przydatne w cronie).
"""

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import (ARP, BOOTP, DHCP, ICMP, IP, STP, UDP, AsyncSniffer, Dot3,
                           Ether, ICMPv6ND_RA, ICMPv6ND_RS, IPerror, ICMPerror, IPv6,
                           conf, get_if_hwaddr, mac2str, sendp, sr, srp)
except ImportError:
    sys.exit("Brak scapy. Zainstaluj: pip install scapy  (lub apt install python3-scapy)")

try:  # opcjonalnie – dekodowanie nazw sąsiadów LLDP
    from scapy.contrib.lldp import LLDPDUSystemName
except Exception:  # noqa: BLE001
    LLDPDUSystemName = None

BCAST = "ff:ff:ff:ff:ff:ff"
DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK",
              7: "RELEASE", 8: "INFORM"}

SEV_ORDER = {"CRIT": 0, "WARN": 1, "INFO": 2, "OK": 3}
COLORS = {"CRIT": "\033[1;31m", "WARN": "\033[1;33m", "INFO": "\033[36m", "OK": "\033[32m"}
DIM = "\033[2m"
RESET = "\033[0m"


# ---------------------------------------------------------------- konsola na żywo

class Console:
    """Bezpieczne wątkowo wypisywanie zdarzeń ze znacznikiem czasu.
    Każda linia trafia od razu (flush) także do pliku logu, jeśli jest otwarty."""

    def __init__(self, enabled, color, logfile=None):
        self.enabled = enabled
        self.color = color
        self.lock = threading.Lock()
        self.last = time.time()
        self.fh = None
        if logfile:
            self.fh = open(logfile, "a", encoding="utf-8", buffering=1)

    def _file(self, text):
        if self.fh:
            try:
                self.fh.write(text + "\n")
                self.fh.flush()
                os.fsync(self.fh.fileno())
            except (OSError, ValueError):
                pass

    def out(self, text, screen=True):
        """Zwykła linia (nagłówki, raport) – na ekran i do pliku."""
        with self.lock:
            if screen:
                print(text, flush=True)
            self._file(re.sub(r"\033\[[0-9;]*m", "", text))

    def log(self, msg, sev=None, dim=False):
        now = time.time()
        ts = time.strftime("%H:%M:%S", time.localtime(now)) + f".{int(now % 1 * 10)}"
        tag = f"[{sev}] " if sev else ""
        plain = f"{ts} {tag}{msg}"
        if self.color:
            if sev:
                tag = COLORS[sev] + tag + RESET
            if dim:
                msg = DIM + msg + RESET
        with self.lock:
            if self.enabled:
                print(f"{ts} {tag}{msg}", flush=True)
            self._file(plain)
            self.last = time.time()

    def close(self):
        if self.fh:
            self.fh.close()
            self.fh = None


class CtrlC:
    """Ctrl+C raz  = pomiń bieżący krok (nasłuch / test).
    Ctrl+C dwa razy w ciągu `window` s = przerwij wszystko i pokaż raport.
    Kolejne Ctrl+C po przerwaniu = natychmiastowe wyjście bez raportu."""

    def __init__(self, window=2.0):
        self.window = window
        self.last = 0.0
        self.abort = False
        self.armed = False      # KeyboardInterrupt rzucamy tylko w trakcie kroku
        self.hits = 0
        signal.signal(signal.SIGINT, self._handler)

    @staticmethod
    def _say(text):
        try:  # os.write jest bezpieczne w obsłudze sygnału (print może się zakleszczyć)
            os.write(sys.stdout.fileno(), ("\n" + text + "\n").encode())
        except OSError:
            pass

    def _handler(self, signum, frame):
        now = time.time()
        if self.abort:
            self._say(">>> Ctrl+C — wyjście bez raportu (log zapisany do tego momentu)")
            os._exit(130)
        self.hits += 1
        if now - self.last <= self.window:
            self.abort = True
            self._say(">>> Ctrl+C ×2 — przerywam wszystko i zapisuję raport "
                      "(kolejne Ctrl+C = wyjście bez raportu)")
        else:
            self._say(f">>> Ctrl+C — pomijam bieżący krok (jeszcze raz w ciągu {self.window:.0f} s = koniec)")
        self.last = now
        if self.armed:
            self.armed = False
            raise KeyboardInterrupt


class Heartbeat(threading.Thread):
    """W fazie aktywnej: jeśli przez `interval` nic się nie wypisało, pokaż co trwa."""

    def __init__(self, con, interval):
        super().__init__(daemon=True)
        self.con, self.interval = con, interval
        self.step, self.status, self.t_step = None, "", 0.0
        self._stop_ev = threading.Event()

    def begin(self, step, status=""):
        self.step, self.status, self.t_step = step, status, time.time()

    def end(self):
        self.step = None

    def run(self):
        while not self._stop_ev.wait(self.interval / 4):
            if self.step and time.time() - self.con.last >= self.interval:
                st = f" — {self.status}" if self.status else ""
                self.con.log(f"… {self.step}: trwa {time.time() - self.t_step:.0f} s{st}", dim=True)

    def stop(self):
        self._stop_ev.set()


# ---------------------------------------------------------------- raport

@dataclass
class Finding:
    sev: str
    area: str
    msg: str
    details: list = field(default_factory=list)


class Report:
    def __init__(self):
        self.items = []

    def add(self, sev, area, msg, details=None):
        self.items.append(Finding(sev, area, msg, list(details or [])))

    def worst(self):
        return min((SEV_ORDER[f.sev] for f in self.items), default=3)

    def print(self, con, color):
        con.out("\n" + "=" * 72)
        con.out(" WYNIKI  " + time.strftime("%Y-%m-%d %H:%M:%S"))
        con.out("=" * 72)
        for f in sorted(self.items, key=lambda x: (SEV_ORDER[x.sev], x.area)):
            tag = f"[{f.sev:4}]"
            if color:
                tag = COLORS[f.sev] + tag + RESET
            con.out(f"{tag} {f.area:<10} {f.msg}")
            for d in f.details:
                con.out(f"{'':18}- {d}")
        c = Counter(f.sev for f in self.items)
        con.out("-" * 72)
        con.out(f" CRIT: {c['CRIT']}   WARN: {c['WARN']}   INFO: {c['INFO']}   OK: {c['OK']}")


# ---------------------------------------------------------------- pomocnicze

ENV_C = dict(os.environ, LC_ALL="C")


def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=ENV_C)
        return p.returncode, p.stdout + p.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as ex:
        return -1, str(ex)


def iface_cidr(iface):
    _, out = run(["ip", "-o", "-4", "addr", "show", "dev", iface])
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out)
    return ipaddress.ip_interface(m.group(1)) if m else None


def default_gw(iface):
    _, out = run(["ip", "-4", "route", "show", "default"])
    fallback = None
    for line in out.splitlines():
        m = re.search(r"via (\S+)", line)
        if not m:
            continue
        if f"dev {iface}" in line:
            return m.group(1)
        fallback = fallback or m.group(1)
    return fallback


def sysfs(iface, name):
    try:
        with open(f"/sys/class/net/{iface}/{name}") as fh:
            return fh.read().strip()
    except OSError:
        return None


STAT_KEYS = ["rx_errors", "rx_crc_errors", "rx_frame_errors", "rx_dropped", "rx_over_errors",
             "rx_missed_errors", "tx_errors", "tx_dropped", "tx_carrier_errors", "collisions"]
ERROR_KEYS = ("rx_crc_errors", "rx_frame_errors", "collisions", "rx_errors", "tx_errors",
              "tx_carrier_errors")


def read_stats(iface):
    d = {}
    for k in STAT_KEYS + ["rx_packets", "tx_packets"]:
        v = sysfs(iface, f"statistics/{k}")
        if v is not None and v.isdigit():
            d[k] = int(v)
    cc = sysfs(iface, "carrier_changes")
    if cc and cc.isdigit():
        d["carrier_changes"] = int(cc)
    return d


def report_stat_changes(con, s_prev, s_cur):
    """Wypisz na żywo przyrost błędów i flapy linku między dwoma odczytami."""
    for k in STAT_KEYS:
        dv = s_cur.get(k, 0) - s_prev.get(k, 0)
        if dv > 0:
            con.log(f"interfejs: {k} +{dv}", "WARN" if k in ERROR_KEYS else "INFO")
    dc = s_cur.get("carrier_changes", 0) - s_prev.get("carrier_changes", 0)
    if dc > 0:
        con.log(f"interfejs: FLAP LINKU ({dc} zmian stanu nośnej)", "CRIT")


def dhcp_opts(pkt):
    out = {}
    for o in pkt[DHCP].options:
        if isinstance(o, tuple) and len(o) >= 2:
            out[o[0]] = o[1]
    return out


def callback_kw(fn):
    """srp/sr nie mają prn – stop_filter wywoływany jest dla każdej odebranej ramki,
    więc używamy go jako callbacku (zawsze zwraca False = nie przerywaj)."""
    def cb(pkt):
        try:
            fn(pkt)
        except Exception:  # noqa: BLE001
            pass
        return False
    return {"stop_filter": cb}


def ping_live(target, count, interval, con, label, iface=None):
    base = ["ping", "-c", str(count), "-i", str(interval), "-W", "1"]
    if iface:
        base += ["-I", iface]
    out = []
    for opts in (["-O"], []):  # -O = pokazuj zgubione pakiety na bieżąco (iputils)
        out = []
        try:
            p = subprocess.Popen(base + opts + [target], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, env=ENV_C)
        except FileNotFoundError:
            con.log("brak polecenia ping", "WARN")
            break
        try:
            for line in p.stdout:
                out.append(line)
                m = re.search(r"icmp_seq=(\d+).*time=([\d.]+) ms", line)
                if m:
                    con.log(f"{label} {target}: seq={m.group(1)} {m.group(2)} ms", dim=True)
                elif "no answer yet" in line:
                    s = re.search(r"icmp_seq=(\d+)", line)
                    con.log(f"{label} {target}: seq={s.group(1) if s else '?'} BRAK ODPOWIEDZI", "WARN")
                elif re.search(r"Unreachable|exceeded|Redirect", line):
                    con.log(f"{label}: {line.strip()}", "WARN")
            p.wait()
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
        if not any("invalid option" in l for l in out):
            break
    text = "".join(out)
    loss = re.search(r"([\d.]+)% packet loss", text)
    rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", text)
    r = {
        "loss": float(loss.group(1)) if loss else 100.0,
        "min": float(rtt.group(1)) if rtt else None,
        "avg": float(rtt.group(2)) if rtt else None,
        "max": float(rtt.group(3)) if rtt else None,
        "mdev": float(rtt.group(4)) if rtt else None,
    }
    con.log(f"{label} {target}: strata {r['loss']:.0f}%, śr. {r['avg']} ms, jitter {r['mdev']} ms",
            "WARN" if r["loss"] > 0 else None)
    return r


# ---------------------------------------------------------------- faza pasywna

class Passive:
    def __init__(self, own_mac, own_ip, gw, args, con):
        self.own_mac = own_mac.lower()
        self.own_ip, self.gw = own_ip, gw
        self.loop_window = args.loop_window
        self.loop_repeats = args.loop_repeats
        self.con = con
        self.cnt = Counter()             # liczniki narastające: total, bcast, mcast, arp, stp...
        self.sec_bcast_src = Counter()   # źródła broadcastu w bieżącym takcie
        self.bcast_sec = Counter()
        self.mcast_sec = Counter()
        self.bcast_src = Counter()
        self.frame_seen = {}
        self.loop_hits = {}              # hash -> (max powtórzeń, opis)
        self.loop_reported = {}          # hash -> liczba powtórzeń przy ostatnim komunikacie
        self.last_prune = 0.0
        self.arp_ip_macs = defaultdict(set)
        self.stp_bpdus = 0
        self.stp_tc = 0
        self.stp_tcn = 0
        self.stp_roots = Counter()
        self.stp_bridges = set()
        self.last_tc_event = 0.0
        self.dhcp_servers = defaultdict(set)
        self.ra_routers = defaultdict(set)
        self.lldp = {}
        self.errors = 0

    def handle(self, pkt):
        try:
            self._handle(pkt)
        except Exception:  # noqa: BLE001 – nie zabijamy sniffera przez jedną dziwną ramkę
            self.errors += 1

    def _handle(self, pkt):
        if Ether in pkt:
            e = pkt[Ether]
        elif Dot3 in pkt:          # ramki 802.3 (np. BPDU STP)
            e = pkt[Dot3]
        else:
            return
        src, dst = e.src.lower(), e.dst.lower()
        if src == self.own_mac:
            return
        ts = float(pkt.time)
        sec = int(ts)
        con = self.con
        self.cnt["total"] += 1

        is_bcast = dst == BCAST
        is_mcast = not is_bcast and (int(dst[:2], 16) & 1) == 1
        if is_bcast:
            self.cnt["bcast"] += 1
            self.bcast_sec[sec] += 1
            self.bcast_src[src] += 1
            self.sec_bcast_src[src] += 1
        elif is_mcast:
            self.cnt["mcast"] += 1
            self.mcast_sec[sec] += 1

        # --- pętla L2: identyczna ramka widziana wiele razy w krótkim oknie
        if is_bcast or is_mcast:
            raw = getattr(pkt, "original", None) or bytes(pkt)
            h = hashlib.blake2b(raw, digest_size=12).digest()
            dq = self.frame_seen.get(h)
            if dq is None:
                dq = self.frame_seen[h] = deque()
            dq.append(ts)
            while dq and ts - dq[0] > self.loop_window:
                dq.popleft()
            if len(dq) >= self.loop_repeats:
                prev = self.loop_hits.get(h, (0, ""))[0]
                desc = f"{src} -> {dst}: {pkt.summary()}"
                rep_n = self.loop_reported.get(h, 0)
                if rep_n == 0:
                    self.cnt["loops"] += 1
                    con.log(f"PĘTLA L2? ta sama ramka {len(dq)}× w {self.loop_window}s: {desc}", "CRIT")
                    self.loop_reported[h] = len(dq)
                elif len(dq) >= rep_n * 2:
                    con.log(f"PĘTLA L2: ramka krąży już {len(dq)}× w {self.loop_window}s: {desc}", "CRIT")
                    self.loop_reported[h] = len(dq)
                if len(dq) > prev:
                    self.loop_hits[h] = (len(dq), desc)
            if ts - self.last_prune > 2:
                cutoff = ts - self.loop_window
                for k in [k for k, v in self.frame_seen.items() if not v or v[-1] < cutoff]:
                    del self.frame_seen[k]
                self.last_prune = ts

        if ARP in pkt:
            self.cnt["arp"] += 1
            a = pkt[ARP]
            ip, mac = a.psrc, a.hwsrc.lower()
            if ip and ip != "0.0.0.0":
                known = self.arp_ip_macs[ip]
                if mac not in known:
                    if ip == self.own_ip:
                        con.log(f"ARP: {mac} ogłasza NASZ adres {ip}!", "CRIT")
                    elif known:
                        sev = "CRIT" if ip == self.gw else "WARN"
                        what = "BRAMA " if ip == self.gw else ""
                        con.log(f"ARP: {what}{ip} ma nowy MAC {mac} (wcześniej {', '.join(sorted(known))})", sev)
                    known.add(mac)

        if STP in pkt:
            self.cnt["stp"] += 1
            s = pkt[STP]
            self.stp_bpdus += 1
            if s.bpdutype == 0x80:
                self.stp_tcn += 1
                con.log(f"STP: TCN (zgłoszenie zmiany topologii) od {src}", "WARN")
            else:
                root = f"{s.rootid}/{s.rootmac.lower()}"
                if root not in self.stp_roots:
                    if self.stp_roots:
                        con.log(f"STP: NOWY root bridge {root} (był {', '.join(self.stp_roots)}) "
                                f"– od mostu {s.bridgemac}", "WARN")
                    else:
                        con.log(f"STP: root bridge {root}, BPDU od mostu {s.bridgeid}/{s.bridgemac} "
                                f"port {s.portid:#x}, koszt {s.pathcost}", "INFO")
                self.stp_roots[root] += 1
                bm = s.bridgemac.lower()
                if bm not in self.stp_bridges and self.stp_bridges:
                    con.log(f"STP: BPDU od kolejnego mostu {bm} na tym segmencie", "INFO")
                self.stp_bridges.add(bm)
                if s.bpduflags & 0x01:
                    self.stp_tc += 1
                    if ts - self.last_tc_event > 5:
                        con.log(f"STP: zmiana topologii (flaga TC) od mostu {bm}", "WARN")
                        self.last_tc_event = ts

        if DHCP in pkt and BOOTP in pkt:
            self.cnt["dhcp"] += 1
            o = dhcp_opts(pkt)
            mt = o.get("message-type")
            name = DHCP_TYPES.get(mt, str(mt))
            b = pkt[BOOTP]
            if mt in (2, 5, 6):  # OFFER / ACK / NAK
                sid = str(o.get("server_id") or (pkt[IP].src if IP in pkt else "?"))
                if sid not in self.dhcp_servers:
                    if self.dhcp_servers:
                        con.log(f"DHCP: KOLEJNY serwer DHCP {sid} ({src})! wcześniej: "
                                f"{', '.join(self.dhcp_servers)}", "CRIT")
                    else:
                        con.log(f"DHCP: serwer {sid} ({src})", "INFO")
                self.dhcp_servers[sid].add(src)
                con.log(f"DHCP {name} od {sid} → {b.yiaddr}", "WARN" if mt == 6 else None, dim=mt != 6)
            else:
                con.log(f"DHCP {name} od klienta {src}", dim=True)

        if ICMPv6ND_RA in pkt and IPv6 in pkt:
            self.cnt["ra"] += 1
            r = pkt[IPv6].src
            if r not in self.ra_routers:
                con.log(f"IPv6 RA: router {r} ({src})", "WARN" if self.ra_routers else "INFO")
            self.ra_routers[r].add(src)

        if getattr(e, "type", None) == 0x88CC:
            name = ""
            if LLDPDUSystemName is not None and LLDPDUSystemName in pkt:
                v = pkt[LLDPDUSystemName].system_name
                name = v.decode(errors="replace") if isinstance(v, bytes) else str(v)
            if src not in self.lldp:
                con.log(f"LLDP: sąsiad {src} {name}".rstrip(), "INFO")
            self.lldp[src] = name


def passive_tick(p, con, args, iface, elapsed, dt, prev_cnt, prev_stats):
    """Jedna linia statystyk na takt + zdarzenia z liczników interfejsu."""
    cur = dict(p.cnt)
    rate = {k: (cur.get(k, 0) - prev_cnt.get(k, 0)) / dt for k in
            ("total", "bcast", "mcast", "arp", "stp", "dhcp")}
    srcs, p.sec_bcast_src = p.sec_bcast_src, Counter()
    sev = None
    if rate["bcast"] >= args.storm_crit:
        sev = "CRIT"
    elif rate["bcast"] >= args.storm_warn or rate["mcast"] >= args.storm_crit:
        sev = "WARN"
    line = (f"[{elapsed:5.1f}s] ramki {rate['total']:6.0f}/s | bcast {rate['bcast']:5.0f}/s | "
            f"mcast {rate['mcast']:5.0f}/s | ARP {rate['arp']:4.0f}/s | BPDU {rate['stp']:3.0f}/s")
    if p.loop_hits:
        line += f" | PĘTLE: {len(p.loop_hits)}"
    if srcs:
        mac, n = srcs.most_common(1)[0]
        line += f" | top bcast: {mac} ({n / dt:.0f}/s)"
    if sev == "CRIT":
        line += "  << BURZA BROADCASTOWA"
    con.log(line, sev, dim=sev is None)
    stats = read_stats(iface)
    report_stat_changes(con, prev_stats, stats)
    return cur, stats


def analyze_passive(p, rep, duration, t_start, own_ip, gw, args):
    secs = range(int(t_start), int(t_start + duration) + 1)
    b = [p.bcast_sec.get(s, 0) for s in secs]
    m = [p.mcast_sec.get(s, 0) for s in secs]
    b_avg, b_max = sum(b) / max(duration, 1), max(b, default=0)
    m_avg, m_max = sum(m) / max(duration, 1), max(m, default=0)
    top = [f"{mac}: {n} ramek ({n / max(duration, 1):.1f}/s)" for mac, n in p.bcast_src.most_common(5)]

    rep.add("INFO", "ruch", f"Odebrano {p.cnt['total']} ramek w {duration} s "
            f"(broadcast śr. {b_avg:.1f}/s, max {b_max}/s; multicast śr. {m_avg:.1f}/s, max {m_max}/s)")

    if p.loop_hits:
        hits = sorted(p.loop_hits.values(), reverse=True)
        rep.add("CRIT", "pętla L2",
                f"{len(hits)} różnych ramek broadcast/multicast powtórzyło się ≥{args.loop_repeats}× "
                f"w {args.loop_window}s (max {hits[0][0]}×) — typowy objaw pętli w warstwie 2",
                [f"{n}× {d}" for n, d in hits[:5]])
    else:
        rep.add("OK", "pętla L2", "Nie wykryto krążących (powtarzających się) ramek")

    if b_max >= args.storm_crit:
        rep.add("CRIT", "broadcast", f"Burza broadcastowa: szczyt {b_max} pps", top)
    elif b_max >= args.storm_warn:
        rep.add("WARN", "broadcast", f"Wysoki ruch broadcast: szczyt {b_max} pps", top)
    else:
        rep.add("OK", "broadcast", f"Ruch broadcast w normie (szczyt {b_max} pps)", top[:3])
    if m_max >= args.storm_crit:
        rep.add("WARN", "multicast", f"Bardzo wysoki ruch multicast: szczyt {m_max} pps "
                "(brak IGMP snooping? strumień wideo?)")

    if p.stp_bpdus == 0:
        rep.add("INFO", "STP", "Brak BPDU na porcie — STP wyłączone, filtrowane (BPDU filter) "
                "albo switch niezarządzalny. Pętla nie zostanie automatycznie zablokowana.")
    else:
        roots = [f"{r} ({n} BPDU)" for r, n in p.stp_roots.most_common()]
        if len(p.stp_roots) > 1:
            rep.add("WARN", "STP", f"Widać {len(p.stp_roots)} różne root bridge — niestabilne STP "
                    "lub mieszanie domen/VLAN-ów na porcie", roots)
        elif roots:
            rep.add("OK", "STP", f"Root bridge: {roots[0]}")
        if p.stp_tc or p.stp_tcn:
            rep.add("WARN", "STP", f"Zmiany topologii: {p.stp_tc} BPDU z flagą TC, {p.stp_tcn} TCN "
                    f"w {duration} s — sprawdź flapujące porty / brak portfast na portach końcowych")
        if len(p.stp_bridges) > 1:
            rep.add("INFO", "STP", f"BPDU od {len(p.stp_bridges)} różnych mostów na tym segmencie — "
                    "między tobą a switchem może być inny switch/hub", sorted(p.stp_bridges))

    for ip, macs in sorted(p.arp_ip_macs.items()):
        if ip == own_ip:
            rep.add("CRIT", "ARP", f"Ktoś inny ogłasza NASZ adres {ip}", sorted(macs))
        elif len(macs) > 1:
            sev = "CRIT" if ip == gw else "WARN"
            extra = " (BRAMA! możliwy ARP spoofing / MITM, chyba że to VRRP/HSRP)" if ip == gw else \
                    " (konflikt IP, proxy ARP lub VRRP/HSRP)"
            rep.add(sev, "ARP", f"IP {ip} ogłaszany przez {len(macs)} różne MAC{extra}", sorted(macs))

    if len(p.dhcp_servers) > 1:
        rep.add("CRIT", "DHCP", f"Pasywnie widać {len(p.dhcp_servers)} serwery DHCP (rogue DHCP?)",
                [f"{s} via {', '.join(sorted(m))}" for s, m in p.dhcp_servers.items()])

    if len(p.ra_routers) > 1:
        rep.add("WARN", "IPv6 RA", f"{len(p.ra_routers)} routery wysyłają Router Advertisement "
                "(rogue RA?)", [f"{s} ({', '.join(sorted(m))})" for s, m in p.ra_routers.items()])
    elif p.ra_routers:
        r, macs = next(iter(p.ra_routers.items()))
        rep.add("INFO", "IPv6 RA", f"Router IPv6: {r} ({', '.join(sorted(macs))})")

    if p.lldp:
        rep.add("INFO", "LLDP", "Sąsiedzi LLDP", [f"{mac} {name}".strip() for mac, name in p.lldp.items()])


# ---------------------------------------------------------------- faza aktywna

def check_own_ip_conflict(iface, mac, own_ip, rep, con, hb):
    con.log(f"ARP probe: czy ktoś jeszcze używa {own_ip}?")
    seen = set()

    def on_pkt(r):
        if ARP in r and r[ARP].op == 2 and r[ARP].psrc == own_ip and r[ARP].hwsrc.lower() != mac:
            m = r[ARP].hwsrc.lower()
            if m not in seen:
                seen.add(m)
                con.log(f"KONFLIKT: {own_ip} odpowiada także {m}", "CRIT")

    pkt = Ether(dst=BCAST, src=mac) / ARP(op=1, hwsrc=mac, psrc="0.0.0.0", pdst=own_ip)
    ans, _ = srp(pkt, iface=iface, timeout=2, multi=True, verbose=0, **callback_kw(on_pkt))
    others = {r[ARP].hwsrc.lower() for _, r in ans if r[ARP].hwsrc.lower() != mac} | seen
    if others:
        rep.add("CRIT", "konflikt", f"Nasz adres {own_ip} jest używany także przez:", sorted(others))
    else:
        con.log(f"brak konfliktu dla {own_ip}", "OK")
        rep.add("OK", "konflikt", f"Brak konfliktu własnego adresu {own_ip}")


def arp_sweep(iface, net, gw, rep, force, con, hb):
    if net.num_addresses > 1024 and not force:
        con.log(f"skan ARP pominięty: {net} ma {net.num_addresses} adresów (użyj --force-scan)", "INFO")
        rep.add("INFO", "skan ARP", f"Pominięto: podsieć {net} jest duża ({net.num_addresses} adresów). "
                "Użyj --force-scan.")
        return
    con.log(f"skan ARP {net}: wysyłam {net.num_addresses - 2} zapytań")
    live = defaultdict(set)

    def on_pkt(r):
        if ARP in r and r[ARP].op == 2:
            ip, m = r[ARP].psrc, r[ARP].hwsrc.lower()
            try:
                if ipaddress.ip_address(ip) not in net:
                    return
            except ValueError:
                return
            if m in live[ip]:
                return
            if live[ip]:
                con.log(f"DUPLIKAT IP {ip}: {m} (wcześniej {', '.join(sorted(live[ip]))})",
                        "CRIT" if ip == gw else "WARN")
            else:
                tag = "  (brama)" if ip == gw else ""
                con.log(f"host {ip:<15} {m}{tag}", dim=True)
            live[ip].add(m)
            hb.status = f"znalezionych hostów: {len(live)}"

    ans, _ = srp(Ether(dst=BCAST) / ARP(pdst=str(net)), iface=iface, timeout=3, retry=1,
                 multi=True, verbose=0, **callback_kw(on_pkt))
    ip_macs = defaultdict(set)
    for _, r in ans:
        ip_macs[r[ARP].psrc].add(r[ARP].hwsrc.lower())
    for ip, macs in live.items():
        ip_macs[ip] |= macs
    mac_ips = defaultdict(set)
    for ip, macs in ip_macs.items():
        for m in macs:
            mac_ips[m].add(ip)
    con.log(f"skan ARP zakończony: {len(ip_macs)} hostów")
    rep.add("INFO", "skan ARP", f"Aktywnych hostów w {net}: {len(ip_macs)}")
    dups = {ip: m for ip, m in ip_macs.items() if len(m) > 1}
    for ip, macs in sorted(dups.items()):
        sev = "CRIT" if ip == gw else "WARN"
        rep.add(sev, "skan ARP", f"Duplikat IP {ip}: odpowiada {len(macs)} MAC", sorted(macs))
    if not dups:
        rep.add("OK", "skan ARP", "Brak zduplikowanych adresów IP")
    for m, ips in mac_ips.items():
        if len(ips) > 8:
            rep.add("INFO", "skan ARP", f"MAC {m} odpowiada za {len(ips)} adresów (proxy ARP / router / spoofing?)")
    if gw and gw not in ip_macs and ipaddress.ip_address(gw) in net:
        con.log(f"brama {gw} nie odpowiedziała na ARP", "WARN")
        rep.add("WARN", "brama", f"Brama {gw} nie odpowiedziała na ARP")


def dhcp_discover(iface, mac, rep, passive_servers, con, hb):
    conf.checkIPaddr = False
    xid = random.randint(1, 0xFFFFFFFF)
    pkt = (Ether(src=mac, dst=BCAST)
           / IP(src="0.0.0.0", dst="255.255.255.255")
           / UDP(sport=68, dport=67)
           / BOOTP(chaddr=mac2str(mac), xid=xid, flags=0x8000)
           / DHCP(options=[("message-type", "discover"), "end"]))
    con.log(f"DHCP: wysyłam DISCOVER (xid {xid:#010x}), czekam 5 s na oferty")
    live = {}

    def on_pkt(r):
        if DHCP in r and BOOTP in r and r[BOOTP].xid == xid:
            o = dhcp_opts(r)
            if o.get("message-type") == 2:
                sid = str(o.get("server_id") or r[IP].src)
                if sid not in live:
                    live[sid] = f"{sid} (MAC {r[Ether].src}, oferuje {r[BOOTP].yiaddr})"
                    con.log(f"DHCP OFFER #{len(live)}: {live[sid]}", "CRIT" if len(live) > 1 else None)
                    hb.status = f"ofert: {len(live)}"

    ans, _ = srp(pkt, iface=iface, multi=True, timeout=5, verbose=0, **callback_kw(on_pkt))
    servers = dict(live)
    for _, r in ans:
        if DHCP not in r:
            continue
        o = dhcp_opts(r)
        if o.get("message-type") == 2:
            sid = str(o.get("server_id") or r[IP].src)
            servers.setdefault(sid, f"{sid} (MAC {r[Ether].src}, oferuje {r[BOOTP].yiaddr})")
    for sid, macs in passive_servers.items():
        servers.setdefault(sid, f"{sid} (MAC {', '.join(sorted(macs))}, widziany pasywnie)")
    if len(servers) > 1:
        rep.add("CRIT", "DHCP", f"W sieci odpowiada {len(servers)} serwerów DHCP — możliwy rogue DHCP",
                list(servers.values()))
    elif servers:
        rep.add("OK", "DHCP", f"Jeden serwer DHCP: {next(iter(servers.values()))}")
    else:
        con.log("DHCP: brak ofert", "INFO")
        rep.add("INFO", "DHCP", "Brak odpowiedzi na DHCP DISCOVER (sieć statyczna lub DHCP snooping?)")


def check_gateway(iface, gw, rep, con, hb):
    if not gw:
        con.log("brak trasy domyślnej", "CRIT")
        rep.add("CRIT", "brama", "Brak trasy domyślnej")
        return
    r = ping_live(gw, 30, 0.2, con, "ping brama", iface=iface)
    desc = (f"{gw}: strata {r['loss']:.0f}%, RTT min/śr/max {r['min']}/{r['avg']}/{r['max']} ms, "
            f"jitter {r['mdev']} ms") if r["avg"] is not None else f"{gw}: brak odpowiedzi"
    if r["loss"] >= 100:
        rep.add("CRIT", "brama", f"Brama nie odpowiada na ping ({gw})")
    elif r["loss"] > 5:
        rep.add("CRIT", "brama", "Duże straty do bramy — " + desc)
    elif r["loss"] > 0:
        rep.add("WARN", "brama", "Straty do bramy — " + desc)
    elif r["avg"] > 10 or r["mdev"] > 5:
        rep.add("WARN", "brama", "Wysokie opóźnienie/jitter w LAN — " + desc)
    else:
        rep.add("OK", "brama", desc)


def check_internet(target, rep, con, hb):
    r = ping_live(target, 10, 0.3, con, "ping internet")
    if r["loss"] >= 100:
        rep.add("WARN", "internet", f"Brak odpowiedzi od {target} (brak internetu lub ICMP blokowane)")
        return False
    sev = "WARN" if r["loss"] > 2 or r["avg"] > 150 else "OK"
    rep.add(sev, "internet", f"{target}: strata {r['loss']:.0f}%, RTT śr. {r['avg']} ms, jitter {r['mdev']} ms")
    return True


def check_pmtu(target, rep, con, hb):
    def ok(size):
        rc, _ = run(["ping", "-M", "do", "-c", "1", "-W", "2", "-s", str(size), target], 10)
        con.log(f"MTU: pakiet {size + 28} B z DF → {'OK' if rc == 0 else 'nie przechodzi'}", dim=True)
        hb.status = f"sprawdzam {size + 28} B"
        return rc == 0

    if ok(1472):
        rep.add("OK", "MTU", f"Path MTU do {target}: 1500")
        return
    lo, hi = 548, 1472
    if not ok(lo):
        rep.add("INFO", "MTU", "Nie udało się zmierzyć Path MTU (ICMP blokowane?)")
        return
    while hi - lo > 1:
        mid = (lo + hi) // 2
        lo, hi = (mid, hi) if ok(mid) else (lo, mid)
    mtu = lo + 28
    con.log(f"Path MTU = {mtu}", "INFO")
    sev = "INFO" if mtu in (1492, 1480, 1460) else "WARN"
    rep.add(sev, "MTU", f"Path MTU do {target}: {mtu} (<1500 – PPPoE/tunel/VPN; przy problemach "
            "z dużymi pakietami sprawdź MSS clamping i czy ICMP 'frag needed' nie jest blokowane)")


def check_dns(rep, con, hb):
    ns = []
    try:
        with open("/etc/resolv.conf") as fh:
            ns = [l.split()[1] for l in fh if l.startswith("nameserver") and len(l.split()) > 1]
    except OSError:
        pass
    con.log(f"DNS: serwery {', '.join(ns) or '?'}", dim=True)
    fails, slow, lines = [], [], []
    for n in ("google.com", "wp.pl", "cloudflare.com"):
        hb.status = n
        t = time.monotonic()
        try:
            res = socket.getaddrinfo(n, None)
            ms = (time.monotonic() - t) * 1000
            lines.append(f"{n}: {ms:.0f} ms")
            con.log(f"DNS {n} → {res[0][4][0]} w {ms:.0f} ms", "WARN" if ms > 500 else None, dim=ms <= 500)
            if ms > 500:
                slow.append(n)
        except OSError as ex:
            fails.append(n)
            lines.append(f"{n}: BŁĄD ({ex})")
            con.log(f"DNS {n}: BŁĄD ({ex})", "WARN")
    lines.append("serwery: " + (", ".join(ns) or "?"))
    if fails:
        rep.add("CRIT" if len(fails) == 3 else "WARN", "DNS", "Błędy rozwiązywania nazw", lines)
    elif slow:
        rep.add("WARN", "DNS", "Wolne odpowiedzi DNS (>500 ms)", lines)
    else:
        rep.add("OK", "DNS", "DNS działa", lines)


def check_routing_loop(target, rep, con, hb, maxttl=30):
    ident = random.randint(1, 65535)
    pkts = [IP(dst=target, ttl=t) / ICMP(id=ident, seq=t) for t in range(1, maxttl + 1)]
    con.log(f"traceroute do {target}: wysyłam sondy TTL 1..{maxttl}")
    live = {}
    t0 = time.time()

    def on_pkt(r):
        if IP not in r or ICMP not in r:
            return
        ic = r[ICMP]
        if ic.type == 0 and ic.id == ident:
            ttl = ic.seq
        elif ic.type == 11 and ICMPerror in r and r[ICMPerror].id == ident:
            ttl = r[ICMPerror].seq
        else:
            return
        if ttl in live:
            return
        live[ttl] = r[IP].src
        seen_at = [t for t, h in live.items() if h == r[IP].src and t != ttl and r[IP].src != target]
        sev = "CRIT" if any(abs(t - ttl) > 1 for t in seen_at) else None
        extra = f"  ← już był na hopie {seen_at} (PĘTLA?)" if sev else ""
        kind = "cel" if ic.type == 0 else "hop"
        con.log(f"traceroute {kind} {ttl:2}: {r[IP].src}  (+{(time.time() - t0) * 1000:.0f} ms){extra}",
                sev, dim=sev is None)
        hb.status = f"odpowiedzi: {len(live)}"

    ans, _ = sr(pkts, timeout=3, verbose=0, **callback_kw(on_pkt))
    hops, reached = {}, None
    for snd, rcv in ans:
        hops[snd.ttl] = rcv.src
        if ICMP in rcv and rcv[ICMP].type == 0:
            reached = snd.ttl if reached is None else min(reached, snd.ttl)
    for t, h in live.items():
        hops.setdefault(t, h)
        if h == target:
            reached = t if reached is None else min(reached, t)
    last = reached or maxttl
    path = [hops.get(t) for t in range(1, last + 1)]
    trace = " → ".join(h or "*" for h in path)
    pos = defaultdict(list)
    for i, h in enumerate(path, 1):
        if h and h != target:
            pos[h].append(i)
    loops = [f"{h} na hopach {p}" for h, p in pos.items()
             if len(p) > 1 and any(b - a > 1 for a, b in zip(p, p[1:]))]
    if loops:
        rep.add("CRIT", "routing", f"Podejrzenie pętli routingu w drodze do {target}", loops + [trace])
    elif reached:
        rep.add("OK", "routing", f"Trasa do {target}: {reached} hopów", [trace])
    else:
        rep.add("INFO", "routing", f"Cel {target} nie odpowiedział w {maxttl} hopach", [trace])


# ---------------------------------------------------------------- interfejs

def analyze_iface(iface, s0, s1, duration, rep):
    speed, duplex = sysfs(iface, "speed"), sysfs(iface, "duplex")
    mtu, state = sysfs(iface, "mtu"), sysfs(iface, "operstate")
    wireless = os.path.exists(f"/sys/class/net/{iface}/wireless")
    rep.add("INFO", "interfejs", f"{iface}: stan {state}, prędkość {speed or '?'} Mb/s, duplex "
            f"{duplex or '?'}, MTU {mtu}" + (" (Wi-Fi)" if wireless else ""))
    if wireless:
        rep.add("INFO", "interfejs", "Pomiar przez Wi-Fi — testy pętli/STP mało wiarygodne, "
                "najlepiej uruchomić na połączeniu kablowym")
    if duplex == "half":
        rep.add("WARN", "interfejs", "Half-duplex — prawdopodobnie niedopasowanie autonegocjacji")
    try:
        if speed and 0 < int(speed) < 1000 and not wireless:
            rep.add("INFO", "interfejs", f"Link tylko {speed} Mb/s — sprawdź kabel/port (pary 4,5,7,8?)")
    except ValueError:
        pass
    keys = STAT_KEYS + ["carrier_changes"]
    delta = {k: s1.get(k, 0) - s0.get(k, 0) for k in keys if k in s0}
    grew = {k: v for k, v in delta.items() if v > 0 and k != "carrier_changes"}
    if delta.get("carrier_changes", 0) > 0:
        rep.add("CRIT", "interfejs", f"Link flapował {delta['carrier_changes']}× podczas testu")
    if grew:
        sev = "WARN" if any(k in grew for k in ERROR_KEYS) else "INFO"
        rep.add(sev, "interfejs", f"Liczniki błędów wzrosły w ciągu {duration:.0f} s",
                [f"{k}: +{v}" for k, v in grew.items()])
    totals = {k: s1[k] for k in STAT_KEYS if s1.get(k)}
    if totals:
        rep.add("INFO", "interfejs", "Liczniki od startu systemu",
                [f"{k}: {v}" for k, v in totals.items()] +
                [f"carrier_changes: {s1.get('carrier_changes', '?')}"])


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Skaner problemów sieci LAN (pętle, burze, STP, DHCP, ARP...)")
    ap.add_argument("-i", "--iface", default=None, help="interfejs (domyślnie ten z trasą domyślną)")
    ap.add_argument("-d", "--duration", type=int, default=60, help="czas nasłuchu pasywnego [s] (60)")
    ap.add_argument("-t", "--target", default="1.1.1.1", help="cel testów internetu/MTU/traceroute")
    ap.add_argument("--interval", type=float, default=1.0,
                    help="co ile sekund linia statystyk na żywo (1.0, min 0.2)")
    ap.add_argument("-q", "--quiet", action="store_true", help="bez podglądu na żywo, tylko raport")
    ap.add_argument("--passive-only", action="store_true", help="tylko nasłuch, bez wysyłania pakietów")
    ap.add_argument("--force-scan", action="store_true", help="skanuj ARP także podsieci > /22")
    ap.add_argument("--no-trace", action="store_true", help="pomiń traceroute")
    ap.add_argument("--storm-warn", type=int, default=300, help="próg WARN broadcast pps (300)")
    ap.add_argument("--storm-crit", type=int, default=2000, help="próg CRIT broadcast pps (2000)")
    ap.add_argument("--loop-repeats", type=int, default=5, help="ile identycznych ramek = pętla (5)")
    ap.add_argument("--loop-window", type=float, default=1.0, help="okno wykrywania pętli [s] (1.0)")
    ap.add_argument("--json", help="zapisz raport do pliku JSON")
    ap.add_argument("--log", help="plik logu (domyślnie netcheck_RRRRMMDD_GGMMSS.log w bieżącym katalogu)")
    ap.add_argument("--no-log", action="store_true", help="nie zapisuj logu do pliku")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()
    args.interval = max(0.2, args.interval)

    if not sys.platform.startswith("linux"):
        sys.exit("Skrypt działa tylko na Linuksie.")
    if os.geteuid() != 0:
        sys.exit("Uruchom jako root (sudo) — potrzebny surowy dostęp do interfejsu.")

    iface = args.iface
    if not iface:
        _, out = run(["ip", "-4", "route", "show", "default"])
        m = re.search(r"dev (\S+)", out)
        iface = m.group(1) if m else None
    if not iface or not os.path.exists(f"/sys/class/net/{iface}"):
        sys.exit(f"Nie znaleziono interfejsu: {iface}")

    cidr = iface_cidr(iface)
    own_ip = str(cidr.ip) if cidr else None
    net = cidr.network if cidr else None
    mac = get_if_hwaddr(iface).lower()
    gw = default_gw(iface)
    color = sys.stdout.isatty() and not args.no_color
    logfile = None if args.no_log else (args.log or time.strftime("netcheck_%Y%m%d_%H%M%S.log"))
    try:
        con = Console(not args.quiet, color, logfile)
    except OSError as ex:
        print(f"Nie mogę otworzyć pliku logu {logfile}: {ex} — kontynuuję bez logu")
        logfile = None
        con = Console(not args.quiet, color)
    ctl = CtrlC()
    rep = Report()

    con.out(f"NetCheck {time.strftime('%Y-%m-%d %H:%M:%S')}  {' '.join(sys.argv[1:])}")
    con.out(f"Interfejs: {iface}  MAC: {mac}  IP: {cidr or 'brak'}  brama: {gw or 'brak'}")
    if logfile:
        con.out(f"Log zapisywany na bieżąco do: {os.path.abspath(logfile)}")
    con.out("Ctrl+C = pomiń bieżący krok,  2× Ctrl+C w ciągu 2 s = zakończ i pokaż raport")
    s0 = read_stats(iface)
    t_begin = time.time()

    # --- faza 1: pasywna
    con.out(f"\n=== FAZA 1: nasłuch pasywny ({args.duration} s) ===")
    p = Passive(mac, own_ip, gw, args, con)
    sniffer = AsyncSniffer(iface=iface, prn=p.handle, store=False)
    sniffer.start()
    time.sleep(0.5)
    t_start = time.time()
    if not args.passive_only:
        try:  # sprowokuj Router Advertisement
            sendp(Ether(src=mac, dst="33:33:00:00:00:02") / IPv6(dst="ff02::2") / ICMPv6ND_RS(),
                  iface=iface, verbose=0)
            con.log("IPv6: wysłano Router Solicitation", dim=True)
        except Exception:  # noqa: BLE001
            pass
    prev_cnt, prev_stats = dict(p.cnt), s0
    t_prev = t_start
    next_t = t_start
    try:
        ctl.armed = True
        while time.time() - t_start < args.duration and not ctl.abort:
            next_t += args.interval
            time.sleep(max(0.0, next_t - time.time()))
            now = time.time()
            if args.quiet:
                continue
            prev_cnt, prev_stats = passive_tick(p, con, args, iface, now - t_start,
                                                max(now - t_prev, 1e-3), prev_cnt, prev_stats)
            t_prev = now
        ctl.armed = False
    except KeyboardInterrupt:
        ctl.armed = False
        con.log("nasłuch przerwany przez użytkownika", "INFO")
    duration = max(1, int(time.time() - t_start))
    sniffer.stop()
    analyze_passive(p, rep, duration, t_start, own_ip, gw, args)

    # --- faza 2: aktywna
    if not args.passive_only and not ctl.abort:
        con.out("\n=== FAZA 2: testy aktywne ===")
        hb = Heartbeat(con, args.interval)
        if not args.quiet:
            hb.start()
        steps = []
        if own_ip:
            steps += [("konflikt własnego IP", lambda: check_own_ip_conflict(iface, mac, own_ip, rep, con, hb)),
                      ("skan ARP", lambda: arp_sweep(iface, net, gw, rep, args.force_scan, con, hb))]
        steps += [("DHCP DISCOVER", lambda: dhcp_discover(iface, mac, rep, p.dhcp_servers, con, hb)),
                  ("ping bramy", lambda: check_gateway(iface, gw, rep, con, hb))]
        internet = {"ok": False}
        steps += [("ping internetu", lambda: internet.update(ok=check_internet(args.target, rep, con, hb))),
                  ("DNS", lambda: check_dns(rep, con, hb)),
                  ("Path MTU", lambda: internet["ok"] and check_pmtu(args.target, rep, con, hb))]
        if not args.no_trace:
            steps.append(("traceroute", lambda: check_routing_loop(args.target, rep, con, hb)))
        skipped = []
        for n, (name, fn) in enumerate(steps, 1):
            if ctl.abort:
                skipped.append(name)
                continue
            con.out(f"--- test {n}/{len(steps)}: {name}", screen=not args.quiet)
            hb.begin(name)
            s_before = read_stats(iface)
            hits_before = ctl.hits
            try:
                ctl.armed = True
                fn()
                ctl.armed = False
            except KeyboardInterrupt:
                ctl.armed = False
            except Exception as ex:  # noqa: BLE001
                ctl.armed = False
                con.log(f"{name}: test nie powiódł się ({ex})", "INFO")
                rep.add("INFO", name, f"Test nie powiódł się: {ex}")
            if ctl.hits != hits_before:  # scapy potrafi sam połknąć KeyboardInterrupt
                con.log(f"{name}: przerwano (wynik częściowy)", "INFO")
                rep.add("INFO", name, "Przerwano przez użytkownika — wynik częściowy")
            hb.end()
            report_stat_changes(con, s_before, read_stats(iface))
        hb.stop()
        if skipped:
            rep.add("INFO", "skrypt", "Pominięte testy (przerwano 2× Ctrl+C)", skipped)

    if ctl.abort:
        con.log("test przerwany (2× Ctrl+C) — raport z tego, co zebrano", "INFO")
        rep.add("INFO", "skrypt", "Test przerwany przez użytkownika (2× Ctrl+C) — wyniki niepełne")
    analyze_iface(iface, s0, read_stats(iface), time.time() - t_begin, rep)
    if p.errors:
        rep.add("INFO", "skrypt", f"{p.errors} ramek nie udało się przeanalizować")

    rep.print(con, color)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "iface": iface, "ip": str(cidr),
                       "gateway": gw, "findings": [asdict(f) for f in rep.items]},
                      fh, ensure_ascii=False, indent=2)
        con.out(f"Raport JSON: {args.json}")
    if logfile:
        con.out(f"Log: {os.path.abspath(logfile)}")
    con.close()

    sys.exit({0: 2, 1: 1}.get(rep.worst(), 0))


if __name__ == "__main__":
    main()
