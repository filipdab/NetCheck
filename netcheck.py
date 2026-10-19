#!/usr/bin/env python3
"""
netcheck.py — diagnostyka sieci LAN pod kątem typowych problemów:

  Faza 1 (pasywna, nasłuch na interfejsie):
    * pętle L2      – te same ramki broadcast/multicast krążące wielokrotnie
    * burze broadcast/multicast (pps), najgłośniejsze źródła
    * STP           – brak BPDU, wiele root bridge, zmiany topologii (TC/TCN)
    * ARP           – jeden IP z wieloma MAC (konflikt / spoofing / VRRP)
    * DHCP          – kilka serwerów DHCP (rogue DHCP)
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

Wymaga: Linux, root, Python 3.8+, scapy (pip install scapy), iputils-ping, iproute2.

Użycie:
    sudo ./netcheck.py -i eth0
    sudo ./netcheck.py -i eth0 -d 120 --json raport.json
    sudo ./netcheck.py -i eth0 --passive-only

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
import socket
import subprocess
import sys
import time
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import (ARP, BOOTP, DHCP, ICMP, IP, STP, UDP, AsyncSniffer, Dot3,
                           Ether, ICMPv6ND_RA, ICMPv6ND_RS, IPv6, conf,
                           get_if_hwaddr, mac2str, sendp, sr, srp)
except ImportError:
    sys.exit("Brak scapy. Zainstaluj: pip install scapy  (lub apt install python3-scapy)")

try:  # opcjonalnie – dekodowanie nazw sąsiadów LLDP
    from scapy.contrib.lldp import LLDPDUSystemName
except Exception:  # noqa: BLE001
    LLDPDUSystemName = None

BCAST = "ff:ff:ff:ff:ff:ff"

# ---------------------------------------------------------------- raport

SEV_ORDER = {"CRIT": 0, "WARN": 1, "INFO": 2, "OK": 3}
COLORS = {"CRIT": "\033[1;31m", "WARN": "\033[1;33m", "INFO": "\033[36m", "OK": "\033[32m"}
RESET = "\033[0m"


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

    def print(self, color):
        print("\n" + "=" * 72)
        print(" WYNIKI")
        print("=" * 72)
        for f in sorted(self.items, key=lambda x: (SEV_ORDER[x.sev], x.area)):
            tag = f"[{f.sev:4}]"
            if color:
                tag = COLORS[f.sev] + tag + RESET
            print(f"{tag} {f.area:<10} {f.msg}")
            for d in f.details:
                print(f"{'':18}- {d}")
        c = Counter(f.sev for f in self.items)
        print("-" * 72)
        print(f" CRIT: {c['CRIT']}   WARN: {c['WARN']}   INFO: {c['INFO']}   OK: {c['OK']}")


# ---------------------------------------------------------------- pomocnicze

def run(cmd, timeout=60):
    env = dict(os.environ, LC_ALL="C")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
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


def read_stats(iface):
    d = {}
    for k in STAT_KEYS:
        v = sysfs(iface, f"statistics/{k}")
        if v is not None and v.isdigit():
            d[k] = int(v)
    cc = sysfs(iface, "carrier_changes")
    if cc and cc.isdigit():
        d["carrier_changes"] = int(cc)
    return d


def dhcp_opts(pkt):
    out = {}
    for o in pkt[DHCP].options:
        if isinstance(o, tuple) and len(o) >= 2:
            out[o[0]] = o[1]
    return out


def ping(target, count=20, interval=0.2, iface=None):
    cmd = ["ping", "-c", str(count), "-i", str(interval), "-W", "1"]
    if iface:
        cmd += ["-I", iface]
    rc, out = run(cmd + [target], timeout=count * interval + 15)
    loss = re.search(r"([\d.]+)% packet loss", out)
    rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    return {
        "loss": float(loss.group(1)) if loss else 100.0,
        "min": float(rtt.group(1)) if rtt else None,
        "avg": float(rtt.group(2)) if rtt else None,
        "max": float(rtt.group(3)) if rtt else None,
        "mdev": float(rtt.group(4)) if rtt else None,
    }


# ---------------------------------------------------------------- faza pasywna

class Passive:
    def __init__(self, own_mac, loop_window, loop_repeats):
        self.own_mac = own_mac.lower()
        self.loop_window = loop_window
        self.loop_repeats = loop_repeats
        self.total = 0
        self.bcast_sec = Counter()
        self.mcast_sec = Counter()
        self.bcast_src = Counter()
        self.frame_seen = {}
        self.loop_hits = {}        # hash -> (max powtórzeń, opis)
        self.last_prune = 0.0
        self.arp_ip_macs = defaultdict(set)
        self.stp_bpdus = 0
        self.stp_tc = 0
        self.stp_tcn = 0
        self.stp_roots = Counter()
        self.stp_bridges = set()
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
        self.total += 1

        is_bcast = dst == BCAST
        is_mcast = not is_bcast and (int(dst[:2], 16) & 1) == 1
        if is_bcast:
            self.bcast_sec[sec] += 1
            self.bcast_src[src] += 1
        elif is_mcast:
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
                if len(dq) > prev:
                    self.loop_hits[h] = (len(dq), f"{src} -> {dst}: {pkt.summary()}")
            if ts - self.last_prune > 2:
                cutoff = ts - self.loop_window
                for k in [k for k, v in self.frame_seen.items() if not v or v[-1] < cutoff]:
                    del self.frame_seen[k]
                self.last_prune = ts

        if ARP in pkt:
            a = pkt[ARP]
            if a.psrc and a.psrc != "0.0.0.0":
                self.arp_ip_macs[a.psrc].add(a.hwsrc.lower())

        if STP in pkt:
            s = pkt[STP]
            self.stp_bpdus += 1
            if s.bpdutype == 0x80:
                self.stp_tcn += 1
            else:
                self.stp_roots[f"{s.rootid}/{s.rootmac.lower()}"] += 1
                self.stp_bridges.add(s.bridgemac.lower())
                if s.bpduflags & 0x01:
                    self.stp_tc += 1

        if DHCP in pkt and BOOTP in pkt:
            o = dhcp_opts(pkt)
            if o.get("message-type") in (2, 5, 6):  # OFFER / ACK / NAK
                sid = o.get("server_id") or (pkt[IP].src if IP in pkt else "?")
                self.dhcp_servers[str(sid)].add(src)

        if ICMPv6ND_RA in pkt and IPv6 in pkt:
            self.ra_routers[pkt[IPv6].src].add(src)

        if getattr(e, "type", None) == 0x88CC:
            name = ""
            if LLDPDUSystemName is not None and LLDPDUSystemName in pkt:
                v = pkt[LLDPDUSystemName].system_name
                name = v.decode(errors="replace") if isinstance(v, bytes) else str(v)
            self.lldp[src] = name


def analyze_passive(p, rep, duration, t_start, own_ip, gw, args):
    secs = range(int(t_start), int(t_start + duration) + 1)
    b = [p.bcast_sec.get(s, 0) for s in secs]
    m = [p.mcast_sec.get(s, 0) for s in secs]
    b_avg, b_max = sum(b) / max(duration, 1), max(b, default=0)
    m_avg, m_max = sum(m) / max(duration, 1), max(m, default=0)
    top = [f"{mac}: {n} ramek ({n / max(duration, 1):.1f}/s)" for mac, n in p.bcast_src.most_common(5)]

    rep.add("INFO", "ruch", f"Odebrano {p.total} ramek w {duration} s "
            f"(broadcast śr. {b_avg:.1f}/s, max {b_max}/s; multicast śr. {m_avg:.1f}/s, max {m_max}/s)")

    # pętla
    if p.loop_hits:
        hits = sorted(p.loop_hits.values(), reverse=True)
        rep.add("CRIT", "pętla L2",
                f"{len(hits)} różnych ramek broadcast/multicast powtórzyło się ≥{args.loop_repeats}× "
                f"w {args.loop_window}s (max {hits[0][0]}×) — typowy objaw pętli w warstwie 2",
                [f"{n}× {d}" for n, d in hits[:5]])
    else:
        rep.add("OK", "pętla L2", "Nie wykryto krążących (powtarzających się) ramek")

    # burza
    if b_max >= args.storm_crit:
        rep.add("CRIT", "broadcast", f"Burza broadcastowa: szczyt {b_max} pps", top)
    elif b_max >= args.storm_warn:
        rep.add("WARN", "broadcast", f"Wysoki ruch broadcast: szczyt {b_max} pps", top)
    else:
        rep.add("OK", "broadcast", f"Ruch broadcast w normie (szczyt {b_max} pps)", top[:3])
    if m_max >= args.storm_crit:
        rep.add("WARN", "multicast", f"Bardzo wysoki ruch multicast: szczyt {m_max} pps "
                "(brak IGMP snooping? strumień wideo?)")

    # STP
    if p.stp_bpdus == 0:
        rep.add("INFO", "STP", "Brak BPDU na porcie — STP wyłączone, filtrowane (BPDU filter) "
                "albo switch niezarządzalny. Pętla nie zostanie automatycznie zablokowana.")
    else:
        roots = [f"{r} ({n} BPDU)" for r, n in p.stp_roots.most_common()]
        if len(p.stp_roots) > 1:
            rep.add("WARN", "STP", f"Widać {len(p.stp_roots)} różne root bridge — niestabilne STP "
                    "lub mieszanie domen/VLAN-ów na porcie", roots)
        else:
            rep.add("OK", "STP", f"Root bridge: {roots[0]}")
        if p.stp_tc or p.stp_tcn:
            rep.add("WARN", "STP", f"Zmiany topologii: {p.stp_tc} BPDU z flagą TC, {p.stp_tcn} TCN "
                    f"w {duration} s — sprawdź flapujące porty / brak portfast na portach końcowych")
        if len(p.stp_bridges) > 1:
            rep.add("INFO", "STP", f"BPDU od {len(p.stp_bridges)} różnych mostów na tym segmencie — "
                    "między tobą a switchem może być inny switch/hub",
                    sorted(p.stp_bridges))

    # ARP
    for ip, macs in sorted(p.arp_ip_macs.items()):
        if ip == own_ip:
            rep.add("CRIT", "ARP", f"Ktoś inny ogłasza NASZ adres {ip}", sorted(macs))
        elif len(macs) > 1:
            sev = "CRIT" if ip == gw else "WARN"
            extra = " (BRAMA! możliwy ARP spoofing / MITM, chyba że to VRRP/HSRP)" if ip == gw else \
                    " (konflikt IP, proxy ARP lub VRRP/HSRP)"
            rep.add(sev, "ARP", f"IP {ip} ogłaszany przez {len(macs)} różne MAC{extra}", sorted(macs))

    # DHCP
    if len(p.dhcp_servers) > 1:
        rep.add("CRIT", "DHCP", f"Pasywnie widać {len(p.dhcp_servers)} serwery DHCP (rogue DHCP?)",
                [f"{s} via {', '.join(sorted(m))}" for s, m in p.dhcp_servers.items()])

    # IPv6 RA
    if len(p.ra_routers) > 1:
        rep.add("WARN", "IPv6 RA", f"{len(p.ra_routers)} routery wysyłają Router Advertisement "
                "(rogue RA?)", [f"{s} ({', '.join(sorted(m))})" for s, m in p.ra_routers.items()])
    elif p.ra_routers:
        r, macs = next(iter(p.ra_routers.items()))
        rep.add("INFO", "IPv6 RA", f"Router IPv6: {r} ({', '.join(sorted(macs))})")

    if p.lldp:
        rep.add("INFO", "LLDP", "Sąsiedzi LLDP", [f"{mac} {name}".strip() for mac, name in p.lldp.items()])


# ---------------------------------------------------------------- faza aktywna

def check_own_ip_conflict(iface, mac, own_ip, rep):
    pkt = Ether(dst=BCAST, src=mac) / ARP(op=1, hwsrc=mac, psrc="0.0.0.0", pdst=own_ip)
    ans, _ = srp(pkt, iface=iface, timeout=2, multi=True, verbose=0)
    others = {r[ARP].hwsrc.lower() for _, r in ans if r[ARP].hwsrc.lower() != mac.lower()}
    if others:
        rep.add("CRIT", "konflikt", f"Nasz adres {own_ip} jest używany także przez:", sorted(others))
    else:
        rep.add("OK", "konflikt", f"Brak konfliktu własnego adresu {own_ip}")


def arp_sweep(iface, net, gw, rep, force):
    if net.num_addresses > 1024 and not force:
        rep.add("INFO", "skan ARP", f"Pominięto: podsieć {net} jest duża ({net.num_addresses} adresów). "
                "Użyj --force-scan.")
        return
    ans, _ = srp(Ether(dst=BCAST) / ARP(pdst=str(net)), iface=iface, timeout=3, retry=1,
                 multi=True, verbose=0)
    ip_macs = defaultdict(set)
    for _, r in ans:
        ip_macs[r[ARP].psrc].add(r[ARP].hwsrc.lower())
    mac_ips = defaultdict(set)
    for ip, macs in ip_macs.items():
        for mac in macs:
            mac_ips[mac].add(ip)
    rep.add("INFO", "skan ARP", f"Aktywnych hostów w {net}: {len(ip_macs)}")
    dups = {ip: m for ip, m in ip_macs.items() if len(m) > 1}
    for ip, macs in sorted(dups.items()):
        sev = "CRIT" if ip == gw else "WARN"
        rep.add(sev, "skan ARP", f"Duplikat IP {ip}: odpowiada {len(macs)} MAC", sorted(macs))
    if not dups:
        rep.add("OK", "skan ARP", "Brak zduplikowanych adresów IP")
    many = {mac: ips for mac, ips in mac_ips.items() if len(ips) > 8}
    for mac, ips in many.items():
        rep.add("INFO", "skan ARP", f"MAC {mac} odpowiada za {len(ips)} adresów (proxy ARP / router / spoofing?)")
    if gw and gw not in ip_macs and ipaddress.ip_address(gw) in net:
        rep.add("WARN", "brama", f"Brama {gw} nie odpowiedziała na ARP")


def dhcp_discover(iface, mac, rep, passive_servers):
    conf.checkIPaddr = False
    pkt = (Ether(src=mac, dst=BCAST)
           / IP(src="0.0.0.0", dst="255.255.255.255")
           / UDP(sport=68, dport=67)
           / BOOTP(chaddr=mac2str(mac), xid=random.randint(1, 0xFFFFFFFF), flags=0x8000)
           / DHCP(options=[("message-type", "discover"), "end"]))
    ans, _ = srp(pkt, iface=iface, multi=True, timeout=5, verbose=0)
    servers = {}
    for _, r in ans:
        if DHCP not in r:
            continue
        o = dhcp_opts(r)
        if o.get("message-type") == 2:
            sid = str(o.get("server_id") or r[IP].src)
            servers[sid] = f"{sid} (MAC {r[Ether].src}, oferuje {r[BOOTP].yiaddr})"
    for sid, macs in passive_servers.items():
        servers.setdefault(sid, f"{sid} (MAC {', '.join(sorted(macs))}, widziany pasywnie)")
    if len(servers) > 1:
        rep.add("CRIT", "DHCP", f"W sieci odpowiada {len(servers)} serwerów DHCP — możliwy rogue DHCP",
                list(servers.values()))
    elif servers:
        rep.add("OK", "DHCP", f"Jeden serwer DHCP: {next(iter(servers.values()))}")
    else:
        rep.add("INFO", "DHCP", "Brak odpowiedzi na DHCP DISCOVER (sieć statyczna lub DHCP snooping?)")


def check_gateway(iface, gw, rep):
    if not gw:
        rep.add("CRIT", "brama", "Brak trasy domyślnej")
        return
    r = ping(gw, count=30, interval=0.2, iface=iface)
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


def check_internet(target, rep):
    r = ping(target, count=10, interval=0.3)
    if r["loss"] >= 100:
        rep.add("WARN", "internet", f"Brak odpowiedzi od {target} (brak internetu lub ICMP blokowane)")
        return False
    sev = "WARN" if r["loss"] > 2 or r["avg"] > 150 else "OK"
    rep.add(sev, "internet", f"{target}: strata {r['loss']:.0f}%, RTT śr. {r['avg']} ms, jitter {r['mdev']} ms")
    return True


def check_pmtu(target, rep):
    def ok(size):
        rc, _ = run(["ping", "-M", "do", "-c", "1", "-W", "2", "-s", str(size), target], 10)
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
    sev = "INFO" if mtu in (1492, 1480, 1460) else "WARN"
    rep.add(sev, "MTU", f"Path MTU do {target}: {mtu} (<1500 – PPPoE/tunel/VPN; przy problemach "
            "z dużymi pakietami sprawdź MSS clamping i czy ICMP 'frag needed' nie jest blokowane)")


def check_dns(rep):
    ns = []
    try:
        with open("/etc/resolv.conf") as fh:
            ns = [l.split()[1] for l in fh if l.startswith("nameserver") and len(l.split()) > 1]
    except OSError:
        pass
    fails, slow, lines = [], [], []
    for n in ("google.com", "wp.pl", "cloudflare.com"):
        t = time.monotonic()
        try:
            socket.getaddrinfo(n, None)
            ms = (time.monotonic() - t) * 1000
            lines.append(f"{n}: {ms:.0f} ms")
            if ms > 500:
                slow.append(n)
        except OSError as ex:
            fails.append(n)
            lines.append(f"{n}: BŁĄD ({ex})")
    lines.append("serwery: " + (", ".join(ns) or "?"))
    if fails:
        rep.add("CRIT" if len(fails) == 3 else "WARN", "DNS", "Błędy rozwiązywania nazw", lines)
    elif slow:
        rep.add("WARN", "DNS", "Wolne odpowiedzi DNS (>500 ms)", lines)
    else:
        rep.add("OK", "DNS", "DNS działa", lines)


def check_routing_loop(target, rep, maxttl=30):
    ans, _ = sr(IP(dst=target, ttl=(1, maxttl)) / ICMP(id=random.randint(1, 65535)),
                timeout=3, verbose=0)
    hops, reached = {}, None
    for snd, rcv in ans:
        hops[snd.ttl] = rcv.src
        if ICMP in rcv and rcv[ICMP].type == 0:
            reached = snd.ttl if reached is None else min(reached, snd.ttl)
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
    delta = {k: s1.get(k, 0) - s0.get(k, 0) for k in s0}
    grew = {k: v for k, v in delta.items() if v > 0 and k != "carrier_changes"}
    if delta.get("carrier_changes", 0) > 0:
        rep.add("CRIT", "interfejs", f"Link flapował {delta['carrier_changes']}× podczas testu")
    if grew:
        sev = "WARN" if any(k in grew for k in ("rx_crc_errors", "rx_frame_errors", "collisions",
                                                  "rx_errors", "tx_errors")) else "INFO"
        rep.add(sev, "interfejs", f"Liczniki błędów wzrosły w ciągu {duration:.0f} s",
                [f"{k}: +{v}" for k, v in grew.items()])
    totals = {k: v for k, v in s1.items() if v and k != "carrier_changes"}
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
    ap.add_argument("--passive-only", action="store_true", help="tylko nasłuch, bez wysyłania pakietów")
    ap.add_argument("--force-scan", action="store_true", help="skanuj ARP także podsieci > /22")
    ap.add_argument("--no-trace", action="store_true", help="pomiń traceroute")
    ap.add_argument("--storm-warn", type=int, default=300, help="próg WARN broadcast pps (300)")
    ap.add_argument("--storm-crit", type=int, default=2000, help="próg CRIT broadcast pps (2000)")
    ap.add_argument("--loop-repeats", type=int, default=5, help="ile identycznych ramek = pętla (5)")
    ap.add_argument("--loop-window", type=float, default=1.0, help="okno wykrywania pętli [s] (1.0)")
    ap.add_argument("--json", help="zapisz raport do pliku JSON")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

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
    rep = Report()

    print(f"Interfejs: {iface}  MAC: {mac}  IP: {cidr or 'brak'}  brama: {gw or 'brak'}")
    s0 = read_stats(iface)
    t_begin = time.time()

    # --- faza 1: pasywna
    p = Passive(mac, args.loop_window, args.loop_repeats)
    sniffer = AsyncSniffer(iface=iface, prn=p.handle, store=False)
    sniffer.start()
    time.sleep(0.5)
    t_start = time.time()
    if not args.passive_only:
        try:  # sprowokuj Router Advertisement
            sendp(Ether(src=mac, dst="33:33:00:00:00:02") / IPv6(dst="ff02::2") / ICMPv6ND_RS(),
                  iface=iface, verbose=0)
        except Exception:  # noqa: BLE001
            pass
    try:
        for s in range(args.duration):
            print(f"\r[1/2] Nasłuch pasywny: {s + 1}/{args.duration} s, ramek: {p.total}", end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nPrzerwano nasłuch — analizuję zebrane dane.")
    duration = max(1, int(time.time() - t_start))
    sniffer.stop()
    print()
    analyze_passive(p, rep, duration, t_start, own_ip, gw, args)

    # --- faza 2: aktywna
    if not args.passive_only:
        steps = []
        if own_ip:
            steps += [("konflikt własnego IP", lambda: check_own_ip_conflict(iface, mac, own_ip, rep)),
                      ("skan ARP", lambda: arp_sweep(iface, net, gw, rep, args.force_scan))]
        steps += [("DHCP DISCOVER", lambda: dhcp_discover(iface, mac, rep, p.dhcp_servers)),
                  ("ping bramy", lambda: check_gateway(iface, gw, rep))]
        internet = {"ok": False}
        steps += [("ping internetu", lambda: internet.update(ok=check_internet(args.target, rep))),
                  ("DNS", lambda: check_dns(rep)),
                  ("Path MTU", lambda: internet["ok"] and check_pmtu(args.target, rep))]
        if not args.no_trace:
            steps.append(("traceroute", lambda: check_routing_loop(args.target, rep)))
        for n, (name, fn) in enumerate(steps, 1):
            print(f"[2/2] Test {n}/{len(steps)}: {name}...", flush=True)
            try:
                fn()
            except Exception as ex:  # noqa: BLE001
                rep.add("INFO", name, f"Test nie powiódł się: {ex}")

    analyze_iface(iface, s0, read_stats(iface), time.time() - t_begin, rep)
    if p.errors:
        rep.add("INFO", "skrypt", f"{p.errors} ramek nie udało się przeanalizować")

    rep.print(color)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "iface": iface, "ip": str(cidr),
                       "gateway": gw, "findings": [asdict(f) for f in rep.items]},
                      fh, ensure_ascii=False, indent=2)
        print(f"Raport JSON: {args.json}")

    sys.exit({0: 2, 1: 1}.get(rep.worst(), 0))


if __name__ == "__main__":
    main()
