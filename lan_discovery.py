#!/usr/bin/env python3
"""n1-monitor lan-discovery — identité LAN autonome.

Construit en continu une table vivante des appareils du LAN et l'écrit dans
``/run/n1-monitor-lan.json`` (lue par le collector pour nommer les IP, suivre
les services par MAC et détecter les collisions d'IP).

Aucune saisie, aucun credential. Croise trois sources autonomes :
  * mDNS : capture L2 (AF_PACKET, donc SOUS netfilter — voit le mDNS que le
    firewall droppe) → hostname ``.local`` + type d'appareil via les services
    annoncés (_googlecast, _workstation, _printer…).
  * ARP : /proc/net/arp + sweep ARP périodique léger → IP ↔ MAC + présence.
  * reverse-DNS + OUI (nmap-mac-prefixes) → noms et constructeur.

Tourne en root (CAP_NET_RAW) via systemd. Sandboxé par l'unit.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import socket
import struct
import threading
import time
from pathlib import Path

OUTPUT = Path("/run/n1-monitor-lan.json")
OUI_PATHS = (
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/share/ieee-data/oui.txt",
)
MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
DEVICE_TTL = 900.0        # un appareil disparaît de la table après 15 min sans signe
ARP_SWEEP_EVERY = 6       # sweep ARP actif tous les N cycles
WELLKNOWN = {
    "224.0.0.251": "mDNS (multicast)", "224.0.0.1": "all-hosts (multicast)",
    "224.0.0.22": "IGMP (multicast)", "239.255.255.250": "SSDP (multicast)",
    "255.255.255.255": "broadcast", "0.0.0.0": "this-network",
}

# Services mDNS → type d'appareil lisible.
SERVICE_TYPE = [
    ("_googlecast", "Cast / TV"), ("_androidtvremote", "Android TV"),
    ("_airplay", "Apple/AirPlay"), ("_raop", "Apple/AirPlay"),
    ("_companion-link", "Apple device"), ("_apple-mobdev", "Apple device"),
    ("_homekit", "HomeKit"), ("_hap", "HomeKit"),
    ("_spotify-connect", "Enceinte/Spotify"), ("_sonos", "Sonos"),
    ("_printer", "Imprimante"), ("_ipp", "Imprimante"), ("_pdl-datastream", "Imprimante"),
    ("_adb-tls-connect", "Android (adb)"), ("_adb", "Android (adb)"),
    ("_workstation", "PC / Linux"), ("_smb", "Partage fichiers"),
    ("_ssh", "Serveur SSH"), ("_sftp-ssh", "Serveur SSH"),
    ("_https", "Serveur web"), ("_http", "Serveur web"),
    ("_device-info", ""),  # informatif seulement
]
# hostnames → type, en dernier recours.
NAME_TYPE = [
    (re.compile(r"^(moto|pixel|galaxy|sm-|redmi|oneplus|huawei|honor|oppo|vivo)", re.I), "Téléphone Android"),
    (re.compile(r"(iphone|ipad)", re.I), "iPhone/iPad"),
    (re.compile(r"(macbook|imac|mac-)", re.I), "Mac"),
    (re.compile(r"(chromecast|nest|google-home)", re.I), "Cast / Google"),
    (re.compile(r"(mibox|aftt|firetv|shield|bravia|tv-)", re.I), "TV / box"),
    (re.compile(r"(printer|epson|canon|brother|hp-)", re.I), "Imprimante"),
]


# --------------------------------------------------------------------------- #
# OUI (constructeur depuis la MAC)
# --------------------------------------------------------------------------- #
def load_oui() -> dict:
    table: dict[str, str] = {}
    for p in OUI_PATHS:
        if not os.path.exists(p):
            continue
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                if p.endswith("nmap-mac-prefixes"):
                    for ln in f:
                        ln = ln.strip()
                        if not ln or ln.startswith("#"):
                            continue
                        parts = ln.split(None, 1)
                        if len(parts) == 2 and len(parts[0]) == 6:
                            table[parts[0].upper()] = parts[1].strip()
                else:  # oui.txt IEEE
                    for ln in f:
                        if "(hex)" in ln:
                            pre, _, vend = ln.partition("(hex)")
                            table[pre.strip().replace("-", "").upper()] = vend.strip()
            if table:
                break
        except OSError:
            continue
    return table


def is_local_mac(mac: str) -> bool:
    """MAC localement administrée (randomisée) = bit 0x02 du 1er octet."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def vendor_for(mac: str, oui: dict) -> str:
    if not mac:
        return ""
    if is_local_mac(mac):
        return "(MAC privée/randomisée)"
    pref = mac.replace(":", "").upper()[:6]
    return oui.get(pref, "")


# --------------------------------------------------------------------------- #
# Décodage mDNS
# --------------------------------------------------------------------------- #
DNS_TYPES = {1: "A", 12: "PTR", 16: "TXT", 28: "AAAA", 33: "SRV", 47: "NSEC"}


def dns_name(data: bytes, off: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    orig = off
    guard = 0
    while off < len(data) and guard < 128:
        guard += 1
        n = data[off]
        if n == 0:
            off += 1
            break
        if (n & 0xC0) == 0xC0:
            if off + 1 >= len(data):
                break
            ptr = ((n & 0x3F) << 8) | data[off + 1]
            if not jumped:
                orig = off + 2
            off = ptr
            jumped = True
            continue
        off += 1
        labels.append(data[off:off + n].decode("utf-8", "replace"))
        off += n
    return ".".join(labels), (orig if jumped else off)


def parse_mdns(data: bytes) -> dict:
    """Retourne {a:{host:ip}, services:set, models:set} extrait d'un paquet mDNS.

    Les services/types ne sont retenus que pour les RÉPONSES (bit QR=1) : un
    appareil qui *interroge* _googlecast n'est pas une TV, il en cherche une.
    """
    res = {"a": {}, "services": set(), "models": set()}
    if len(data) < 12:
        return res
    try:
        qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    except struct.error:
        return res
    is_response = bool(data[2] & 0x80)
    off = 12
    for _ in range(qd):  # questions : on saute (discovery, pas une offre de service)
        _nm, off = dns_name(data, off)
        off += 4
        if off > len(data):
            return res
    if not is_response:
        return res  # une requête ne décrit pas ce que l'émetteur offre
    for _ in range(an + ns + ar):
        nm, off = dns_name(data, off)
        if off + 10 > len(data):
            break
        typ, _cls, _ttl, rdl = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rd = data[off:off + rdl]
        off += rdl
        ts = DNS_TYPES.get(typ, str(typ))
        for tag, _t in SERVICE_TYPE:
            if tag in nm:
                res["services"].add(tag)
        try:
            if ts == "A" and len(rd) >= 4:
                res["a"][nm] = ".".join(map(str, rd[:4]))  # host.local -> ip
            elif ts == "TXT":
                i = 0
                while i < len(rd):
                    ln = rd[i]
                    i += 1
                    kv = rd[i:i + ln].decode("utf-8", "replace")
                    i += ln
                    low = kv.lower()
                    if low.startswith(("model=", "md=", "ty=", "fn=")):
                        res["models"].add(kv.split("=", 1)[1])
        except Exception:
            pass
    return res


# --------------------------------------------------------------------------- #
# Table des appareils
# --------------------------------------------------------------------------- #
class Inventory:
    def __init__(self, oui: dict, subnet: str = "") -> None:
        self.lock = threading.Lock()
        self.dev: dict[str, dict] = {}        # ip -> record
        self.oui = oui
        self.alerts: list[dict] = []
        self.name_to_ip: dict[str, str] = {}  # détection "nom réapparu à une autre IP"
        try:
            self.net = ipaddress.ip_network(subnet, strict=False) if subnet else None
        except ValueError:
            self.net = None

    def _type_from(self, rec: dict) -> str:
        for tag, label in SERVICE_TYPE:
            if label and tag in rec.get("services", []):
                return label
        name = rec.get("name", "")
        for rx, label in NAME_TYPE:
            if name and rx.search(name):
                return label
        if rec.get("models"):
            return next(iter(rec["models"]))
        return ""

    def touch(self, ip: str, *, mac: str = "", name: str = "",
              services: set | None = None, models: set | None = None,
              source: str = "") -> None:
        if not ip or ip.startswith(("224.", "239.", "255.")) or ip == "0.0.0.0":
            return
        if self.net is not None:  # ne garder que le LAN (mDNS capté sur d'autres liens ignoré)
            try:
                if ipaddress.ip_address(ip) not in self.net:
                    return
            except ValueError:
                return
        now = time.time()
        with self.lock:
            rec = self.dev.get(ip)
            if rec is None:
                rec = {"ip": ip, "mac": "", "name": "", "vendor": "",
                       "services": set(), "models": set(),
                       "first_seen": now, "last_seen": now, "sources": set()}
                self.dev[ip] = rec
            rec["last_seen"] = now
            if source:
                rec["sources"].add(source)
            if services:
                rec["services"] |= services
            if models:
                rec["models"] |= models
            if mac and mac != rec["mac"]:
                if rec["mac"] and rec["mac"] != mac:
                    # L'IP a changé d'appareil → collision / réattribution DHCP.
                    self.alerts.append({"ts": now, "kind": "mac-change", "ip": ip,
                                        "old": rec["mac"], "new": mac,
                                        "name": rec.get("name", "")})
                    self.alerts[:] = self.alerts[-50:]
                rec["mac"] = mac
                rec["vendor"] = vendor_for(mac, self.oui)
            if name and name != rec["name"]:
                short = name.split(".")[0]
                prev_ip = self.name_to_ip.get(short)
                if prev_ip and prev_ip != ip:
                    self.alerts.append({"ts": now, "kind": "ip-change", "ip": ip,
                                        "old": prev_ip, "new": ip, "name": short})
                    self.alerts[:] = self.alerts[-50:]
                self.name_to_ip[short] = ip
                rec["name"] = short

    def snapshot(self, iface: str, subnet: str) -> dict:
        now = time.time()
        with self.lock:
            for ip in list(self.dev):
                if now - self.dev[ip]["last_seen"] > DEVICE_TTL:
                    del self.dev[ip]
            devs = []
            by_ip = {}
            for ip, rec in self.dev.items():
                out = {
                    "ip": ip, "mac": rec["mac"], "name": rec["name"],
                    "vendor": rec["vendor"], "type": self._type_from(rec),
                    "services": sorted(rec["services"]),
                    "reachable": (now - rec["last_seen"]) < 120,
                    "first_seen": rec["first_seen"], "last_seen": rec["last_seen"],
                    "sources": sorted(rec["sources"]),
                }
                devs.append(out)
                by_ip[ip] = out
            alerts = list(self.alerts[-20:])
        devs.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")) if d["ip"].count(".") == 3 else (0,))
        return {"ts": now, "iface": iface, "subnet": subnet,
                "devices": devs, "by_ip": by_ip, "alerts": alerts}


# --------------------------------------------------------------------------- #
# Détection interface LAN
# --------------------------------------------------------------------------- #
def detect_lan() -> tuple[str, str, str, bytes]:
    """(iface, ip, subnet_cidr, mac_bytes) de l'interface LAN principale."""
    virt = re.compile(r"^(lo|veth|docker|br-|virbr|wg|tun|tap|vnet)")
    best = None
    try:
        import subprocess
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                             capture_output=True, text=True, timeout=5).stdout
    except Exception:
        out = ""
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) < 4:
            continue
        iface = parts[1]
        if virt.match(iface):
            continue
        cidr = parts[3]
        try:
            net = ipaddress.ip_interface(cidr)
        except ValueError:
            continue
        if net.ip.is_private and not net.ip.is_loopback:
            best = (iface, str(net.ip), str(net.network))
            break
    if not best:
        return ("", "", "", b"\x00" * 6)
    iface, ip, subnet = best
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            mac = bytes.fromhex(f.read().strip().replace(":", ""))
    except OSError:
        mac = b"\x00" * 6
    return iface, ip, subnet, mac


# --------------------------------------------------------------------------- #
# Lecture ARP + sweep actif
# --------------------------------------------------------------------------- #
def read_proc_arp(inv: Inventory, iface: str) -> None:
    try:
        with open("/proc/net/arp") as f:
            lines = f.read().splitlines()[1:]
    except OSError:
        return
    for ln in lines:
        f = ln.split()
        if len(f) < 6:
            continue
        ip, _hw, flags, mac, _mask, dev = f[:6]
        if dev != iface or mac == "00:00:00:00:00:00":
            continue
        if flags == "0x0":  # entrée incomplète
            continue
        inv.touch(ip, mac=mac.lower(), source="arp")


def _enc_name(name: str) -> bytes:
    out = b""
    for part in name.split("."):
        if part:
            b = part.encode()
            out += bytes([len(b)]) + b
    return out + b"\x00"


def _ip_udp_cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


# Requêtes d'énumération mDNS pour provoquer les annonces (au lieu d'attendre).
_MDNS_QUERY_NAMES = [
    "_services._dns-sd._udp.local", "_device-info._tcp.local",
    "_workstation._tcp.local", "_googlecast._tcp.local", "_airplay._tcp.local",
    "_companion-link._tcp.local", "_raop._tcp.local", "_spotify-connect._tcp.local",
    "_http._tcp.local", "_ssh._tcp.local", "_smb._tcp.local",
    "_printer._tcp.local", "_ipp._tcp.local", "_homekit._tcp.local",
]


def build_mdns_query(src_ip: str, src_mac: bytes) -> bytes:
    body = b"".join(_enc_name(n) + struct.pack(">HH", 12, 0x0001) for n in _MDNS_QUERY_NAMES)
    mdns = struct.pack(">HHHHHH", 0, 0, len(_MDNS_QUERY_NAMES), 0, 0, 0) + body
    udp_len = 8 + len(mdns)
    dst_ip = socket.inet_aton(MDNS_GROUP)
    s_ip = socket.inet_aton(src_ip)
    udp_nock = struct.pack(">HHHH", MDNS_PORT, MDNS_PORT, udp_len, 0) + mdns
    pseudo = s_ip + dst_ip + struct.pack(">BBH", 0, 17, udp_len)
    uck = _ip_udp_cksum(pseudo + udp_nock) or 0xFFFF
    udp = struct.pack(">HHHH", MDNS_PORT, MDNS_PORT, udp_len, uck) + mdns
    ip_len = 20 + udp_len
    iph = struct.pack(">BBHHHBBH4s4s", 0x45, 0, ip_len, 0x1234, 0, 255, 17, 0, s_ip, dst_ip)
    iph = struct.pack(">BBHHHBBH4s4s", 0x45, 0, ip_len, 0x1234, 0, 255, 17,
                      _ip_udp_cksum(iph), s_ip, dst_ip)
    dst_mac = bytes.fromhex("01005e0000fb")  # MAC multicast de 224.0.0.251
    return dst_mac + src_mac + struct.pack(">H", 0x0800) + iph + udp


def send_mdns_query(iface: str, src_ip: str, src_mac: bytes) -> None:
    if not src_ip:
        return
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((iface, 0))
        s.send(build_mdns_query(src_ip, src_mac))
        s.close()
    except OSError:
        pass


def arp_sweep(iface: str, src_ip: str, src_mac: bytes, subnet: str) -> None:
    """Envoie un ARP who-has à chaque hôte du /24 pour peupler la table ARP."""
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return
    if net.num_addresses > 1024:  # garde-fou : pas de sweep sur des plages énormes
        return
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((iface, 0))
    except OSError:
        return
    spa = socket.inet_aton(src_ip)
    eth = b"\xff" * 6 + src_mac + b"\x08\x06"
    for host in net.hosts():
        tpa = socket.inet_aton(str(host))
        arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) + src_mac + spa + b"\x00" * 6 + tpa
        try:
            s.send(eth + arp)
        except OSError:
            break
        time.sleep(0.003)
    s.close()


# --------------------------------------------------------------------------- #
# Threads
# --------------------------------------------------------------------------- #
def mdns_listener(inv: Inventory, stop: threading.Event) -> None:
    """Capture L2 d'emblée (voit le mDNS même droppé par le firewall) ;
    repli UDP multicast si AF_PACKET est indisponible (pas de CAP_NET_RAW)."""
    try:
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)).close()
        mdns_listener_l2(inv, stop)
        return
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
        s.bind(("", MDNS_PORT))
        mreq = struct.pack("4sl", socket.inet_aton(MDNS_GROUP), socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        s.settimeout(1.0)
    except OSError:
        return
    while not stop.is_set():
        try:
            data, addr = s.recvfrom(9000)
        except socket.timeout:
            continue
        _ingest_mdns(inv, addr[0], data)


def mdns_listener_l2(inv: Inventory, stop: threading.Event) -> None:
    """Capture mDNS au niveau 2 (voit ce que le firewall droppe)."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        s.settimeout(1.0)
    except OSError:
        return
    while not stop.is_set():
        try:
            raw, _ = s.recvfrom(65535)
        except socket.timeout:
            continue
        if len(raw) < 14 or struct.unpack(">H", raw[12:14])[0] != 0x0800:
            continue
        if raw[23] != 17:  # UDP
            continue
        ihl = (raw[14] & 0x0F) * 4
        src_ip = ".".join(map(str, raw[26:30]))
        uoff = 14 + ihl
        try:
            sport, dport = struct.unpack(">HH", raw[uoff:uoff + 4])
        except struct.error:
            continue
        if MDNS_PORT not in (sport, dport):
            continue
        src_mac = ":".join(f"{b:02x}" for b in raw[6:12])
        inv.touch(src_ip, mac=src_mac, source="mdns")
        _ingest_mdns(inv, src_ip, raw[uoff + 8:])


def _ingest_mdns(inv: Inventory, src_ip: str, payload: bytes) -> None:
    p = parse_mdns(payload)
    # A records : host.local -> ip (la source s'auto-nomme).
    for host, ip in p["a"].items():
        inv.touch(ip, name=host, source="mdns")
    name = ""
    for host, ip in p["a"].items():
        if ip == src_ip:
            name = host
            break
    inv.touch(src_ip, name=name, services=p["services"], models=p["models"], source="mdns")


def arp_thread(inv: Inventory, iface: str, src_ip: str, src_mac: bytes,
               subnet: str, interval: float, stop: threading.Event) -> None:
    cycle = 0
    while not stop.is_set():
        read_proc_arp(inv, iface)
        send_mdns_query(iface, src_ip, src_mac)  # provoque les annonces mDNS
        if cycle % ARP_SWEEP_EVERY == 0 and src_ip:
            arp_sweep(iface, src_ip, src_mac, subnet)
            time.sleep(1.0)  # laisse les réponses ARP arriver
            read_proc_arp(inv, iface)
        cycle += 1
        stop.wait(interval)


def rdns_thread(inv: Inventory, stop: threading.Event) -> None:
    socket.setdefaulttimeout(1.5)
    while not stop.is_set():
        with inv.lock:
            todo = [ip for ip, r in inv.dev.items() if not r["name"]]
        for ip in todo:
            if stop.is_set():
                return
            try:
                host = socket.gethostbyaddr(ip)[0]
            except (OSError, socket.error):
                host = ""
            if host:
                inv.touch(ip, name=host, source="rdns")
        stop.wait(60.0)


def write_atomic(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    with tmp.open("w") as f:
        json.dump(data, f, default=str)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=30.0, help="période ARP/écriture")
    ap.add_argument("--once", action="store_true", help="un seul cycle (debug)")
    args = ap.parse_args()

    iface, ip, subnet, mac = detect_lan()
    oui = load_oui()
    inv = Inventory(oui, subnet)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    if not iface:
        write_atomic(OUTPUT, {"ts": time.time(), "error": "no LAN interface detected",
                              "devices": [], "by_ip": {}, "alerts": []})
        return 1

    if args.once:
        read_proc_arp(inv, iface)
        if ip:
            arp_sweep(iface, ip, mac, subnet)
            time.sleep(2.0)
            read_proc_arp(inv, iface)
        write_atomic(OUTPUT, inv.snapshot(iface, subnet))
        return 0

    threading.Thread(target=mdns_listener, args=(inv, stop), daemon=True).start()
    threading.Thread(target=arp_thread,
                     args=(inv, iface, ip, mac, subnet, args.interval, stop),
                     daemon=True).start()
    threading.Thread(target=rdns_thread, args=(inv, stop), daemon=True).start()

    while not stop.is_set():
        try:
            write_atomic(OUTPUT, inv.snapshot(iface, subnet))
        except Exception as e:
            try:
                write_atomic(OUTPUT, {"ts": time.time(), "error": str(e),
                                      "devices": [], "by_ip": {}, "alerts": []})
            except Exception:
                pass
        stop.wait(5.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
