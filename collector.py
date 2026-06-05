#!/usr/bin/env python3
"""n1-monitor collector — agrège l'état firewall/réseau/VPN dans /run/n1-monitor.json.

Tourne en root via systemd. Écrit du JSON atomiquement toutes les ``--interval``
secondes. Un thread parallèle tail le journal kernel pour capter les drops
NFT en temps réel (reprise par curseur pour éviter le double-comptage au
redémarrage du tailer).

Métriques : firewall + drops glissants, sockets en écoute (+ détection de
nouveaux ports exposés), connexions établies (+ classification IP, reverse-DNS
caché, géoloc optionnelle), Mullvad, fail2ban, système (load, CPU %, CPU °C,
mémoire, disques, débit réseau par interface).
"""
from __future__ import annotations

import collections
import concurrent.futures
import errno
import glob
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

OUTPUT = Path("/run/n1-monitor.json")
LAN_OUT = Path("/run/n1-monitor-lan.json")  # table d'identité LAN (lan_discovery)
# IP multicast/broadcast bien connues, étiquetées telles quelles dans les drops.
WELLKNOWN = {
    "224.0.0.251": "mDNS", "224.0.0.1": "all-hosts", "224.0.0.22": "IGMP",
    "239.255.255.250": "SSDP", "255.255.255.255": "broadcast", "0.0.0.0": "this-net",
    "ff02::fb": "mDNS", "ff02::1": "all-nodes",
}
DROP_RE = re.compile(r"\[NFT-DROP-(?P<chain>IN|OUT|FWD)\]")
KV_RE = re.compile(r"(\w+)=(\S*)")
CHAIN_MAP = {"IN": "input", "OUT": "output", "FWD": "forward"}
PROTO_MAP = {"1": "icmp", "2": "igmp", "6": "tcp", "17": "udp"}

DROPS_MAX = 5000  # bornage mémoire
WINDOW_1M, WINDOW_5M, WINDOW_1H = 60, 300, 3600

NEW_EXPOSED_GRACE = 5.0     # ports vus dans les 5 premières s = baseline (pas "new")
NEW_EXPOSED_WINDOW = 300.0  # un port reste flaggé "new" pendant 5 min
RDNS_TTL = 3600.0           # cache reverse-DNS 1h
CGNAT = ipaddress.ip_network("100.64.0.0/10")

# Interfaces virtuelles ignorées pour le débit réseau.
VIRT_IFACE = re.compile(r"^(lo|veth|docker|br-|virbr)")
GEOIP_PATHS = (
    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    "/var/lib/GeoIP/GeoLite2-Country.mmdb",
)

# --- Infra / présence -------------------------------------------------------
HOSTS_CFG = Path(__file__).with_name("hosts.json")  # inventaire éditable
PROBE_TIMEOUT = 1.2        # s par sonde TCP
INFRA_INTERVAL = 10.0      # période du thread de sonde infra
HANDSHAKE_ALIVE = 180.0    # handshake wg < 3 min => peer vivant
EVENTS_MAX = 200           # transitions up/down conservées (ring + persistance)


# --------------------------------------------------------------------------- #
# Drops NFT (alimenté par le thread journal_tailer)
# --------------------------------------------------------------------------- #
class Drops:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.events: collections.deque = collections.deque(maxlen=DROPS_MAX)
        self.total = {"input": 0, "output": 0, "forward": 0}

    def add(self, ev: dict) -> None:
        with self.lock:
            self.events.append(ev)
            self.total[ev["chain"]] = self.total.get(ev["chain"], 0) + 1

    def snapshot(self, resolve=None) -> dict:
        """``resolve`` : callable IP -> nom lisible (None = pas de résolution)."""
        def nm(ip: str) -> str:
            return resolve(ip) if (resolve and ip) else ""
        now = time.time()
        cnt = {w: {"input": 0, "output": 0, "forward": 0} for w in ("1m", "5m", "1h")}
        agg: dict = {}
        with self.lock:
            for ev in self.events:
                age = now - ev["ts"]
                ch = ev["chain"]
                if age <= WINDOW_1M:
                    cnt["1m"][ch] += 1
                if age <= WINDOW_5M:
                    cnt["5m"][ch] += 1
                if age <= WINDOW_1H:
                    cnt["1h"][ch] += 1
                    key = (ch, ev.get("proto", "?"), ev.get("dport", "?"), ev.get("src", "?"))
                    agg[key] = agg.get(key, 0) + 1
            recent = list(self.events)[-30:]
            total = dict(self.total)
        top = sorted(agg.items(), key=lambda kv: -kv[1])[:10]
        return {
            "drops_1m": cnt["1m"],
            "drops_5m": cnt["5m"],
            "drops_1h": cnt["1h"],
            "drops_total": total,
            "top_dropped": [
                {"chain": k[0], "proto": k[1], "dport": k[2], "src": k[3],
                 "src_name": nm(k[3]), "count": v}
                for k, v in top
            ],
            "recent": [
                {**{k: v for k, v in ev.items() if k != "raw"},
                 "src_name": nm(ev.get("src", "")), "dst_name": nm(ev.get("dst", ""))}
                for ev in recent
            ],
        }


def parse_drop(line: str, ts: float | None = None) -> dict | None:
    m = DROP_RE.search(line)
    if not m:
        return None
    kv = dict(KV_RE.findall(line))
    proto = kv.get("PROTO", "?")
    if proto.isdigit():
        proto = PROTO_MAP.get(proto, proto)
    return {
        "ts": ts if ts is not None else time.time(),
        "chain": CHAIN_MAP[m.group("chain")],
        "iif": kv.get("IN", ""),
        "oif": kv.get("OUT", ""),
        "src": kv.get("SRC", ""),
        "dst": kv.get("DST", ""),
        "proto": proto.lower(),
        "sport": kv.get("SPT", ""),
        "dport": kv.get("DPT", ""),
    }


def journal_tailer(drops: Drops, state: "State", stop: threading.Event) -> None:
    """Tail le journal kernel en JSON ; reprend au curseur après un crash.

    Premier démarrage : ``--since -1h`` pour pré-charger les compteurs glissants.
    Redémarrages : ``--after-cursor`` pour ne pas recompter les lignes déjà vues.
    """
    base = ["journalctl", "-kf", "-o", "json", "--no-pager"]
    while not stop.is_set():
        cmd = base + (["--after-cursor", state.cursor] if state.cursor else ["--since", "-1h"])
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            assert p.stdout is not None
            for line in p.stdout:
                if stop.is_set():
                    p.terminate()
                    return
                try:
                    obj = json.loads(line)
                except (ValueError, TypeError):
                    continue
                cur = obj.get("__CURSOR")
                if cur:
                    state.cursor = cur  # écrit uniquement par ce thread
                msg = obj.get("MESSAGE", "")
                if isinstance(msg, list):  # journald encode parfois MESSAGE en octets
                    try:
                        msg = bytes(msg).decode("utf-8", "replace")
                    except (ValueError, TypeError):
                        continue
                ts = None
                rt = obj.get("__REALTIME_TIMESTAMP")
                if rt:
                    try:
                        ts = int(rt) / 1e6
                    except (ValueError, TypeError):
                        ts = None
                ev = parse_drop(msg, ts)
                if ev:
                    drops.add(ev)
        except Exception:
            time.sleep(2)


# --------------------------------------------------------------------------- #
# Reverse-DNS caché + géoloc optionnelle
# --------------------------------------------------------------------------- #
def ip_class(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "other"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link-local"
    if a.is_multicast:
        return "multicast"
    if a.version == 4 and a in CGNAT:
        return "cgnat"
    if a.is_private:
        return "private"
    return "public"


class RdnsCache:
    """Résout les PTR dans un thread dédié ; le boucle principale ne bloque jamais."""

    def __init__(self, ttl: float = RDNS_TTL) -> None:
        self.ttl = ttl
        self.lock = threading.Lock()
        self.cache: dict[str, tuple[str, float]] = {}
        self.queue: collections.deque = collections.deque()
        self.qset: set[str] = set()
        self.wake = threading.Event()

    def get(self, ip: str) -> str:
        now = time.time()
        with self.lock:
            ent = self.cache.get(ip)
            if ent and now - ent[1] < self.ttl:
                return ent[0]
            if ip not in self.qset:
                self.qset.add(ip)
                self.queue.append(ip)
                self.wake.set()
            return ent[0] if ent else ""

    def worker(self, stop: threading.Event) -> None:
        socket.setdefaulttimeout(1.5)  # best-effort (glibc peut dépasser)
        while not stop.is_set():
            self.wake.wait(1.0)
            if stop.is_set():
                return
            with self.lock:
                ip = self.queue.popleft() if self.queue else None
                if not self.queue:
                    self.wake.clear()
            if not ip:
                continue
            host = ""
            try:
                host = socket.gethostbyaddr(ip)[0]
            except (OSError, socket.error):
                host = ""
            with self.lock:
                self.cache[ip] = (host, time.time())
                self.qset.discard(ip)


class GeoIP:
    """Géoloc pays optionnelle : active uniquement si geoip2 + un .mmdb sont présents."""

    def __init__(self) -> None:
        self.reader = None
        self.tried = False

    def country(self, ip: str) -> str:
        if not self.tried:
            self.tried = True
            try:
                import geoip2.database  # type: ignore
                for p in GEOIP_PATHS:
                    if os.path.exists(p):
                        self.reader = geoip2.database.Reader(p)
                        break
            except Exception:
                self.reader = None
        if not self.reader:
            return ""
        try:
            return self.reader.country(ip).country.iso_code or ""
        except Exception:
            return ""


# --------------------------------------------------------------------------- #
# Infra : inventaire, sonde de présence, journal persistant, ntfy, wireguard
# --------------------------------------------------------------------------- #
class Ntfy:
    """Notification ntfy best-effort (POST async, n'échoue jamais bruyamment)."""

    def __init__(self, cfg: dict) -> None:
        self.enabled = bool(cfg.get("enabled"))
        url = (cfg.get("url") or "").rstrip("/")
        topic = cfg.get("topic") or ""
        self.endpoint = f"{url}/{topic}" if url and topic else url

    def send(self, title: str, msg: str, tags: str = "", priority: str = "default") -> None:
        if not self.enabled or not self.endpoint:
            return

        def _post() -> None:
            try:
                # Headers ntfy en latin-1 : titre ASCII only, l'emoji vient des Tags.
                req = urllib.request.Request(
                    self.endpoint,
                    data=msg.encode("utf-8"),
                    method="POST",
                    headers={"Title": title.encode("ascii", "ignore").decode(),
                             "Tags": tags, "Priority": priority},
                )
                urllib.request.urlopen(req, timeout=3)
            except Exception:
                pass

        threading.Thread(target=_post, daemon=True).start()


def resolve_state_dir() -> Path:
    """Répertoire du journal de présence. Préfère un emplacement persistant
    (StateDirectory systemd / /var/lib) ; retombe sur /run si non inscriptible."""
    candidates = []
    env = os.environ.get("STATE_DIRECTORY")
    if env:
        candidates.append(Path(env.split(":")[0]))
    candidates += [Path("/var/lib/n1-monitor"), Path("/run/n1-monitor")]
    for p in candidates:
        try:
            p.mkdir(parents=True, exist_ok=True)
            probe = p / ".wtest"
            probe.touch()
            probe.unlink()
            return p
        except OSError:
            continue
    return Path("/run")


def ping(ip: str) -> bool:
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "1", "-n", ip],
                           capture_output=True, timeout=3)
        return r.returncode == 0
    except Exception:
        return False


def probe_host(host: dict, lan_by_ip: dict | None = None, expected_mac: str = "") -> dict:
    """Sonde un hôte (mode strict). Statuts :
      up           : le port de service répond (connexion établie) ;
      service-down : l'hôte est joignable (ping/RST) mais le service est muet ;
      wrong-device : l'IP est tenue par un AUTRE appareil (MAC != attendue) ;
      down         : l'hôte ne répond pas du tout ;
      unreachable  : pas de route depuis n1.
    Un appareil qui répond juste au ping ne fait donc PLUS passer un serveur
    pour 'up' (fini les faux verts type 'le tél a pris l'IP du serveur')."""
    name = host.get("name", "?")
    ip = host.get("ip")
    pr = host.get("probe") or {}
    res = {"name": name, "status": "unknown", "rtt_ms": None, "port_closed": False}
    if not ip:
        return res
    occ = (lan_by_ip or {}).get(ip) or {}
    occ_mac = (occ.get("mac") or "").lower()
    res["mac"] = occ_mac

    if pr.get("type") == "icmp":
        res["status"] = "up" if ping(ip) else "down"
    else:
        port = int(pr.get("port", 22))
        res["port"] = port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(PROBE_TIMEOUT)
        t0 = time.time()
        try:
            s.connect((ip, port))
            res["status"] = "up"
            res["rtt_ms"] = round((time.time() - t0) * 1000)
        except ConnectionRefusedError:
            # L'hôte a répondu (RST) mais rien n'écoute sur le port de service.
            res["status"] = "service-down"
            res["port_closed"] = True
            res["rtt_ms"] = round((time.time() - t0) * 1000)
        except (socket.timeout, TimeoutError):
            # Muet sur le port : joignable au ping = service-down, sinon down.
            res["status"] = "service-down" if ping(ip) else "down"
            res["port_closed"] = True
        except OSError as e:
            res["status"] = ("unreachable"
                             if e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH) else "down")
        finally:
            s.close()

    # Croisement MAC : si l'IP est occupée par un appareil dont la MAC ne
    # correspond pas à celle attendue, c'est qu'un autre appareil a pris l'IP.
    if res["status"] != "up" and expected_mac and occ_mac and occ_mac != expected_mac.lower():
        res["status"] = "wrong-device"
    if res["status"] in ("service-down", "wrong-device", "down") and occ:
        res["occupant"] = {"name": occ.get("name", ""), "mac": occ_mac,
                           "vendor": occ.get("vendor", ""), "type": occ.get("type", "")}
    return res


def collect_wg(ifaces: list) -> list:
    """Handshakes WireGuard via `wg show <if> dump` (root). age < 3 min = vivant."""
    res = []
    now = time.time()
    for iface in ifaces:
        out = run(["wg", "show", iface, "dump"])
        if not out:
            continue
        for ln in out.splitlines()[1:]:  # 1ère ligne = l'interface elle-même
            f = ln.split("\t")
            if len(f) < 5:
                continue
            endpoint = f[2]
            try:
                hs = int(f[4])
            except ValueError:
                hs = 0
            age = (now - hs) if hs else None
            res.append({
                "iface": iface,
                "endpoint": "" if endpoint == "(none)" else endpoint,
                "age": round(age) if age is not None else None,
                "alive": age is not None and age < HANDSHAKE_ALIVE,
            })
    return res


def load_presence(path: Path, host_status: dict, events: collections.deque) -> None:
    """Restaure le dernier état connu + le ring d'événements au démarrage."""
    if not path.exists():
        return
    try:
        lines = path.read_text().splitlines()[-EVENTS_MAX:]
    except OSError:
        return
    for ln in lines:
        try:
            ev = json.loads(ln)
        except ValueError:
            continue
        events.append(ev)
        h = ev.get("host")
        if h:
            up = ev.get("to") == "up"
            host_status[h] = {"status": "up" if up else "down", "is_up": up,
                              "since": ev.get("ts"), "last_change": ev.get("ts")}


def infra_prober(state: "State", stop: threading.Event) -> None:
    """Thread dédié : sonde l'inventaire, met à jour présence + ring + ntfy,
    publie un snapshot dans state.infra_cache (lu tel quel par la boucle principale)."""
    while not stop.is_set():
        try:
            cfg = state.load_hosts()
            state.load_lan()
            lan_by_ip = state.lan_by_ip()
            hosts = cfg.get("hosts", [])
            results: dict = {}
            if hosts:
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(hosts))) as ex:
                    futs = {}
                    for h in hosts:
                        exp = (h.get("mac") or state.host_macs.get(h.get("name", ""), ""))
                        futs[ex.submit(probe_host, h, lan_by_ip, exp)] = h.get("name", "?")
                    for fut, name in futs.items():
                        try:
                            r = fut.result(timeout=PROBE_TIMEOUT + 4)
                        except Exception:
                            r = {"name": name, "status": "unknown", "rtt_ms": None, "port_closed": False}
                        results[r.get("name", name)] = r
            now = time.time()
            host_out = []
            summary = {"up": 0, "service-down": 0, "wrong-device": 0,
                       "down": 0, "unreachable": 0, "unknown": 0, "total": 0}
            for h in hosts:
                name = h["name"]
                r = results.get(name, {"status": "unknown", "rtt_ms": None, "port_closed": False})
                status = r["status"]
                # Apprend la MAC légitime quand le service répond vraiment.
                if status == "up" and r.get("mac"):
                    state.host_macs[name] = r["mac"]
                occ = r.get("occupant") or {}
                if occ:  # nom cohérent avec le resolver (label curé > découverte)
                    occ["name"] = state.resolve_name(h.get("ip", "")) or occ.get("name", "")
                detail = ""
                if status == "wrong-device":
                    who = occ.get("name") or occ.get("vendor") or occ.get("mac") or "inconnu"
                    detail = f"IP tenue par un autre appareil ({who})"
                elif status == "service-down":
                    detail = "hôte joignable mais service muet"
                state.update_presence(name, status, now, bool(h.get("alert", False)), h, detail)
                rec = state.host_status.get(name, {})
                summary[status if status in summary else "unknown"] += 1
                summary["total"] += 1
                host_out.append({
                    "name": name, "ip": h.get("ip"), "group": h.get("group", "other"),
                    "role": h.get("role", ""), "status": status, "is_up": status == "up",
                    "since": rec.get("since"), "last_change": rec.get("last_change"),
                    "rtt_ms": r.get("rtt_ms"), "port_closed": r.get("port_closed", False),
                    "mac": r.get("mac", ""), "occupant": occ, "detail": detail,
                    "alert": bool(h.get("alert", False)),
                })
            state.infra_cache = {
                "ts": now,
                "hosts": host_out,
                "summary": summary,
                "events": list(state.infra_events)[-30:],
                "wg": collect_wg(cfg.get("wg_ifaces", [])),
                "persistent": state.presence_persistent,
            }
        except Exception as e:
            state.infra_cache = {"ts": time.time(), "error": str(e), "hosts": [], "summary": {}}
        stop.wait(INFRA_INTERVAL)


# --------------------------------------------------------------------------- #
# État inter-cycles (compteurs réseau/CPU, baseline ports exposés, curseur)
# --------------------------------------------------------------------------- #
class State:
    def __init__(self) -> None:
        self.started = time.time()
        self.net_prev: dict[str, tuple[int, int, float]] = {}
        self.cpu_prev: tuple[int, int] | None = None
        self.exposed_first: dict[tuple[str, int], float] = {}
        self.cursor: str | None = None
        self.rdns = RdnsCache()
        self.geo = GeoIP()
        # Identité LAN autonome (alimentée par lan_discovery)
        self.lan: dict = {}
        self.lan_mtime: float | None = None
        self.lan_alerts_seen: set[tuple] = set()
        self.host_macs: dict[str, str] = {}  # MAC apprise quand un hôte est réellement UP
        # Infra / présence
        self.hosts_cfg: dict | None = None
        self.hosts_mtime: float | None = None
        self.name_map: dict[str, str] = {}      # IP -> nom inventaire (hosts[])
        self.override_map: dict[str, str] = {}  # IP -> label explicite (lan_names)
        self.ntfy = Ntfy({})
        self.host_status: dict[str, dict] = {}
        self.infra_events: collections.deque = collections.deque(maxlen=EVENTS_MAX)
        self.infra_cache: dict = {}
        self.updates: dict = {}  # paquets upgradables (rafraîchi par updates_prober)
        self.state_dir = resolve_state_dir()
        self.presence_path = self.state_dir / "presence.jsonl"
        self.presence_persistent = not str(self.state_dir).startswith("/run")
        load_presence(self.presence_path, self.host_status, self.infra_events)
        self.load_hosts()

    def load_hosts(self) -> dict:
        """Recharge hosts.json si son mtime a changé (édition à chaud)."""
        try:
            m = HOSTS_CFG.stat().st_mtime
        except OSError:
            return self.hosts_cfg or {"hosts": [], "wg_ifaces": [], "ntfy": {}}
        if self.hosts_cfg is None or m != self.hosts_mtime:
            try:
                with HOSTS_CFG.open() as f:
                    self.hosts_cfg = json.load(f)
                self.hosts_mtime = m
                self.ntfy = Ntfy(self.hosts_cfg.get("ntfy", {}))
                self._build_name_map()
            except (OSError, ValueError):
                if self.hosts_cfg is None:
                    self.hosts_cfg = {"hosts": [], "wg_ifaces": [], "ntfy": {}}
        return self.hosts_cfg

    def _build_name_map(self) -> None:
        """Construit l'inventaire (hosts[]) et les labels explicites (lan_names)."""
        cfg = self.hosts_cfg or {}
        self.name_map = {h["ip"]: h["name"] for h in cfg.get("hosts", [])
                         if h.get("ip") and h.get("name")}
        self.override_map = {ip: name for ip, name in (cfg.get("lan_names") or {}).items()
                             if ip and name and not ip.startswith("_")}

    def load_lan(self) -> dict:
        """Recharge /run/n1-monitor-lan.json quand son mtime change (peu coûteux)."""
        try:
            m = LAN_OUT.stat().st_mtime
        except OSError:
            return self.lan
        if m != self.lan_mtime:
            try:
                with LAN_OUT.open() as f:
                    self.lan = json.load(f)
                self.lan_mtime = m
            except (OSError, ValueError):
                pass
        return self.lan

    def lan_by_ip(self) -> dict:
        return (self.lan or {}).get("by_ip", {}) or {}

    def resolve_name(self, ip: str) -> str:
        """Nom lisible pour une IP. Ordre : multicast connu > labels curés
        (lan_names puis inventaire hosts) > découverte LAN (mDNS/ARP) >
        type/constructeur > reverse-DNS. Les noms curés priment sur la
        découverte (qui sort parfois des UUID/Android_xxxx peu lisibles)."""
        if not ip:
            return ""
        if ip in WELLKNOWN:
            return WELLKNOWN[ip]
        if ip in self.override_map:        # label manuel explicite (lan_names)
            return self.override_map[ip]
        if ip in self.name_map:            # nom d'inventaire (hosts[])
            return self.name_map[ip]
        rec = self.lan_by_ip().get(ip)
        if rec and rec.get("name"):        # découverte autonome
            return rec["name"]
        if rec:
            t = rec.get("type") or rec.get("vendor")
            if t:
                return t
        h = self.rdns.get(ip)
        if h:
            return h.split(".")[0]
        return ""

    def new_lan_alerts(self) -> list:
        """Alertes de découverte (collision/changement d'IP) pas encore notifiées."""
        out = []
        for a in (self.lan or {}).get("alerts", []):
            sig = (a.get("kind"), a.get("ip"), a.get("old"), a.get("new"))
            if sig in self.lan_alerts_seen:
                continue
            self.lan_alerts_seen.add(sig)
            out.append(a)
        return out

    def _persist_event(self, ev: dict) -> None:
        try:
            with self.presence_path.open("a") as f:
                f.write(json.dumps(ev, default=str) + "\n")
        except OSError:
            pass

    def update_presence(self, name: str, status: str, now: float,
                        alertable: bool, host: dict, detail: str = "") -> None:
        """Met à jour l'état d'un hôte ; sur transition up<->down : ring +
        journal persistant + ntfy (si alertable). ``detail`` précise la cause
        (service muet, mauvais appareil…)."""
        is_up = status == "up"
        rec = self.host_status.get(name)
        if rec is None:
            # Baseline au premier passage : pas d'événement ni de notif.
            self.host_status[name] = {"status": status, "is_up": is_up,
                                      "since": now, "last_change": now}
            return
        rec["status"] = status
        if is_up == rec["is_up"]:
            return
        rec["is_up"] = is_up
        rec["since"] = now
        rec["last_change"] = now
        ev = {"ts": now, "host": name, "ip": host.get("ip"),
              "role": host.get("role", ""), "to": "up" if is_up else "down",
              "status": status, "detail": detail, "alert": alertable}
        self.infra_events.append(ev)
        self._persist_event(ev)
        if alertable:
            verb = "de retour" if is_up else (detail or "injoignable")
            body = f"{host.get('ip', '')} - {host.get('role', '')}"
            if detail and not is_up:
                body = f"{detail} — {body}"
            self.ntfy.send(
                f"{name} {verb}" if is_up else f"{name} : {verb}",
                body,
                tags="white_check_mark" if is_up else "rotating_light",
                priority="default" if is_up else "high",
            )


def run(cmd: list[str], timeout: int = 5) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def fw_active() -> bool:
    out = run(["nft", "list", "tables"])
    return "inet hardening" in out


# --------------------------------------------------------------------------- #
# Sockets en écoute (+ détection nouveaux ports exposés)
# --------------------------------------------------------------------------- #
def collect_listening(state: State) -> list:
    """Sockets en écoute, avec flag exposed_lan si bind 0.0.0.0/:: ."""
    out = run(["ss", "-tulnpH"])  # H = no header
    listeners = []
    now = time.time()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, _state, _rq, _sq, local = parts[:5]
        proc = parts[6] if len(parts) > 6 else ""
        if ":" not in local:
            continue
        addr, port = local.rsplit(":", 1)
        addr = addr.strip("[]")
        try:
            port_n = int(port)
        except ValueError:
            continue
        comm = ""
        pid = None
        m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', proc)
        if m:
            comm = m.group(1)
            pid = int(m.group(2))
        exposed = addr in ("0.0.0.0", "*", "::") and port_n < 49152
        first_seen = None
        is_new = False
        if exposed:
            key = (proto, port_n)
            first = state.exposed_first.get(key)
            if first is None:
                # Vu dans la fenêtre de grâce initiale => baseline, sinon nouveau.
                first = state.started if (now - state.started) <= NEW_EXPOSED_GRACE else now
                state.exposed_first[key] = first
            first_seen = first
            is_new = first > state.started + NEW_EXPOSED_GRACE and (now - first) <= NEW_EXPOSED_WINDOW
        listeners.append(
            {
                "proto": proto,
                "addr": addr,
                "port": port_n,
                "pid": pid,
                "comm": comm,
                "exposed_lan": exposed,
                "first_seen": first_seen,
                "new": is_new,
            }
        )
    listeners.sort(key=lambda x: (not x["exposed_lan"], not x["new"], x["port"]))
    return listeners


# --------------------------------------------------------------------------- #
# Connexions établies (+ classification / reverse-DNS / géoloc)
# --------------------------------------------------------------------------- #
def collect_established(state: State) -> dict:
    out = run(["ss", "-tnpH", "state", "established"])
    conns = []
    by_proc: dict = {}
    by_remote: dict = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        _rq, _sq, local, peer = parts[:4]
        proc = parts[4] if len(parts) > 4 else ""
        comm = ""
        pid = None
        user_uid = None
        m = re.search(r'users:\(\("([^"]+)",pid=(\d+),fd=\d+\)\)', proc)
        if m:
            comm = m.group(1)
            pid = int(m.group(2))
        if pid is not None:
            try:
                user_uid = os.stat(f"/proc/{pid}").st_uid
            except OSError:
                pass
        rip = peer.rsplit(":", 1)[0].strip("[]")
        cls = ip_class(rip)
        public = cls == "public"
        rhost = state.rdns.get(rip) if public else ""
        rname = state.resolve_name(rip)  # nom LAN (mDNS/inventaire) si dispo
        country = state.geo.country(rip) if public else ""
        conns.append(
            {
                "proto": "tcp",
                "local": local,
                "remote": peer,
                "rip": rip,
                "rclass": cls,
                "rhost": rhost,
                "rname": rname,
                "country": country,
                "comm": comm,
                "pid": pid,
                "uid": user_uid,
            }
        )
        if comm:
            by_proc[comm] = by_proc.get(comm, 0) + 1
        if public:
            r = by_remote.setdefault(rip, {"count": 0, "rhost": rhost, "country": country, "comm": comm})
            r["count"] += 1
            if rhost and not r["rhost"]:
                r["rhost"] = rhost
    top = sorted(by_proc.items(), key=lambda kv: -kv[1])[:10]
    top_remote = sorted(by_remote.items(), key=lambda kv: -kv[1]["count"])[:10]
    return {
        "count": len(conns),
        "by_process": [{"comm": k, "count": v} for k, v in top],
        "top_remote": [
            {"ip": ip, "count": r["count"], "rhost": r["rhost"], "country": r["country"], "comm": r["comm"]}
            for ip, r in top_remote
        ],
        "sample": conns[:40],
    }


def collect_mullvad() -> dict:
    out = run(["mullvad", "status"])
    connected = "Connected" in out
    relay = ""
    ip = ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Relay:"):
            relay = line.split(":", 1)[1].strip()
        elif line.startswith("Visible location:"):
            ip_m = re.search(r"IPv4:\s*(\S+)", line)
            if ip_m:
                ip = ip_m.group(1)
    lock = run(["mullvad", "lockdown-mode", "get"]).strip()
    lockdown = "on" in lock.lower() and "off" not in lock.lower()
    if "Block traffic when the VPN is disconnected: on" in lock:
        lockdown = True
    elif "Block traffic when the VPN is disconnected: off" in lock:
        lockdown = False
    return {"connected": connected, "relay": relay, "ip": ip, "lockdown": lockdown}


def collect_fail2ban() -> dict:
    out = run(["fail2ban-client", "status"])
    jails = []
    jl = re.search(r"Jail list:\s*(.+)", out)
    if jl:
        for j in [x.strip() for x in jl.group(1).split(",") if x.strip()]:
            jout = run(["fail2ban-client", "status", j])
            currently = re.search(r"Currently banned:\s*(\d+)", jout)
            total = re.search(r"Total banned:\s*(\d+)", jout)
            failed = re.search(r"Total failed:\s*(\d+)", jout)
            jails.append(
                {
                    "name": j,
                    "banned": int(currently.group(1)) if currently else 0,
                    "total_banned": int(total.group(1)) if total else 0,
                    "total_failed": int(failed.group(1)) if failed else 0,
                }
            )
    return {"jails": jails}


# --------------------------------------------------------------------------- #
# Système : load, CPU %, CPU °C, mémoire, disques, débit réseau
# --------------------------------------------------------------------------- #
def read_cpu_pct(state: State) -> float | None:
    try:
        with open("/proc/stat") as f:
            fields = [int(x) for x in f.readline().split()[1:]]
    except (OSError, ValueError):
        return None
    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)  # idle + iowait
    total = sum(fields)
    prev = state.cpu_prev
    state.cpu_prev = (idle, total)
    if prev is None:
        return None
    dt = total - prev[1]
    di = idle - prev[0]
    if dt <= 0:
        return None
    return round(100.0 * (1 - di / dt), 1)


def read_cpu_temp() -> float | None:
    cpu_names = {"k10temp", "zenpower", "coretemp", "cpu_thermal"}
    for hw in sorted(glob.glob("/sys/class/hwmon/hwmon*")):
        try:
            with open(os.path.join(hw, "name")) as f:
                name = f.read().strip()
        except OSError:
            continue
        if name not in cpu_names:
            continue
        fallback = None
        for inp in sorted(glob.glob(os.path.join(hw, "temp*_input"))):
            label = ""
            try:
                with open(inp[:-len("_input")] + "_label") as f:
                    label = f.read().strip()
            except OSError:
                pass
            try:
                with open(inp) as f:
                    val = int(f.read()) / 1000.0
            except (OSError, ValueError):
                continue
            if label in ("Tdie", "Tctl", "Package id 0"):
                return round(val, 1)
            if fallback is None:
                fallback = val
        if fallback is not None:
            return round(fallback, 1)
    # Repli : thermal_zone de type x86_pkg_temp / cpu.
    for tz in sorted(glob.glob("/sys/class/thermal/thermal_zone*")):
        try:
            with open(os.path.join(tz, "type")) as f:
                t = f.read().strip().lower()
            if "x86_pkg" in t or "cpu" in t:
                with open(os.path.join(tz, "temp")) as f:
                    return round(int(f.read()) / 1000.0, 1)
        except (OSError, ValueError):
            continue
    return None


def read_net(state: State) -> dict:
    now = time.time()
    out: dict = {}
    try:
        with open("/proc/net/dev") as f:
            lines = f.read().splitlines()[2:]
    except OSError:
        return out
    for line in lines:
        name, _, rest = line.partition(":")
        name = name.strip()
        if not name or VIRT_IFACE.match(name):
            continue
        fields = rest.split()
        if len(fields) < 16:
            continue
        try:
            rx, tx = int(fields[0]), int(fields[8])
        except ValueError:
            continue
        prev = state.net_prev.get(name)
        state.net_prev[name] = (rx, tx, now)
        rx_bps = tx_bps = 0.0
        if prev:
            dt = now - prev[2]
            if dt > 0:
                rx_bps = max(0.0, (rx - prev[0]) / dt)
                tx_bps = max(0.0, (tx - prev[1]) / dt)
        out[name] = {
            "rx_bps": round(rx_bps),
            "tx_bps": round(tx_bps),
            "rx_total": rx,
            "tx_total": tx,
        }
    return out


def collect_system(state: State) -> dict:
    try:
        with open("/proc/loadavg") as f:
            load = f.read().split()[:3]
    except OSError:
        load = ["?", "?", "?"]
    mi: dict = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, rest = line.partition(":")
                v = rest.strip().split()
                if v and v[0].isdigit():
                    mi[k] = int(v[0])
        total = mi.get("MemTotal", 0) / 1024 / 1024
        avail = mi.get("MemAvailable", 0) / 1024 / 1024
        used = max(0.0, total - avail)
    except OSError:
        total = avail = used = 0.0
    disk = {}
    for mnt in ("/", "/home", "/mnt/sda1"):
        try:
            st = os.statvfs(mnt)
            disk[mnt] = {
                "used_pct": int(100 * (1 - st.f_bavail / st.f_blocks)),
                "free_gib": round(st.f_bavail * st.f_frsize / (1024 ** 3), 1),
            }
        except OSError:
            pass
    try:
        with open("/proc/uptime") as f:
            uptime = float(f.read().split()[0])
    except OSError:
        uptime = 0.0
    swap_total = mi.get("SwapTotal", 0) / 1024 / 1024
    swap_used = max(0.0, swap_total - mi.get("SwapFree", 0) / 1024 / 1024)
    return {
        "load": load,
        "cores": os.cpu_count() or 1,
        "uptime": round(uptime),
        "cpu_pct": read_cpu_pct(state),
        "cpu_temp": read_cpu_temp(),
        "mem_gib": {"used": round(used, 1), "total": round(total, 1)},
        "swap_gib": {"used": round(swap_used, 1), "total": round(swap_total, 1)},
        "disk": disk,
        "net": read_net(state),
    }


def collect_health() -> dict:
    """Services systemd en échec + reboot requis + sessions ouvertes."""
    failed = []
    for ln in run(["systemctl", "--failed", "--no-legend", "--plain"]).splitlines():
        f = ln.split()
        if f and f[0].endswith((".service", ".timer", ".socket", ".mount")):
            failed.append(f[0])
    reboot = os.path.exists("/var/run/reboot-required") or os.path.exists("/run/reboot-required")
    users = []
    for ln in run(["who"]).splitlines():
        f = ln.split()
        if len(f) < 2:
            continue
        remote = f[-1].strip("()") if f[-1].startswith("(") and f[-1].endswith(")") else ""
        users.append({"user": f[0], "tty": f[1], "from": remote, "remote": bool(remote)})
    return {
        "failed_units": failed,
        "reboot_required": reboot,
        "sessions": {
            "count": len(users),
            "ssh": sum(1 for u in users if u["remote"]),
            "users": users,
        },
    }


def collect_updates() -> dict:
    """Paquets upgradables (total + sécurité). Lent (apt) → thread dédié."""
    insts = [ln for ln in run(["apt-get", "-s", "upgrade"], timeout=40).splitlines()
             if ln.startswith("Inst ")]
    sec = sum(1 for ln in insts if "security" in ln.lower())
    return {"total": len(insts), "security": sec}


def updates_prober(state: "State", stop: threading.Event) -> None:
    """Rafraîchit l'inventaire des paquets upgradables (apt lent) hors boucle principale."""
    while not stop.is_set():
        try:
            state.updates = collect_updates()
        except Exception as e:
            state.updates = {"error": str(e)}
        stop.wait(1800.0)  # 30 min


def write_atomic(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    with tmp.open("w") as f:
        json.dump(data, f, default=str)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


class TTL:
    """Mémoïse un appel coûteux (mullvad/fail2ban) pendant ``ttl`` secondes."""

    def __init__(self, fn, ttl: float) -> None:
        self.fn = fn
        self.ttl = ttl
        self.ts = 0.0
        self.val = None

    def get(self):
        now = time.time()
        if self.val is None or now - self.ts >= self.ttl:
            self.val = self.fn()
            self.ts = now
        return self.val


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=2.0)
    args = ap.parse_args()

    drops = Drops()
    state = State()
    stop = threading.Event()
    threading.Thread(target=journal_tailer, args=(drops, state, stop), daemon=True).start()
    threading.Thread(target=state.rdns.worker, args=(stop,), daemon=True).start()
    threading.Thread(target=infra_prober, args=(state, stop), daemon=True).start()
    threading.Thread(target=updates_prober, args=(state, stop), daemon=True).start()

    # Collectes lentes (subprocess) mémoïsées pour ne pas spammer à chaque cycle.
    mv_cache = TTL(collect_mullvad, ttl=6.0)
    fb_cache = TTL(collect_fail2ban, ttl=20.0)
    health_cache = TTL(collect_health, ttl=12.0)

    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    while not stop.is_set():
        try:
            state.load_lan()
            data = {
                "ts": time.time(),
                "firewall": {"active": fw_active(), **drops.snapshot(state.resolve_name)},
                "listening": collect_listening(state),
                "connections": collect_established(state),
                "mullvad": mv_cache.get(),
                "fail2ban": fb_cache.get(),
                "system": collect_system(state),
                "health": health_cache.get(),
                "updates": state.updates,
                "infra": state.infra_cache,
                "lan": state.lan,
            }
            write_atomic(OUTPUT, data)
            # Alertes de découverte (collision d'IP / appareil qui change d'IP).
            for a in state.new_lan_alerts():
                if a.get("kind") == "mac-change":
                    state.ntfy.send(
                        f"Collision IP {a.get('ip')}",
                        f"changement de MAC {a.get('old')} -> {a.get('new')}"
                        f" ({a.get('name') or 'appareil inconnu'})",
                        tags="rotating_light", priority="high")
                elif a.get("kind") == "ip-change":
                    state.ntfy.send(
                        f"{a.get('name')} a changé d'IP",
                        f"{a.get('old')} -> {a.get('new')}",
                        tags="information_source", priority="default")
        except Exception as e:
            try:
                write_atomic(OUTPUT, {"ts": time.time(), "error": str(e)})
            except Exception:
                pass
        stop.wait(args.interval)
    state.rdns.wake.set()  # débloque le worker pour qu'il sorte proprement
    return 0


if __name__ == "__main__":
    sys.exit(main())
