#!/usr/bin/env python3
"""n1mon drop-logger : historique persistant des drops nftables.

Service systeme independant du collector n1mon. Tail le journal kernel
(`journalctl -kf`), parse les lignes [NFT-DROP-IN|OUT|FWD], et append un
enregistrement JSON par drop dans drops.jsonl.

Le parsing est calque sur collector.py pour rester coherent avec le TUI n1mon.
Daemon volontairement minimal : stdlib uniquement, AUCUN acces a /home (les
labels manuels lan_names sont appliques cote viewer `nft-drops`, qui tourne en
espace utilisateur). Seuls les noms multicast/broadcast bien connus sont
resolus ici. Lecture de l'historique : voir l'outil `nft-drops`.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path

# --- Emplacements -----------------------------------------------------------
STATE_DIR = Path("/var/lib/n1-monitor")
JSONL = STATE_DIR / "drops.jsonl"
CURSOR_FILE = STATE_DIR / "drop_logger.cursor"

MAX_BYTES = 16 * 1024 * 1024  # plafond : au-dela, rotation (on garde la moitie recente)
SEED_SINCE = "-1h"            # au tout premier demarrage, pre-charge 1h de contexte

# --- Parsing (identique a collector.parse_drop) -----------------------------
DROP_RE = re.compile(r"\[NFT-DROP-(?P<chain>IN|OUT|FWD)\]")
KV_RE = re.compile(r"(\w+)=(\S*)")
CHAIN_MAP = {"IN": "input", "OUT": "output", "FWD": "forward"}
PROTO_MAP = {"1": "icmp", "2": "igmp", "6": "tcp", "17": "udp"}

# Noms multicast / broadcast bien connus (les labels LAN manuels sont ajoutes
# par le viewer nft-drops, pas ici : le daemon n'accede pas a /home).
WELL_KNOWN = {
    "224.0.0.1": "all-hosts", "224.0.0.2": "all-routers", "224.0.0.22": "IGMPv3",
    "224.0.0.251": "mDNS", "224.0.0.252": "LLMNR", "239.255.255.250": "SSDP",
    "255.255.255.255": "broadcast", "0.0.0.0": "this-net",  # nosec B104 — clé de nommage, pas un bind
    "ff02::fb": "mDNS", "ff02::1": "all-nodes", "ff02::2": "all-routers",
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
        "sport": kv.get("SPT", ""),
        "dst": kv.get("DST", ""),
        "dport": kv.get("DPT", ""),
        "proto": proto.lower(),
    }


def rotate_if_needed() -> None:
    try:
        if JSONL.exists() and JSONL.stat().st_size > MAX_BYTES:
            lines = JSONL.read_text(errors="replace").splitlines()
            keep = lines[len(lines) // 2:]
            JSONL.write_text("\n".join(keep) + "\n")
            os.chmod(JSONL, 0o644)
    except OSError:
        pass


def read_cursor() -> str | None:
    try:
        c = CURSOR_FILE.read_text().strip()
        return c or None
    except OSError:
        return None


def write_cursor(cur: str) -> None:
    try:
        CURSOR_FILE.write_text(cur)
    except OSError:
        pass


def main() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    JSONL.touch(exist_ok=True)
    os.chmod(JSONL, 0o644)  # lisible par l'utilisateur (viewer sans root)

    base = ["journalctl", "-kf", "-o", "json", "--no-pager"]
    cursor = read_cursor()

    while True:
        cmd = base + (["--after-cursor", cursor] if cursor else ["--since", SEED_SINCE])
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, text=True, bufsize=1)
            if p.stdout is None:  # pas d'assert : sauté sous python -O
                raise OSError("journalctl: pas de flux stdout")
            for raw in p.stdout:
                try:
                    obj = json.loads(raw)
                except (ValueError, TypeError):
                    continue
                cur = obj.get("__CURSOR")
                if cur:
                    cursor = cur
                msg = obj.get("MESSAGE", "")
                if isinstance(msg, list):
                    try:
                        msg = bytes(msg).decode("utf-8", "replace")
                    except (ValueError, TypeError):
                        continue
                if "[NFT-DROP-" not in msg:
                    continue
                ts = None
                rt = obj.get("__REALTIME_TIMESTAMP")
                if rt:
                    try:
                        ts = int(rt) / 1_000_000
                    except (ValueError, TypeError):
                        ts = None
                ev = parse_drop(msg, ts)
                if not ev:
                    continue
                ev["iso"] = time.strftime("%Y-%m-%dT%H:%M:%S%z",
                                          time.localtime(ev["ts"]))
                ev["src_name"] = WELL_KNOWN.get(ev["src"], "")
                ev["dst_name"] = WELL_KNOWN.get(ev["dst"], "")
                rotate_if_needed()
                with JSONL.open("a") as f:
                    f.write(json.dumps(ev, ensure_ascii=False) + "\n")
                if cur:
                    write_cursor(cur)
        except FileNotFoundError:
            raise  # journalctl absent : systemd Restart gere
        except OSError:
            pass
        time.sleep(2)  # reconnexion apres coupure du pipe


if __name__ == "__main__":
    main()
