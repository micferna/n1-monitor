#!/usr/bin/env python3
"""n1-monitor TUI — visualise /run/n1-monitor.json en live (Textual)."""
from __future__ import annotations

import collections
import json
import subprocess
import time
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid
from textual.containers import VerticalScroll
from textual.reactive import reactive
from textual.widgets import Footer, Header, Static

STATE = Path("/run/n1-monitor.json")
SPARK_LEN = 120  # ~2 min d'historique à 1 Hz
STALE_S = 8.0    # au-delà, la donnée est considérée figée


def load_state() -> dict:
    try:
        with STATE.open() as f:
            return json.load(f)
    except Exception as e:
        return {"error": str(e)}


def hr_bps(b: float) -> str:
    """Débit lisible (B/s, KiB/s, …)."""
    b = float(b)
    for u in ("B", "K", "M", "G"):
        if b < 1024 or u == "G":
            return f"{b:.0f} {u}/s" if u == "B" else f"{b:.1f} {u}/s"
        b /= 1024
    return f"{b:.1f} T/s"


def hr_age(s: float | None) -> str:
    """Durée lisible et compacte (s/m/h/j)."""
    if s is None:
        return "?"
    s = int(s)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h{(s % 3600) // 60:02d}"
    return f"{s // 86400}j{(s % 86400) // 3600:02d}h"


_SPARK = "▁▂▃▄▅▆▇█"


def sparkline(vals, width: int = 22) -> str:
    """Mini-graphe temporel en blocs Unicode."""
    vals = [float(v) for v in list(vals)[-width:]]
    if not vals:
        return ""
    hi, lo = max(vals), min(vals)
    rng = hi - lo
    if rng <= 0:
        return _SPARK[0 if hi == 0 else 3] * len(vals)
    return "".join(_SPARK[min(7, int((v - lo) / rng * 7.999))] for v in vals)


def bar(pct: float, width: int = 12) -> str:
    """Barre de progression texte."""
    pct = max(0.0, min(100.0, float(pct)))
    filled = int(round(pct / 100 * width))
    return "█" * filled + "░" * (width - filled)


def pct_color(pct: float, warn: float = 80, crit: float = 90) -> str:
    return "green" if pct < warn else ("yellow" if pct < crit else "red")


def sum_chains(d: dict) -> int:
    return sum(d.values()) if d else 0


# --------------------------------------------------------------------------- #
# Rendus de sections
# --------------------------------------------------------------------------- #
def fmt_drops(fw: dict) -> str:
    d1 = sum_chains(fw.get("drops_1m", {}))
    d5 = sum_chains(fw.get("drops_5m", {}))
    dh = sum_chains(fw.get("drops_1h", {}))
    dt = fw.get("drops_total", {})
    color = "green" if d1 == 0 else ("yellow" if d1 < 10 else "red")
    active = "[green]ACTIVE[/green]" if fw.get("active") else "[red bold blink]OFF[/red bold blink]"
    return (
        f"[bold]🛡  firewall :[/bold] {active}\n"
        f"  drops 1m  : [{color}]{d1}[/{color}]   5m: {d5}   1h: {dh}\n"
        f"  total     : IN {dt.get('input', 0)}  OUT {dt.get('output', 0)}  FWD {dt.get('forward', 0)}\n"
    )


def fmt_mullvad(mv: dict) -> str:
    if not mv:
        return "[dim]🔒 mullvad : no data[/dim]"
    color = "green" if mv.get("connected") else "red"
    lock_color = "green" if mv.get("lockdown") else "yellow"
    lock_state = "ON" if mv.get("lockdown") else "[bold]OFF[/bold]"
    return (
        f"[bold]🔒 mullvad :[/bold] [{color}]{'CONNECTED' if mv.get('connected') else 'DISCONNECTED'}[/{color}]"
        f"  killswitch [{lock_color}]{lock_state}[/{lock_color}]\n"
        f"  relay {mv.get('relay') or '-'}   exit {mv.get('ip') or '-'}\n"
    )


def fmt_fail2ban(fb: dict) -> str:
    jails = fb.get("jails", [])
    if not jails:
        return "[dim]🚫 fail2ban : pas de jail actif[/dim]"
    lines = ["[bold]🚫 fail2ban :[/bold]"]
    for j in jails:
        b = j["banned"]
        col = "red" if b else "dim"
        lines.append(
            f"  {j['name']:<10} banned [{col}]{b}[/{col}]  total {j['total_banned']}  failed {j['total_failed']}"
        )
    return "\n".join(lines)


def fmt_system(s: dict, hist: dict) -> str:
    load = list(s.get("load", ["?", "?", "?"]))
    cores = s.get("cores")
    load_txt = " ".join(str(x) for x in load)
    if cores:
        try:
            l1 = float(str(load[0]).replace(",", "."))
            lc = "green" if l1 < cores * 0.7 else ("yellow" if l1 < cores else "red")
            load_txt = f"[{lc}]{load[0]}[/{lc}] {load[1]} {load[2]} [dim]/{cores}c[/dim]"
        except (ValueError, IndexError):
            pass
    up = hr_age(s.get("uptime")) if s.get("uptime") else "?"
    lines = [f"[bold]🖥  système :[/bold]  [dim]up[/dim] {up}   load {load_txt}"]

    cpu = s.get("cpu_pct") or 0
    cc = pct_color(cpu, 60, 85)
    cpu_line = f"  cpu  [{cc}]{bar(cpu)}[/{cc}] {cpu:>4.0f}%"
    temp = s.get("cpu_temp")
    if temp is not None:
        tc = pct_color(temp, 70, 85)
        cpu_line += f"    temp [{tc}]{temp:.0f}°C[/{tc}]"
    lines.append(cpu_line)

    mem = s.get("mem_gib", {})
    mt, mu = mem.get("total") or 0, mem.get("used") or 0
    mpct = (mu / mt * 100) if mt else 0
    mc = pct_color(mpct, 80, 92)
    lines.append(f"  mem  [{mc}]{bar(mpct)}[/{mc}] {mu}/{mt} GiB")
    sw = s.get("swap_gib", {})
    st, su = sw.get("total") or 0, sw.get("used") or 0
    if st:
        spct = su / st * 100
        sc = pct_color(spct, 40, 70)
        lines.append(f"  swap [{sc}]{bar(spct)}[/{sc}] {su}/{st} GiB")

    for mnt, d in s.get("disk", {}).items():
        pct = d["used_pct"]
        col = pct_color(pct, 80, 90)
        lines.append(f"  {mnt:<10} [{col}]{bar(pct)}[/{col}] {pct:>3}% [dim]({d['free_gib']} GiB libre)[/dim]")

    if hist:
        lines.append(
            f"  [dim]cpu[/dim] {sparkline(hist.get('cpu', []))}"
            f"  [dim]net[/dim] {sparkline(hist.get('net', []))}"
            f"  [dim]conns[/dim] {sparkline(hist.get('conns', []))}"
        )

    net = s.get("net", {})
    if net:
        lines.append("[bold]🌐 réseau :[/bold]")
        for iface, n in net.items():
            lines.append(f"  {iface:<13} ↓ {hr_bps(n['rx_bps']):>11}   ↑ {hr_bps(n['tx_bps']):>11}")
    return "\n".join(lines)


def fmt_health(h: dict, upd: dict) -> str:
    lines = []
    failed = h.get("failed_units", [])
    if failed:
        names = ", ".join(x.rsplit(".", 1)[0] for x in failed[:4])
        more = f" +{len(failed) - 4}" if len(failed) > 4 else ""
        lines.append(f"[bold]⚙  services :[/bold] [red]⚠ {len(failed)} en échec[/red]  [dim]{names}{more}[/dim]")
    else:
        lines.append("[bold]⚙  services :[/bold] [green]tous OK[/green]")

    sess = h.get("sessions", {})
    n, ssh = sess.get("count", 0), sess.get("ssh", 0)
    who = ", ".join(f"{u['user']}@{u['from'] or u['tty']}" for u in sess.get("users", [])[:4])
    ssh_txt = f"[yellow]{ssh} SSH[/yellow]" if ssh else "0 SSH"
    lines.append(f"[bold]👤 sessions :[/bold] {n} ({ssh_txt})  [dim]{who}[/dim]")

    rb = "[red]OUI[/red]" if h.get("reboot_required") else "[green]non[/green]"
    t, sec = upd.get("total"), upd.get("security")
    if t is None:
        utxt = "[dim]?[/dim]"
    else:
        uc = "red" if sec else ("yellow" if t else "green")
        utxt = f"[{uc}]{t}[/{uc}] ({sec} sécu)"
    lines.append(f"[bold]🔄 reboot :[/bold] {rb}    [bold]📦 updates :[/bold] {utxt}")
    return "\n".join(lines)


_GROUPS = [
    ("tunnel", "Tunnel"),
    ("tunnel-vm", "VMs internes (non routées depuis n1)"),
    ("lan", "LAN"),
]
_STATUS_STYLE = {
    "up": ("●", "green"),
    "down": ("●", "red"),
    "unreachable": ("◌", "yellow"),
    "unknown": ("?", "dim"),
}


def fmt_infra(inf: dict) -> str:
    if not inf or not inf.get("hosts"):
        if inf.get("error"):
            return f"[red]🛰  infra : {inf['error']}[/red]"
        return "[dim]🛰  infra : initialisation…[/dim]"
    now = time.time()
    summ = inf.get("summary", {})
    persist = "" if inf.get("persistent") else "  [dim](historique non persistant)[/dim]"
    lines = [
        f"[bold]🛰  infra :[/bold] [green]{summ.get('up', 0)} up[/green]  "
        f"[red]{summ.get('down', 0)} down[/red]  "
        f"[yellow]{summ.get('unreachable', 0)} injoignable[/yellow]  "
        f"/ {summ.get('total', 0)}{persist}"
    ]
    wg = inf.get("wg", [])
    if wg:
        parts = []
        for w in wg:
            col = "green" if w.get("alive") else "red"
            glyph = "●" if w.get("alive") else "○"
            parts.append(f"{w['iface']} [{col}]{glyph}[/{col}] {hr_age(w.get('age'))}")
        lines.append("  [bold]wg[/bold] " + "   ".join(parts))
    lines.append("")
    hosts = inf["hosts"]
    for gkey, gname in _GROUPS:
        ghosts = [h for h in hosts if h.get("group") == gkey]
        if not ghosts:
            continue
        lines.append(f"[bold cyan]{gname}[/bold cyan]")
        for h in ghosts:
            glyph, col = _STATUS_STYLE.get(h.get("status", "unknown"), ("?", "dim"))
            age = hr_age(now - h["since"]) if h.get("since") else "?"
            rtt = f" {h['rtt_ms']}ms" if h.get("rtt_ms") is not None else ""
            closed = " [dim](port fermé)[/dim]" if h.get("port_closed") else ""
            mute = "" if h.get("alert") else " [dim]🔕[/dim]"
            lines.append(
                f"  [{col}]{glyph}[/{col}] {h['name']:<13} [dim]{(h.get('ip') or ''):<13}[/dim] "
                f"[{col}]{h.get('status', '?'):<11}[/{col}] {age:<6}{rtt}{closed}{mute}"
                f"  [dim]{h.get('role', '')}[/dim]"
            )
        lines.append("")
    evs = inf.get("events", [])
    if evs:
        lines.append("[bold]derniers événements :[/bold]")
        for e in evs[-8:][::-1]:
            to = e.get("to")
            col = "green" if to == "up" else "red"
            arrow = "↑" if to == "up" else "↓"
            ago = hr_age(now - e["ts"]) if e.get("ts") else "?"
            lines.append(f"  [{col}]{arrow}[/{col}] {e.get('host', ''):<13} {to or '?':<5} [dim]il y a {ago}[/dim]")
    return "\n".join(lines)


def health_banner(s: dict, age: float | None) -> str:
    """Ligne de synthèse globale : 🟢 / 🟡 / 🔴."""
    probs, warns = [], []
    if age is None or age > STALE_S:
        probs.append("pas de data" if age is None else f"data figée ({hr_age(age)})")
    fw = s.get("firewall", {})
    if not fw.get("active"):
        probs.append("firewall OFF")
    mv = s.get("mullvad", {})
    if mv and not mv.get("connected"):
        probs.append("Mullvad déconnecté")
    if mv and not mv.get("lockdown"):
        warns.append("killswitch OFF")
    newp = [l for l in s.get("listening", []) if l.get("new")]
    if newp:
        probs.append(f"{len(newp)} nouveau port exposé")
    h = s.get("health", {})
    fu = h.get("failed_units", [])
    if fu:
        warns.append(f"{len(fu)} service(s) en échec")
    if h.get("reboot_required"):
        warns.append("reboot requis")
    downs = [x for x in s.get("infra", {}).get("hosts", []) if x.get("alert") and not x.get("is_up")]
    if downs:
        warns.append(f"{len(downs)} hôte(s) down")
    for mnt, d in s.get("system", {}).get("disk", {}).items():
        if d.get("used_pct", 0) >= 92:
            warns.append(f"{mnt} {d['used_pct']}%")
    sec = s.get("updates", {}).get("security") or 0
    if sec:
        warns.append(f"{sec} update sécu")

    if probs:
        return "[bold white on red] 🔴 PROBLÈME [/] " + " · ".join(probs + warns)
    if warns:
        return "[bold black on yellow] 🟡 ATTENTION [/] " + " · ".join(warns)
    return "[bold black on green] 🟢 TOUT OK [/] [dim]firewall actif · killswitch ON · 0 service en échec[/dim]"


# --------------------------------------------------------------------------- #
# Panneaux
# --------------------------------------------------------------------------- #
class Panel(VerticalScroll):
    """Panneau scrollable rendu en texte Rich via render_body()."""

    state: reactive[dict] = reactive(dict)
    body_id = "body"

    def compose(self) -> ComposeResult:
        yield Static(id=self.body_id)

    def render_body(self, s: dict) -> str:
        return ""

    def watch_state(self, s: dict) -> None:
        try:
            self.query_one(f"#{self.body_id}", Static).update(self.render_body(s))
        except Exception:
            pass


class FirewallPanel(Panel):
    body_id = "fw_body"

    def render_body(self, s: dict) -> str:
        fw = s.get("firewall", {})
        body = fmt_drops(fw)
        hist = s.get("_hist", {})
        if hist.get("drops"):
            body += f"  [dim]1m[/dim] {sparkline(hist['drops'])}\n"
        top = fw.get("top_dropped", [])
        if top:
            body += "\n[bold]top dropped (1h) :[/bold]\n"
            for t in top[:6]:
                src = t["src"] or "-"
                body += f"  [{t['chain'][:3]}] {t['proto']}/{str(t['dport']):<5} from {src:<16} ×{t['count']}\n"
        recent = fw.get("recent", [])
        if recent:
            body += "\n[bold]flux live :[/bold]\n"
            for r in recent[-6:][::-1]:
                dport = r.get("dport", "") or ""
                sep = ":" if dport else ""
                body += (
                    f"  [dim]{(r.get('chain', '') or '')[:3]}[/dim] {r.get('src', '?')} → "
                    f"{r.get('dst', '?')}{sep}{dport} [dim]{r.get('proto', '')}[/dim]\n"
                )
        return body


class ConnectionsPanel(Panel):
    body_id = "conns_body"

    def render_body(self, s: dict) -> str:
        c = s.get("connections", {})
        lines = [f"[bold]🌐 connexions établies :[/bold] {c.get('count', 0)}\n"]
        lines.append("[bold]top remote :[/bold]")
        for r in c.get("top_remote", [])[:8]:
            who = r.get("rhost") or r.get("ip")
            cc = f" [cyan]{r['country']}[/cyan]" if r.get("country") else ""
            lines.append(f"  ×{r['count']:<3} {who}{cc}  [dim]{r.get('comm') or ''}[/dim]")
        lines.append("")
        lines.append("[bold]par process :[/bold]")
        for p in c.get("by_process", [])[:6]:
            lines.append(f"  {p['comm']:<22} {p['count']}")
        lines.append("")
        lines.append("[bold]échantillon :[/bold]")
        for cn in c.get("sample", [])[:12]:
            comm = cn["comm"] or "-"
            who = cn.get("rhost") or cn.get("rip") or cn.get("remote")
            cls = cn.get("rclass", "")
            tag = "" if cls in ("public", "") else f" [yellow]({cls})[/yellow]"
            lines.append(f"  {comm:<16} → {who}{tag}")
        return "\n".join(lines)


class ListenPanel(Panel):
    body_id = "listen_body"

    def render_body(self, s: dict) -> str:
        listeners = s.get("listening", [])
        exposed = [l for l in listeners if l.get("exposed_lan")]
        new = [l for l in exposed if l.get("new")]
        safe = [l for l in listeners if not l.get("exposed_lan")]
        head = f"[bold]👂 sockets en écoute :[/bold] {len(listeners)} total, [red]{len(exposed)} exposés LAN[/red]"
        if new:
            head += f"  [red bold blink]({len(new)} NOUVEAU)[/red bold blink]"
        lines = [head, ""]
        if exposed:
            lines.append("[red bold]Exposés (0.0.0.0 / ::) :[/red bold]")
            for l in exposed[:15]:
                comm = l["comm"] or "-"
                badge = " [red bold]NEW[/red bold]" if l.get("new") else ""
                lines.append(f"  [red]⚠[/red] {l['proto']}/{str(l['port']):<6} {comm}{badge}")
            lines.append("")
        if safe:
            lines.append("[dim]Localhost / privé :[/dim]")
            for l in safe[:10]:
                comm = l["comm"] or "-"
                lines.append(f"  {l['proto']}/{str(l['port']):<6} {comm:<18} {l['addr']}")
        return "\n".join(lines)


class StatusPanel(Panel):
    body_id = "status_body"

    def render_body(self, s: dict) -> str:
        hist = s.get("_hist", {})
        return (
            fmt_mullvad(s.get("mullvad", {}))
            + "\n"
            + fmt_fail2ban(s.get("fail2ban", {}))
            + "\n\n"
            + fmt_system(s.get("system", {}), hist)
            + "\n\n"
            + fmt_health(s.get("health", {}), s.get("updates", {}))
        )


class InfraPanel(Panel):
    body_id = "infra_body"

    def render_body(self, s: dict) -> str:
        return fmt_infra(s.get("infra", {}))


# --------------------------------------------------------------------------- #
# Application
# --------------------------------------------------------------------------- #
class N1Monitor(App):
    CSS = """
    #banner {
        height: 1;
        padding: 0 1;
        content-align: left middle;
    }
    Grid {
        grid-size: 2 3;
        grid-rows: 1fr 1fr 1fr;
        grid-gutter: 1;
        padding: 0 1 1 1;
    }
    #infra {
        column-span: 2;
        border: round $accent;
    }
    Panel {
        border: round $primary;
        padding: 0 1;
        height: 100%;
    }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("p", "toggle_pause", "Pause"),
        Binding("l", "toggle_lockdown", "Mullvad lockdown"),
        Binding("f", "toggle_fw", "Firewall"),
    ]

    paused: reactive[bool] = reactive(False)

    def __init__(self) -> None:
        super().__init__()
        self.h_cpu: collections.deque = collections.deque([0] * SPARK_LEN, maxlen=SPARK_LEN)
        self.h_net: collections.deque = collections.deque([0] * SPARK_LEN, maxlen=SPARK_LEN)
        self.h_conns: collections.deque = collections.deque([0] * SPARK_LEN, maxlen=SPARK_LEN)
        self.h_drops: collections.deque = collections.deque([0] * SPARK_LEN, maxlen=SPARK_LEN)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="banner")
        with Grid():
            yield FirewallPanel(id="fw")
            yield ConnectionsPanel(id="conns")
            yield ListenPanel(id="listen")
            yield StatusPanel(id="status")
            yield InfraPanel(id="infra")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "n1-monitor"
        self.sub_title = "real-time firewall & network"
        self.set_interval(1.0, self.refresh_state)
        self.refresh_state()

    def refresh_state(self) -> None:
        if self.paused:
            return
        s = load_state()
        age = (time.time() - s["ts"]) if s.get("ts") else None
        sysd = s.get("system", {})
        self.h_cpu.append(sysd.get("cpu_pct") or 0)
        net = sysd.get("net", {})
        self.h_net.append(sum((n.get("rx_bps", 0) + n.get("tx_bps", 0)) for n in net.values()))
        self.h_conns.append(s.get("connections", {}).get("count", 0))
        self.h_drops.append(sum_chains(s.get("firewall", {}).get("drops_1m", {})))
        s["_hist"] = {
            "cpu": list(self.h_cpu), "net": list(self.h_net),
            "conns": list(self.h_conns), "drops": list(self.h_drops),
        }
        s["_age"] = age
        try:
            self.query_one("#banner", Static).update(health_banner(s, age))
        except Exception:
            pass
        for panel_id in ("fw", "conns", "listen", "status", "infra"):
            try:
                self.query_one(f"#{panel_id}", Panel).state = s
            except Exception:
                pass

    def action_refresh(self) -> None:
        self.refresh_state()

    def action_toggle_pause(self) -> None:
        self.paused = not self.paused
        self.sub_title = "PAUSED" if self.paused else "real-time firewall & network"

    def action_toggle_lockdown(self) -> None:
        s = load_state()
        currently = s.get("mullvad", {}).get("lockdown", False)
        new = "off" if currently else "on"
        subprocess.run(["sudo", "-n", "mullvad", "lockdown-mode", "set", new], check=False)
        self.refresh_state()

    def action_toggle_fw(self) -> None:
        s = load_state()
        active = s.get("firewall", {}).get("active", False)
        if active:
            subprocess.run(["sudo", "-n", "nft", "delete", "table", "inet", "hardening"], check=False)
        else:
            subprocess.run(["sudo", "-n", "nft", "-f", "/etc/nftables-hardening.conf"], check=False)
        self.refresh_state()


if __name__ == "__main__":
    N1Monitor().run()
