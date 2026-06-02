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
from textual.containers import Grid, VerticalScroll
from textual.reactive import reactive
from textual.widgets import Footer, Header, Sparkline, Static

STATE = Path("/run/n1-monitor.json")
SPARK_LEN = 120  # ~2 min d'historique à 1 Hz


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


def sum_chains(d: dict) -> int:
    return sum(d.values()) if d else 0


def fmt_drops(fw: dict) -> str:
    d1 = sum_chains(fw.get("drops_1m", {}))
    d5 = sum_chains(fw.get("drops_5m", {}))
    dh = sum_chains(fw.get("drops_1h", {}))
    dt = fw.get("drops_total", {})
    color = "green" if d1 == 0 else ("yellow" if d1 < 10 else "red")
    active = "[green]ACTIVE[/green]" if fw.get("active") else "[red bold blink]OFF[/red bold blink]"
    return (
        f"[bold]firewall :[/bold] {active}\n"
        f"  drops 1m  : [{color}]{d1}[/{color}]   5m: {d5}   1h: {dh}\n"
        f"  total     : IN {dt.get('input', 0)}  OUT {dt.get('output', 0)}  FWD {dt.get('forward', 0)}\n"
    )


def fmt_mullvad(mv: dict) -> str:
    if not mv:
        return "[dim]mullvad : no data[/dim]"
    color = "green" if mv.get("connected") else "red"
    lock_color = "green" if mv.get("lockdown") else "yellow"
    lock_state = "ON" if mv.get("lockdown") else "[bold]OFF[/bold]"
    return (
        f"[bold]mullvad :[/bold] [{color}]{'CONNECTED' if mv.get('connected') else 'DISCONNECTED'}[/{color}]"
        f"  killswitch [{lock_color}]{lock_state}[/{lock_color}]\n"
        f"  relay {mv.get('relay') or '-'}   exit {mv.get('ip') or '-'}\n"
    )


def fmt_fail2ban(fb: dict) -> str:
    jails = fb.get("jails", [])
    if not jails:
        return "[dim]fail2ban : pas de jail actif[/dim]"
    lines = ["[bold]fail2ban :[/bold]"]
    for j in jails:
        b = j["banned"]
        col = "red" if b else "dim"
        lines.append(
            f"  {j['name']:<10} banned [{col}]{b}[/{col}]  total {j['total_banned']}  failed {j['total_failed']}"
        )
    return "\n".join(lines)


def fmt_system(s: dict) -> str:
    load = " ".join(s.get("load", ["?"] * 3))
    cpu = s.get("cpu_pct")
    temp = s.get("cpu_temp")
    cpu_col = "green" if (cpu or 0) < 60 else ("yellow" if (cpu or 0) < 85 else "red")
    temp_col = "green" if (temp or 0) < 70 else ("yellow" if (temp or 0) < 85 else "red")
    cpu_txt = f"[{cpu_col}]{cpu}%[/{cpu_col}]" if cpu is not None else "?"
    temp_txt = f"[{temp_col}]{temp}°C[/{temp_col}]" if temp is not None else "?"
    mem = s.get("mem_gib", {})
    lines = [
        "[bold]système :[/bold]",
        f"  load {load}   cpu {cpu_txt}   temp {temp_txt}",
        f"  mem  {mem.get('used', '?')}/{mem.get('total', '?')} GiB",
    ]
    for mnt, d in s.get("disk", {}).items():
        pct = d["used_pct"]
        col = "red" if pct > 90 else ("yellow" if pct > 80 else "green")
        lines.append(f"  {mnt:<10} [{col}]{pct}%[/{col}] used, {d['free_gib']} GiB libre")
    net = s.get("net", {})
    if net:
        lines.append("[bold]réseau :[/bold]")
        for iface, n in net.items():
            lines.append(f"  {iface:<13} ↓ {hr_bps(n['rx_bps']):>11}   ↑ {hr_bps(n['tx_bps']):>11}")
    return "\n".join(lines)


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
        return f"{s // 3600}h"
    return f"{s // 86400}j"


_GROUPS = [
    ("tunnel", "Tunnel ovh-cnd"),
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
            return f"[red]infra : {inf['error']}[/red]"
        return "[dim]infra : initialisation…[/dim]"
    now = time.time()
    summ = inf.get("summary", {})
    persist = "" if inf.get("persistent") else "  [dim](historique non persistant)[/dim]"
    lines = [
        f"[bold]infra :[/bold] [green]{summ.get('up', 0)} up[/green]  "
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
                f"[{col}]{h.get('status', '?'):<11}[/{col}] {age:<4}{rtt}{closed}{mute}"
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

    def compose(self) -> ComposeResult:
        yield Static(id=self.body_id)
        yield Sparkline([0], id="fw_spark", summary_function=max)

    def render_body(self, s: dict) -> str:
        fw = s.get("firewall", {})
        body = fmt_drops(fw)
        top = fw.get("top_dropped", [])
        if top:
            body += "\n[bold]top dropped (1h) :[/bold]\n"
            for t in top[:8]:
                src = t["src"] or "-"
                body += f"  [{t['chain'][:3]}] {t['proto']}/{str(t['dport']):<5} from {src:<18} ×{t['count']}\n"
        return body


class ConnectionsPanel(Panel):
    body_id = "conns_body"

    def render_body(self, s: dict) -> str:
        c = s.get("connections", {})
        lines = [f"[bold]connexions établies :[/bold] {c.get('count', 0)}\n"]
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
        head = f"[bold]sockets en écoute :[/bold] {len(listeners)} total, [red]{len(exposed)} exposés LAN[/red]"
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
        return (
            fmt_mullvad(s.get("mullvad", {}))
            + "\n"
            + fmt_fail2ban(s.get("fail2ban", {}))
            + "\n\n"
            + fmt_system(s.get("system", {}))
        )


class InfraPanel(Panel):
    body_id = "infra_body"

    def render_body(self, s: dict) -> str:
        return fmt_infra(s.get("infra", {}))


class N1Monitor(App):
    CSS = """
    Grid {
        grid-size: 2 3;
        grid-rows: 1fr 1fr 1fr;
        grid-gutter: 1;
        padding: 1;
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
    #fw_spark {
        height: 3;
        margin-top: 1;
    }
    Sparkline > .sparkline--max-color { color: $error; }
    Sparkline > .sparkline--min-color { color: $success; }
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
        self.history: collections.deque = collections.deque([0] * SPARK_LEN, maxlen=SPARK_LEN)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
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
        for panel_id in ("fw", "conns", "listen", "status", "infra"):
            self.query_one(f"#{panel_id}", Panel).state = s
        d1 = sum_chains(s.get("firewall", {}).get("drops_1m", {}))
        self.history.append(d1)
        try:
            self.query_one("#fw_spark", Sparkline).data = list(self.history)
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
