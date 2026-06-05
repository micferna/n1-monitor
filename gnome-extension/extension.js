// n1-monitor — GNOME 48 panel indicator showing live firewall/VPN state.
// Reads /run/n1-monitor.json maintained by the system collector.

import GObject from 'gi://GObject';
import St from 'gi://St';
import GLib from 'gi://GLib';
import Clutter from 'gi://Clutter';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';

const STATE_FILE = '/run/n1-monitor.json';
const REFRESH_SECONDS = 2;

const sumChains = (d) => d ? Object.values(d).reduce((a, b) => a + b, 0) : 0;

const hrBps = (b) => {
    b = Number(b) || 0;
    const units = ['B', 'K', 'M', 'G'];
    for (let i = 0; i < units.length; i++) {
        if (b < 1024 || i === units.length - 1)
            return i === 0 ? `${b.toFixed(0)} ${units[i]}/s` : `${b.toFixed(1)} ${units[i]}/s`;
        b /= 1024;
    }
    return `${b.toFixed(1)} T/s`;
};

const exposedPorts = (listen) =>
    listen.filter(l => l.exposed_lan).map(l => `${l.proto}/${l.port}`);

const Indicator = GObject.registerClass(
class Indicator extends PanelMenu.Button {
    _init() {
        super._init(0.0, 'n1-monitor');

        // Label compact en barre du haut
        this._label = new St.Label({
            text: '🛡 …',
            y_align: Clutter.ActorAlign.CENTER,
            style_class: 'n1mon-label',
        });
        this.add_child(this._label);

        // Sections menu
        this._fwSection = new PopupMenu.PopupMenuSection();
        this._mvSection = new PopupMenu.PopupMenuSection();
        this._expSection = new PopupMenu.PopupMenuSection();
        this._sysSection = new PopupMenu.PopupMenuSection();

        this._fwLine1 = new PopupMenu.PopupMenuItem('Firewall: …', {reactive: false});
        this._fwLine2 = new PopupMenu.PopupMenuItem('Drops 1m/5m/1h: …', {reactive: false});
        this._fwLine3 = new PopupMenu.PopupMenuItem('Top drops: …', {reactive: false});
        this._fwSection.addMenuItem(this._fwLine1);
        this._fwSection.addMenuItem(this._fwLine2);
        this._fwSection.addMenuItem(this._fwLine3);

        this._mvLine1 = new PopupMenu.PopupMenuItem('Mullvad: …', {reactive: false});
        this._mvLockdown = new PopupMenu.PopupSwitchMenuItem('Lockdown (killswitch)', false);
        this._mvLockdown.connect('toggled', (_, state) => {
            const cmd = `sudo -n mullvad lockdown-mode set ${state ? 'on' : 'off'}`;
            this._spawn(cmd);
        });
        this._mvSection.addMenuItem(this._mvLine1);
        this._mvSection.addMenuItem(this._mvLockdown);

        this._expLine = new PopupMenu.PopupMenuItem('Exposés LAN: …', {reactive: false});
        this._expSection.addMenuItem(this._expLine);

        this._sysLine = new PopupMenu.PopupMenuItem('Load / mem / disk: …', {reactive: false});
        this._netLine = new PopupMenu.PopupMenuItem('Réseau: …', {reactive: false});
        this._sysSection.addMenuItem(this._sysLine);
        this._sysSection.addMenuItem(this._netLine);

        this._infraSection = new PopupMenu.PopupMenuSection();
        this._infraLine = new PopupMenu.PopupMenuItem('Infra: …', {reactive: false});
        this._infraDownLine = new PopupMenu.PopupMenuItem('', {reactive: false});
        this._infraSection.addMenuItem(this._infraLine);
        this._infraSection.addMenuItem(this._infraDownLine);

        this.menu.addMenuItem(this._fwSection);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this.menu.addMenuItem(this._mvSection);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this.menu.addMenuItem(this._expSection);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this.menu.addMenuItem(this._sysSection);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this.menu.addMenuItem(this._infraSection);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        // Appareils LAN découverts automatiquement (mDNS/ARP).
        this._lanSub = new PopupMenu.PopupSubMenuMenuItem('Appareils LAN : …');
        this.menu.addMenuItem(this._lanSub);
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        const tui = new PopupMenu.PopupMenuItem('Ouvrir le TUI');
        tui.connect('activate', () => this._spawn('ghostty -e n1mon'));
        this.menu.addMenuItem(tui);

        const fwOn = new PopupMenu.PopupMenuItem('Firewall : recharger (fw-on)');
        fwOn.connect('activate', () => this._spawn('sudo -n nft -f /etc/nftables-hardening.conf'));
        this.menu.addMenuItem(fwOn);

        const fwOff = new PopupMenu.PopupMenuItem('Firewall : couper (fw-off)');
        fwOff.connect('activate', () => this._spawn('sudo -n nft delete table inet hardening'));
        this.menu.addMenuItem(fwOff);

        // État précédent pour la détection de transitions (alertes).
        // null = pas encore initialisé : pas de notif au démarrage du shell.
        this._prev = null;

        this._timeout = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, REFRESH_SECONDS, () => {
            this._refresh();
            return GLib.SOURCE_CONTINUE;
        });
        this._refresh();
    }

    _spawn(cmd) {
        try {
            GLib.spawn_command_line_async(cmd);
        } catch (e) {
            Main.notify('n1-monitor', `Erreur exec : ${e.message || e}`);
        }
    }

    _notify(title, body, critical) {
        try {
            if (critical)
                Main.notifyError(title, body);
            else
                Main.notify(title, body);
        } catch (e) {
            // notification best-effort
        }
    }

    // Compare l'état courant au précédent et notifie sur les transitions.
    _checkAlerts(cur) {
        const prev = this._prev;
        this._prev = cur;
        if (!prev)
            return; // premier passage : on enregistre la baseline sans notifier

        if (prev.fwActive && !cur.fwActive)
            this._notify('🛡 Firewall coupé', 'La table nftables « inet hardening » n\'est plus chargée.', true);
        else if (!prev.fwActive && cur.fwActive)
            this._notify('🛡 Firewall réactivé', 'Table nftables « inet hardening » chargée.', false);

        if (prev.mvConnected && !cur.mvConnected)
            this._notify('Mullvad déconnecté', 'Le tunnel VPN est tombé.', true);
        else if (!prev.mvConnected && cur.mvConnected)
            this._notify('Mullvad reconnecté', cur.relay ? `via ${cur.relay}` : '', false);

        if (prev.lockdown && !cur.lockdown)
            this._notify('Killswitch OFF', 'Le trafic n\'est plus bloqué hors VPN (lockdown désactivé).', true);

        const fresh = cur.exposed.filter(p => !prev.exposed.includes(p));
        if (fresh.length)
            this._notify('⚠ Nouveau port exposé LAN', fresh.join(', '), true);

        // Présence machines (uniquement les hôtes avec alert:true côté collector).
        if (prev.infra) {
            for (const name in cur.infra) {
                const was = prev.infra[name];
                if (was === undefined)
                    continue; // hôte nouvellement apparu : baseline, pas de notif
                if (was && !cur.infra[name])
                    this._notify(`🔴 ${name} injoignable`, 'Machine passée hors-ligne.', true);
                else if (!was && cur.infra[name])
                    this._notify(`🟢 ${name} de retour`, 'Machine de nouveau joignable.', false);
            }
        }
    }

    _refresh() {
        try {
            const [ok, contents] = GLib.file_get_contents(STATE_FILE);
            if (!ok) {
                this._label.set_text('🛡 ?');
                return;
            }
            const data = JSON.parse(new TextDecoder().decode(contents));
            this._render(data);
        } catch (e) {
            this._label.set_text('🛡 err');
        }
    }

    _render(d) {
        const fw = d.firewall || {};
        const mv = d.mullvad || {};
        const listen = d.listening || [];
        const sys = d.system || {};
        const conns = d.connections || {};
        const infra = d.infra || {};
        const infraHosts = infra.hosts || [];
        const infraSumm = infra.summary || {};
        const infraDownAlert = infraHosts.filter(h => h.alert && !h.is_up);

        const drops1m = sumChains(fw.drops_1m);
        const drops5m = sumChains(fw.drops_5m);
        const drops1h = sumChains(fw.drops_1h);
        const exposed = listen.filter(l => l.exposed_lan).length;

        const fwIcon = fw.active ? '🛡' : '❌';
        const mvIcon = mv.connected ? (mv.lockdown ? '🔒' : '▼') : '✗';
        const expBadge = exposed > 0 ? ` ⚠${exposed}` : '';
        const infraBadge = infraDownAlert.length ? ` 🖥${infraDownAlert.length}` : '';
        const bansBadge = (() => {
            const total = (d.fail2ban?.jails || []).reduce((a, j) => a + j.banned, 0);
            return total > 0 ? ` 🚫${total}` : '';
        })();

        this._label.set_text(`${fwIcon} ${drops1m} ${mvIcon}${expBadge}${infraBadge}${bansBadge}`);

        const infraUp = infraSumm.up || 0;
        const infraTotal = infraSumm.total || infraHosts.length;
        this._infraLine.label.set_text(
            `Infra : ${infraUp}/${infraTotal} up` +
            (infraSumm.down ? `  ${infraSumm.down} down` : '') +
            (infraSumm.unreachable ? `  ${infraSumm.unreachable} injoign.` : '')
        );
        this._infraDownLine.label.set_text(
            infraDownAlert.length
                ? `  ⚠ ${infraDownAlert.map(h => `${h.name} (${h.status})`).join(', ')}`
                : ''
        );

        this._fwLine1.label.set_text(`Firewall : ${fw.active ? 'ACTIVE' : 'OFF'}  conns: ${conns.count || 0}`);
        this._fwLine2.label.set_text(`Drops  1m: ${drops1m}  /  5m: ${drops5m}  /  1h: ${drops1h}`);

        // Top sources droppées, NOMMÉES (au lieu des IP brutes).
        const topDrops = (fw.top_dropped || []).slice(0, 4).map(t => {
            const who = t.src_name || t.src || '-';
            const dp = t.dport ? `:${t.dport}` : '';
            return `${who}${dp} ×${t.count}`;
        }).join('   ');
        this._fwLine3.label.set_text(`Top drops : ${topDrops || '—'}`);

        // Sous-menu appareils LAN (découverte autonome mDNS/ARP).
        const lan = d.lan || {};
        const devs = lan.devices || [];
        this._lanSub.label.set_text(`Appareils LAN : ${devs.length}`);
        this._lanSub.menu.removeAll();
        for (const x of devs) {
            const seen = x.reachable ? '●' : '○';
            const name = x.name || '?';
            const extra = x.type || x.vendor || '';
            const it = new PopupMenu.PopupMenuItem(
                `${seen} ${x.ip}   ${name}   ${extra}`, {reactive: false});
            this._lanSub.menu.addMenuItem(it);
        }
        for (const a of (lan.alerts || []).slice(-3)) {
            let t = '';
            if (a.kind === 'mac-change')
                t = `⚠ collision IP ${a.ip} : ${a.old} → ${a.new}`;
            else if (a.kind === 'ip-change')
                t = `ℹ ${a.name} : ${a.old} → ${a.new}`;
            if (t)
                this._lanSub.menu.addMenuItem(new PopupMenu.PopupMenuItem(t, {reactive: false}));
        }

        this._mvLine1.label.set_text(
            `Mullvad : ${mv.connected ? 'connecté' : 'DÉCONNECTÉ'}` +
            (mv.relay ? ` via ${mv.relay}` : '') +
            (mv.ip ? ` (${mv.ip})` : '')
        );
        // Évite la boucle infinie quand on set programmatiquement
        if (this._mvLockdown.state !== !!mv.lockdown) {
            this._mvLockdown.setToggleState(!!mv.lockdown);
        }

        this._expLine.label.set_text(`Exposés LAN : ${exposed}` + (exposed ? `  → ${listen.filter(l => l.exposed_lan).map(l => l.port).slice(0, 8).join(', ')}` : ''));

        const disk = sys.disk?.['/'];
        const diskTxt = disk ? `${disk.used_pct}% (${disk.free_gib}G libre)` : '?';
        const mem = sys.mem_gib || {};
        const cpuTxt = sys.cpu_pct != null ? `${sys.cpu_pct}%` : '?';
        const tempTxt = sys.cpu_temp != null ? `${sys.cpu_temp}°C` : '?';
        this._sysLine.label.set_text(
            `cpu ${cpuTxt} ${tempTxt}  load ${(sys.load || []).join(' ')}  ` +
            `mem ${mem.used || '?'}/${mem.total || '?'}G  / ${diskTxt}`
        );

        const net = sys.net || {};
        const netTxt = Object.keys(net).length
            ? Object.entries(net)
                .map(([iface, n]) => `${iface} ↓${hrBps(n.rx_bps)} ↑${hrBps(n.tx_bps)}`)
                .join('   ')
            : '—';
        this._netLine.label.set_text(`Réseau : ${netTxt}`);

        // Style d'alerte sur le label de la barre + détection de transitions.
        const alert = !fw.active || (mv.connected && !mv.lockdown) || exposed > 0 || infraDownAlert.length > 0;
        if (alert)
            this._label.add_style_class_name('n1mon-alert');
        else
            this._label.remove_style_class_name('n1mon-alert');

        // Carte {nom: up} restreinte aux hôtes alertables (alert:true côté collector).
        const infraStatus = {};
        infraHosts.forEach(h => { if (h.alert) infraStatus[h.name] = !!h.is_up; });

        this._checkAlerts({
            fwActive: !!fw.active,
            mvConnected: !!mv.connected,
            lockdown: !!mv.lockdown,
            relay: mv.relay || '',
            exposed: exposedPorts(listen),
            infra: infraStatus,
        });
    }

    destroy() {
        if (this._timeout) {
            GLib.source_remove(this._timeout);
            this._timeout = null;
        }
        super.destroy();
    }
});

export default class N1MonitorExtension extends Extension {
    enable() {
        this._indicator = new Indicator();
        Main.panel.addToStatusArea('n1-monitor', this._indicator);
    }
    disable() {
        if (this._indicator) {
            this._indicator.destroy();
            this._indicator = null;
        }
    }
}
