# n1-monitor

[![CI](https://github.com/micferna/n1-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/micferna/n1-monitor/actions/workflows/ci.yml)

Monitoring temps réel, léger, pour un hôte Linux : parefeu (nftables), réseau,
Mullvad (killswitch), fail2ban, système, et un volet **Infra** (présence up/down
d'un inventaire d'hôtes). Trois composants qui partagent un seul état JSON.

> Stack maison. Le `collector` est stdlib-only (aucune dépendance) ; seul le TUI
> a besoin de [Textual](https://textual.textualize.io/).

## Architecture

Les trois composants communiquent via un unique fichier d'état : `/run/n1-monitor.json`.

| Composant | Rôle | Fichier |
|---|---|---|
| **Collector** | daemon (root) — agrège nft drops / `ss` connexions / Mullvad / fail2ban / système / sondes infra | `collector.py` |
| **TUI** | interface Textual, 6 panneaux (firewall, connexions, ports en écoute, Mullvad+fail2ban+sys, **Infra**) | `tui.py` (lancé via `bin/n1mon`) |
| **Extension GNOME** | indicateur en barre du haut `🛡 N 🔒 ⚠N 🚫N` + menu | `gnome-extension/` |

## Installation

```sh
# 1. déposer le code
mkdir -p ~/.local/share/n1-monitor
cp collector.py tui.py requirements.txt ~/.local/share/n1-monitor/
cp hosts.example.json ~/.local/share/n1-monitor/hosts.json   # puis éditer avec tes vraies IP

# 2. extension GNOME
cp -r gnome-extension ~/.local/share/gnome-shell/extensions/n1-monitor@ocb

# 3. install système (venv + systemd + sudoers + wrapper + raccourci)
sudo bash scripts/n1-setup.sh
```

`scripts/n1-setup.sh` est **idempotent** : il (ré)installe le service systemd, le
sudoers ciblé, le venv Textual, le wrapper `/usr/local/bin/n1mon`, le raccourci
GNOME `Super+F`, et active l'extension.

Lancer le TUI : `n1mon` (ou `Super+F`). Suivre le collector :
`journalctl -u n1mon-collector -f`.

## Volet Infra — sémantique des sondes

L'inventaire vit dans `hosts.json` (rechargé à chaud sur changement de mtime).
Chaque hôte est sondé par un **connect TCP** sur un port :

| Résultat du connect | Statut |
|---|---|
| connecté **ou** refusé (RST) | **up** (l'hôte a répondu) |
| **timeout** → fallback **ICMP** : ping OK | **up** (+ `port_closed` : vivant, service injoignable) |
| **timeout** → fallback **ICMP** : ping KO | **down** |
| EHOSTUNREACH / ENETUNREACH | **unreachable** (pas de route) |

Le fallback ICMP évite les **faux `down`** quand un hôte est bien vivant mais que
le port sondé est fermé/filtré/mauvais.

### ⚠️ Piège : allowlist du parefeu en sortie

Si l'hôte applique une politique nftables `output` en *drop par défaut* avec
liste blanche de ports, une sonde TCP sur un port **hors liste** voit son SYN
droppé **localement** → faux `down`. Le fallback ICMP le masque (si le ping
sortant est autorisé). Pour une sonde TCP fiable sur un port exotique, ouvre ce
port en sortie, ou ajoute-le à l'allowlist.

### Champs d'un hôte

```json
{"name": "router", "ip": "192.0.2.1", "group": "tunnel|tunnel-vm|lan",
 "role": "texte libre", "probe": {"type": "tcp|icmp", "port": 80}, "alert": true}
```

`alert: true` lève une notification (ntfy côté collector + desktop côté
extension) sur **transition** up↔down. Les transitions sont journalisées dans
`/var/lib/n1-monitor/presence.jsonl` (persistant).

## Schéma de `/run/n1-monitor.json`

```
{ ts,
  firewall: { active, drops_1m/5m/1h, drops_total, top_dropped, recent },
  listening: [{ proto, port, addr, comm, exposed_lan }],
  connections: { count, by_process, top_remote, sample },
  mullvad: { connected, relay, ip, lockdown },
  fail2ban: { jails },
  system: { load, cpu_pct, cpu_temp, mem_gib, disk, net },
  infra: { ts, summary:{up,down,unreachable,total},
           hosts:[{name,ip,group,role,status,is_up,since,rtt_ms,port_closed,alert}],
           events:[{ts,host,to}], wg:[{iface,age,alive}], persistent } }
```

## Sécurité

- **`hosts.json` (le vrai) n'est pas dans le dépôt** (`.gitignore`) — c'est la carte
  de ton infra. Seul `hosts.example.json` (IP de documentation) est versionné.
- `sudoers.d/n1-monitor` n'accorde NOPASSWD qu'à **4 commandes** précises (toggle
  firewall + toggle Mullvad lockdown), rien d'autre.
- Le service tourne en root mais durci : `ProtectSystem=strict`, `ProtectHome=ro`,
  `NoNewPrivileges`, `MemoryMax=128M`, `CPUQuota=15%`.

## Touches du TUI

`q` quitter · `r` refresh · `l` toggle Mullvad lockdown · `f` toggle firewall

## Layout du dépôt

```
collector.py              daemon de collecte (stdlib only)
tui.py                    interface Textual
hosts.example.json        gabarit d'inventaire (à copier en hosts.json)
requirements.txt          deps du TUI (textual)
bin/n1mon                 wrapper de lancement
systemd/                  unit du collector
sudoers.d/                permissions ciblées (toggles)
scripts/                  n1-setup.sh (install) + n1-fix-envs.sh (durcissement perms)
gnome-extension/          indicateur barre du haut
```
