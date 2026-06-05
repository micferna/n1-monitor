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
| **Collector** | daemon (root) — agrège nft drops / `ss` connexions / Mullvad / fail2ban / système / sondes infra ; **nomme les IP** (drops, connexions, sondes) | `collector.py` |
| **LAN-discovery** | daemon (root, `CAP_NET_RAW` seul) — **identité LAN autonome** : capture mDNS L2 + ARP + OUI → `/run/n1-monitor-lan.json` | `lan_discovery.py` |
| **TUI** | interface Textual (firewall, connexions, ports en écoute, Mullvad+fail2ban+sys, **Infra + appareils LAN**) | `tui.py` (lancé via `bin/n1mon`) |
| **Extension GNOME** | indicateur en barre du haut `🛡 N 🔒 ⚠N 🚫N` + menu (drops nommés, sous-menu appareils LAN) | `gnome-extension/` |

## Installation

```sh
# 1. déposer le code
mkdir -p ~/.local/share/n1-monitor
cp collector.py lan_discovery.py tui.py requirements.txt ~/.local/share/n1-monitor/
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
Chaque hôte est sondé par un **connect TCP** sur un port, en **mode strict** :

| Résultat | Statut |
|---|---|
| port de service ouvert (connect OK) | **up** |
| hôte joignable (RST/ping) mais service muet | **service-down** |
| IP tenue par un autre appareil (MAC ≠ attendue) | **wrong-device** (+ occupant) |
| injoignable (ni connect ni ping) | **down** |
| EHOSTUNREACH / ENETUNREACH | **unreachable** (pas de route) |

La sonde stricte tue les **faux `up`** : un téléphone qui prend l'IP d'un serveur
(DHCP) et répond au ping ne fait **plus** passer le service pour « up ». La MAC
attendue est soit fixée (`"mac"` dans `hosts.json`), soit **apprise** quand le
service répond vraiment, et recoupée avec la table de découverte LAN.

## Identité LAN autonome

Le daemon `lan-discovery` (root, `CAP_NET_RAW` seul, installé dans
`/usr/local/lib/n1-monitor/`) construit en continu une table des appareils du LAN
dans `/run/n1-monitor-lan.json`, **sans aucune saisie ni credential** :

- **mDNS** capturé en **niveau 2 (AF_PACKET)** — donc *sous* netfilter : voit les
  annonces que le parefeu droppe. Sonde aussi activement (`_services._dns-sd`,
  `_googlecast`, `_workstation`…) pour ne pas attendre les annonces spontanées.
  → hostname `.local` + **type** d'appareil (déduit des services *offerts*, QR=1).
- **ARP** (`/proc/net/arp` + sweep léger) → IP ↔ **MAC** + présence + **constructeur (OUI)**.
- **reverse-DNS** local en complément.

Le collector s'en sert pour **nommer les IP** partout (drops, connexions, sondes),
suivre les services **par identité (MAC)** plutôt que par IP figée, et **alerter**
sur collision d'IP (MAC qui change) ou appareil qui change d'IP. Résolution d'un
nom : `lan_names` (label manuel) → découverte mDNS/ARP → inventaire `hosts` →
type/constructeur → reverse-DNS.

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
  firewall: { active, drops_1m/5m/1h, drops_total,
              top_dropped:[{chain,proto,dport,src,src_name,count}],
              recent:[{...,src,dst,src_name,dst_name}] },
  listening: [{ proto, port, addr, comm, exposed_lan }],
  connections: { count, by_process, top_remote, sample:[{...,rip,rhost,rname}] },
  mullvad: { connected, relay, ip, lockdown },
  fail2ban: { jails },
  system: { load, cpu_pct, cpu_temp, mem_gib, disk, net },
  infra: { ts, summary:{up,"service-down","wrong-device",down,unreachable,total},
           hosts:[{name,ip,group,role,status,is_up,since,rtt_ms,mac,occupant,detail,alert}],
           events:[{ts,host,to,status,detail}], wg:[{iface,age,alive}], persistent },
  lan: { ts, iface, subnet, devices:[{ip,mac,name,vendor,type,reachable,...}],
         by_ip:{...}, alerts:[{kind,ip,old,new,name}] } }
```

`/run/n1-monitor-lan.json` (écrit par `lan-discovery`) a la même forme que la
clé `lan` ci-dessus.

## Sécurité

- **`hosts.json` (le vrai) n'est pas dans le dépôt** (`.gitignore`) — c'est la carte
  de ton infra. Seul `hosts.example.json` (IP de documentation) est versionné.
- `sudoers.d/n1-monitor` n'accorde NOPASSWD qu'à **4 commandes** précises (toggle
  firewall + toggle Mullvad lockdown), rien d'autre.
- Le collector tourne en root mais durci : `ProtectSystem=strict`, `ProtectHome=ro`,
  `NoNewPrivileges`, `MemoryMax=128M`, `CPUQuota=15%`.
- `lan-discovery` tourne en root avec **`CAP_NET_RAW` comme seule capability**
  (bounding set réduit → pas de `CAP_DAC_OVERRIDE`), `ProtectHome=true`,
  `ProtectSystem=strict` ; son script est en chemin système (`/usr/local/lib`)
  car sans `CAP_DAC_OVERRIDE` il ne pourrait pas lire un script dans `/home` (700).

## Touches du TUI

`q` quitter · `r` refresh · `l` toggle Mullvad lockdown · `f` toggle firewall

## Layout du dépôt

```
collector.py              daemon de collecte (stdlib only) + résolution de noms
lan_discovery.py          daemon découverte LAN (mDNS/ARP/OUI, stdlib only)
tui.py                    interface Textual
hosts.example.json        gabarit d'inventaire (à copier en hosts.json)
requirements.txt          deps du TUI (textual)
bin/n1mon                 wrapper de lancement
systemd/                  units collector + lan-discovery
sudoers.d/                permissions ciblées (toggles)
scripts/                  n1-setup.sh (install) + n1-fix-envs.sh (durcissement perms)
gnome-extension/          indicateur barre du haut
```
