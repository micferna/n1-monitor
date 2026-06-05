#!/usr/bin/env bash
# n1-setup.sh — installation du monitoring + fixes critiques côté système.
# À lancer en root : sudo bash ~/n1-setup.sh
#
# Idempotent : tu peux le rejouer sans tout casser.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "→ lance avec : sudo bash $0" >&2
    exit 1
fi

USER_NAME="${SUDO_USER:-$(logname 2>/dev/null || echo youruser)}"
USER_HOME="/home/${USER_NAME}"
N1MON_DIR="${USER_HOME}/.local/share/n1-monitor"
VENV="${N1MON_DIR}/.venv"

log() { printf '\n\e[1;36m▸ %s\e[0m\n' "$*"; }
ok()  { printf '  \e[32m✓\e[0m %s\n' "$*"; }
warn(){ printf '  \e[33m⚠\e[0m %s\n' "$*"; }

# ============================================================
# Phase 1 : libération espace disque /
# ============================================================
log "Phase 1 — nettoyage disque /"
df -h / | tail -1
apt clean
ok "apt clean fait"
journalctl --vacuum-time=30d > /dev/null 2>&1 || true
ok "journal vacuum 30d"
df -h /

# ============================================================
# Phase 2 : Mullvad lockdown (killswitch)
# ============================================================
log "Phase 2 — Mullvad lockdown ON"
if command -v mullvad >/dev/null 2>&1; then
    mullvad lockdown-mode set on
    ok "lockdown ON"
    mullvad lockdown-mode get
else
    warn "mullvad CLI introuvable, skip"
fi

# ============================================================
# Phase 3 : sysctl hardening additions
# ============================================================
log "Phase 3 — sysctl hardening supplémentaire"
SYSCTL=/etc/sysctl.d/99-hardening.conf
if ! grep -q "kernel.kptr_restrict" "$SYSCTL" 2>/dev/null; then
    cat >> "$SYSCTL" <<'EOF'

# Ajouts n1-setup (audit)
kernel.kptr_restrict = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 4
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv6.conf.all.disable_ipv6 = 1
EOF
    ok "sysctl ajouté dans $SYSCTL"
else
    warn "sysctl déjà patché, skip"
fi
sysctl --system > /dev/null 2>&1 || true
ok "sysctl --system rechargé"

# ============================================================
# Phase 4 : sudoers NOPASSWD pour les toggles
# ============================================================
log "Phase 4 — sudoers NOPASSWD ciblé"
SUDOERS=/etc/sudoers.d/n1-monitor
cat > "$SUDOERS" <<EOF
# Permissions ciblées pour le widget n1-monitor (toggles firewall + Mullvad)
${USER_NAME} ALL=(root) NOPASSWD: /usr/sbin/nft -f /etc/nftables-hardening.conf, /usr/sbin/nft delete table inet hardening, /usr/bin/mullvad lockdown-mode set on, /usr/bin/mullvad lockdown-mode set off
EOF
chmod 440 "$SUDOERS"
visudo -cf "$SUDOERS" > /dev/null
ok "sudoers ajouté ($SUDOERS)"

# ============================================================
# Phase 5 : venv Python + Textual pour le TUI
# ============================================================
log "Phase 5 — venv Python + Textual"
sudo -u "$USER_NAME" python3 -m venv "$VENV"
sudo -u "$USER_NAME" "$VENV/bin/pip" install --quiet --upgrade pip
sudo -u "$USER_NAME" "$VENV/bin/pip" install --quiet -r "$N1MON_DIR/requirements.txt"
ok "venv prêt : $VENV"

# ============================================================
# Phase 6 : wrapper /usr/local/bin/n1mon
# ============================================================
log "Phase 6 — wrapper n1mon"
cat > /usr/local/bin/n1mon <<EOF
#!/bin/sh
exec ${VENV}/bin/python ${N1MON_DIR}/tui.py "\$@"
EOF
chmod 755 /usr/local/bin/n1mon
ok "/usr/local/bin/n1mon installé"

# ============================================================
# Phase 7 : service systemd pour le collector
# ============================================================
log "Phase 7 — service systemd n1mon-collector"
cat > /etc/systemd/system/n1mon-collector.service <<EOF
[Unit]
Description=n1 monitor — collecteur firewall/réseau/VPN
After=nftables-hardening.service network-online.target
Wants=nftables-hardening.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${N1MON_DIR}/collector.py --interval 2
Restart=on-failure
RestartSec=3
# Hardening modéré (le service a besoin d'accéder à nft, journal kernel, ss --processes)
NoNewPrivileges=true
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=/run
# Journal de présence infra persistant (crée /var/lib/n1-monitor, root:root)
StateDirectory=n1-monitor
PrivateTmp=true
LockPersonality=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
MemoryMax=128M
CPUQuota=15%

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable n1mon-collector.service
# restart (pas 'enable --now') : recharge le code même si le service tourne déjà
systemctl restart n1mon-collector.service
sleep 1
systemctl --no-pager --lines 5 status n1mon-collector.service || true

# Vérification : le JSON existe ?
sleep 2
if [[ -f /run/n1-monitor.json ]]; then
    ok "/run/n1-monitor.json créé"
    ls -la /run/n1-monitor.json
else
    warn "/run/n1-monitor.json absent — check 'journalctl -u n1mon-collector -n 30'"
fi

# ============================================================
# Phase 7b : service de découverte LAN (identité autonome mDNS/ARP)
# ============================================================
log "Phase 7b — service n1mon-lan-discovery"
# Tourne en root avec CAP_NET_RAW SEUL (pas de CAP_DAC_OVERRIDE) → il ne peut
# pas lire un script dans /home (mode 700). On l'installe en chemin système.
install -d -m 0755 /usr/local/lib/n1-monitor
install -m 0644 "${N1MON_DIR}/lan_discovery.py" /usr/local/lib/n1-monitor/lan_discovery.py
ok "lan_discovery.py installé dans /usr/local/lib/n1-monitor"
install -m 0644 "${N1MON_DIR}/systemd/n1mon-lan-discovery.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable n1mon-lan-discovery.service
systemctl restart n1mon-lan-discovery.service
sleep 1
if [[ -f /run/n1-monitor-lan.json ]]; then
    ok "/run/n1-monitor-lan.json créé (découverte LAN active)"
else
    warn "/run/n1-monitor-lan.json absent — check 'journalctl -u n1mon-lan-discovery -n 30'"
fi

# ============================================================
# Phase 8 : raccourci clavier Super+F → n1mon (via GSettings)
# ============================================================
log "Phase 8 — raccourci clavier Super+F"
# Setup custom keybinding pour le user GNOME, via dbus avec son env
USER_UID=$(id -u "$USER_NAME")
sudo -u "$USER_NAME" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${USER_UID}/bus" \
    bash -c '
        set -e
        SCHEMA="org.gnome.settings-daemon.plugins.media-keys"
        BIND_SCHEMA="org.gnome.settings-daemon.plugins.media-keys.custom-keybinding"
        PATH_KB="/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/n1mon/"
        EXISTING=$(gsettings get $SCHEMA custom-keybindings 2>/dev/null || echo "@as []")
        # On ajoute notre path SEULEMENT s'\''il n'\''y est pas déjà — sans écraser les autres raccourcis
        if [[ "$EXISTING" != *"n1mon"* ]]; then
            if [[ "$EXISTING" == "@as []" || "$EXISTING" == "[]" ]]; then
                NEW="['\''$PATH_KB'\'']"
            else
                NEW="${EXISTING%]}, '\''$PATH_KB'\'']"
            fi
            gsettings set $SCHEMA custom-keybindings "$NEW"
        fi
        gsettings set "$BIND_SCHEMA:$PATH_KB" name "n1mon TUI"
        gsettings set "$BIND_SCHEMA:$PATH_KB" command "ghostty -e n1mon"
        gsettings set "$BIND_SCHEMA:$PATH_KB" binding "<Super>F"
    ' && ok "raccourci Super+F → n1mon configuré" || warn "raccourci à configurer manuellement"

# ============================================================
# Phase 9 : activation de l'extension GNOME
# ============================================================
log "Phase 9 — activation extension GNOME"
sudo -u "$USER_NAME" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${USER_UID}/bus" \
    gnome-extensions enable n1-monitor@ocb 2>&1 || warn "l'extension nécessite un logout/login pour être détectée par GNOME 48 — voir Phase 10"

# ============================================================
# Phase 10 : récap final
# ============================================================
log "Phase 10 — terminé"
cat <<EOF

Pour activer définitivement le widget :
  1. Sur Wayland (ton cas), GNOME doit recharger les extensions.
     Option A : log out / log in
     Option B : 'busctl --user call org.gnome.Shell.Extensions /org/gnome/Shell/Extensions org.gnome.Shell.Extensions ReloadExtension s n1-monitor@ocb' (ne marche pas toujours sous Wayland)
     Option C : tape Alt+F2 → 'r' (X11 only — chez toi Wayland, donc fais logout/login)
  2. Vérifie : gnome-extensions list --enabled | grep n1
  3. Si pas activé : gnome-extensions enable n1-monitor@ocb

TUI : lance avec 'n1mon' depuis Ghostty (ou Super+F).
Tu peux suivre le collector : journalctl -u n1mon-collector -f

Reste à faire MANUELLEMENT (les compose actifs ne sont pas touchés) :
  • rebind les services exposés (docker-compose) sur 127.0.0.1 + mot de passe Redis/DB
  • préfixer les *_HOST_PORT exposés par 127.0.0.1 dans les .env
  • chmod 600 sur les .env (voir n1-fix-envs.sh)
  • déplacer les clés privées *.pem hors de ~/Téléchargements (voir n1-fix-envs.sh)

EOF
