#!/usr/bin/env bash
# n1-fix-envs.sh — durcit les permissions des fichiers sensibles côté user.
# À lancer en tant qu'utilisateur normal (pas root) : bash n1-fix-envs.sh
#
# Idempotent.

set -euo pipefail

if [[ $EUID -eq 0 ]]; then
    echo "→ lance en utilisateur normal (pas sudo)" >&2
    exit 1
fi

ok()  { printf '  \e[32m✓\e[0m %s\n' "$*"; }
warn(){ printf '  \e[33m⚠\e[0m %s\n' "$*"; }

# .env → 600
echo "▸ chmod 600 sur tous les .env de ~/Documents et ~/Téléchargements"
COUNT=0
while IFS= read -r -d '' f; do
    chmod 600 "$f"
    COUNT=$((COUNT+1))
done < <(find ~/Documents ~/Téléchargements -maxdepth 5 -type f \
    \( -name ".env" -o -name ".env.*" -o -name "*.pem" -o -name "*.key" \) \
    -not -path "*/node_modules/*" -not -path "*/.git/*" -print0 2>/dev/null)
ok "$COUNT fichiers passés à 600"

# Clés privées de services (GitHub App, CI, etc.) → ~/.config/secrets/
SECRETS_DIR="$HOME/.config/secrets"
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"
for f in ~/Téléchargements/*.pem; do
    if [[ -f "$f" ]]; then
        mv "$f" "$SECRETS_DIR/"
        chmod 600 "$SECRETS_DIR/$(basename "$f")"
        ok "déplacé : $(basename "$f") → $SECRETS_DIR/"
    fi
done

# .wireguard → perms strictes
if [[ -d ~/.wireguard ]]; then
    chmod 700 ~/.wireguard
    chmod 600 ~/.wireguard/*.key ~/.wireguard/*.conf 2>/dev/null || true
    ok "~/.wireguard durci (700 dir, 600 fichiers)"
fi

# .google_authenticator déjà 400, on vérifie
if [[ -f ~/.google_authenticator ]]; then
    chmod 400 ~/.google_authenticator
    ok "~/.google_authenticator confirmé 400"
fi

# .ssh check final
chmod 700 ~/.ssh
chmod 600 ~/.ssh/* 2>/dev/null || true
chmod 644 ~/.ssh/*.pub ~/.ssh/known_hosts ~/.ssh/known_hosts.old ~/.ssh/config 2>/dev/null || true
ok "~/.ssh perms canoniques"

echo ""
echo "Reste à vérifier MANUELLEMENT :"
echo "  • vérifier ~/.ssh/authorized_keys — retirer toute clé inattendue/obsolète"
echo "  • ~/Bureau/rootCA.pem — déplacer vers ~/.local/share/mkcert/ si c'est celui de mkcert"
