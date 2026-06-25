#!/usr/bin/env bash
# =============================================================================
# harden.sh — durcissement d'un VPS Debian/Ubuntu pour exposer p2pfs.
# Idempotent : relançable sans risque. À exécuter en root au provisioning.
#
#   sudo SSH_PORT=22 ADMIN_USER=deploy ./harden.sh
#
# Ce que ça fait :
#   - met à jour le système + active les patchs de sécurité automatiques
#   - SSH : clés uniquement, pas de root, pas de mot de passe
#   - UFW : deny par défaut, autorise seulement SSH + 80/443
#   - fail2ban sur SSH
#   - durcissement noyau (sysctl)
#   - installe le binaire p2pfs + l'unit systemd + Caddy
#
# ⚠️ Vérifiez que votre clé SSH publique est bien déployée AVANT de lancer
#    (sinon vous pourriez vous verrouiller dehors).
# =============================================================================
set -euo pipefail

SSH_PORT="${SSH_PORT:-22}"
ADMIN_USER="${ADMIN_USER:-}"
DOMAIN="${DOMAIN:-vault.example.com}"

log() { printf '\033[1;34m[harden]\033[0m %s\n' "$*"; }
[[ $EUID -eq 0 ]] || { echo "à lancer en root"; exit 1; }

# --- 1. Système à jour + mises à jour de sécurité automatiques ---------------
log "mise à jour du système…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get -y -qq upgrade
apt-get -y -qq install ufw fail2ban unattended-upgrades curl ca-certificates debian-keyring debian-archive-keyring apt-transport-https

log "activation des mises à jour de sécurité automatiques…"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
dpkg-reconfigure -f noninteractive unattended-upgrades || true

# --- 2. Durcissement SSH -----------------------------------------------------
log "durcissement SSH (port $SSH_PORT, clés uniquement)…"
install -d -m 755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<EOF
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
AllowTcpForwarding no
EOF
if [[ -n "$ADMIN_USER" ]]; then
  echo "AllowUsers ${ADMIN_USER}" >> /etc/ssh/sshd_config.d/99-hardening.conf
fi
sshd -t && systemctl reload ssh 2>/dev/null || systemctl reload sshd

# --- 3. Pare-feu UFW ---------------------------------------------------------
log "configuration UFW (deny par défaut)…"
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}"/tcp comment 'SSH'
ufw allow 80/tcp  comment 'HTTP (ACME challenge / redirect)'
ufw allow 443/tcp comment 'HTTPS (WebUI)'
ufw --force enable
ufw status verbose

# --- 4. fail2ban sur SSH -----------------------------------------------------
log "configuration fail2ban…"
cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled  = true
port     = ${SSH_PORT}
maxretry = 4
findtime = 10m
bantime  = 1h
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban

# --- 5. Durcissement noyau (sysctl) -----------------------------------------
log "durcissement noyau…"
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# anti-spoofing
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
# ignore redirects ICMP (anti-MITM)
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
# ignore source routing
net.ipv4.conf.all.accept_source_route=0
# SYN cookies (anti SYN-flood)
net.ipv4.tcp_syncookies=1
# log des paquets martiens
net.ipv4.conf.all.log_martians=1
# ASLR
kernel.randomize_va_space=2
# restreint l'accès au dmesg
kernel.dmesg_restrict=1
EOF
sysctl --system >/dev/null

# --- 6. Installation du binaire + service + Caddy ----------------------------
if [[ -f ./p2pfs ]]; then
  log "installation du binaire p2pfs…"
  install -m 0755 ./p2pfs /usr/local/bin/p2pfs
fi
if [[ -f ./deploy/p2pfs.service ]]; then
  install -m 0644 ./deploy/p2pfs.service /etc/systemd/system/p2pfs.service
  systemctl daemon-reload
  systemctl enable p2pfs
  systemctl restart p2pfs
  log "p2pfs actif : $(systemctl is-active p2pfs)"
fi

if ! command -v caddy >/dev/null 2>&1; then
  log "installation de Caddy…"
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq && apt-get install -y -qq caddy
fi
if [[ -f ./deploy/Caddyfile ]]; then
  sed "s/vault.example.com/${DOMAIN}/g" ./deploy/Caddyfile > /etc/caddy/Caddyfile
  install -d -m 0755 /var/log/caddy
  systemctl enable --now caddy
  systemctl reload caddy || systemctl restart caddy
  log "Caddy actif : $(systemctl is-active caddy)"
fi

log "TERMINÉ. Vérifiez : systemd-analyze security p2pfs ; ufw status ; curl -I https://${DOMAIN}"
