#!/usr/bin/env bash
# =============================================================================
# gcp-provision.sh — déploiement complet de p2pfs sur GCP Compute Engine.
#
# Idempotent : relançable sans risque (chaque ressource est créée seulement si
# absente). Trois phases :
#
#   ./deploy/gcp-provision.sh provision   # infra : réseau, firewall, IP, VM, snapshots
#   #   --> créer l'enregistrement DNS A : DOMAIN -> IP affichée
#   ./deploy/gcp-provision.sh deploy      # build + scp du binaire + harden.sh (TLS)
#   ./deploy/gcp-provision.sh destroy     # tout supprimer (⚠️ détruit les données)
#
# « all » = provision puis instructions (le DNS doit être posé avant deploy).
#
# Prérequis : gcloud authentifié (`gcloud auth login`), un projet de facturation,
# Go + dig sur la machine locale.
# =============================================================================
set -euo pipefail

# ----------------------------- CONFIG ----------------------------------------
PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${REGION:-europe-west9}"            # Paris ; pour le FREE TIER e2-micro : us-central1
ZONE="${ZONE:-europe-west9-a}"              # ... et us-central1-a
VM_NAME="${VM_NAME:-p2pfs}"
MACHINE_TYPE="${MACHINE_TYPE:-e2-micro}"    # la moins chère ; passe à e2-small/e2-medium plus tard
DOMAIN="${DOMAIN:-p2pfs.example.com}"       # TON domaine (RP ID WebAuthn — IMMUABLE !)
NETWORK="${NETWORK:-p2pfs-net}"
IP_NAME="${IP_NAME:-p2pfs-ip}"
BOOT_SIZE="${BOOT_SIZE:-20GB}"
BOOT_TYPE="${BOOT_TYPE:-pd-standard}"       # pd-standard = le moins cher ; pd-balanced si + d'IOPS
SSH_SRC="${SSH_SRC:-}"                       # ton IP en /32 pour SSH ; vide => auto-détection
SNAP_RETENTION="${SNAP_RETENTION:-14}"      # jours de rétention des snapshots
ADMIN_USER="${ADMIN_USER:-}"                # vide => pas de restriction AllowUsers (évite tout lockout)
NETWORK_TAG="p2pfs"
SNAP_POLICY="p2pfs-daily"
# -----------------------------------------------------------------------------

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
log()  { printf '\033[1;34m[gcp]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[gcp]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[gcp] %s\033[0m\n' "$*" >&2; exit 1; }
gx()   { gcloud "$@" --project "$PROJECT"; }              # gcloud avec projet
exists() { "$@" >/dev/null 2>&1; }                        # vrai si la commande réussit

[[ -n "$PROJECT" ]] || die "Aucun projet GCP. Fais : gcloud config set project <ID>  (ou PROJECT=<ID>)."

# --------------------------------------------------------------------------- #
provision() {
  log "Projet=$PROJECT  Région=$REGION  Zone=$ZONE  VM=$VM_NAME ($MACHINE_TYPE)"
  log "Activation de l'API Compute…"
  gx services enable compute.googleapis.com

  # 1) Réseau dédié (on maîtrise tout le pare-feu, pas de règle 'default' trop large)
  if exists gx compute networks describe "$NETWORK"; then
    log "réseau $NETWORK : déjà présent"
  else
    log "création du réseau ${NETWORK}…"
    gx compute networks create "$NETWORK" --subnet-mode=auto
  fi

  # 2) IP SSH source (auto-détection si non fournie)
  if [[ -z "$SSH_SRC" ]]; then
    myip="$(curl -fsS https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ -n "$myip" ]]; then SSH_SRC="${myip}/32"; log "IP SSH auto-détectée : $SSH_SRC"
    else SSH_SRC="0.0.0.0/0"; warn "IP non détectée → SSH ouvert à TOUS. Définis SSH_SRC=<ip>/32 !"; fi
  fi

  # 3) Pare-feu VPC : 80/443 publics, 22 restreint, RIEN d'autre (jamais 8000)
  if ! exists gx compute firewall-rules describe p2pfs-allow-web; then
    log "firewall : 80/443 (0.0.0.0/0)…"
    gx compute firewall-rules create p2pfs-allow-web --network="$NETWORK" \
      --direction=INGRESS --action=ALLOW --rules=tcp:80,tcp:443 \
      --source-ranges=0.0.0.0/0 --target-tags="$NETWORK_TAG"
  fi
  if ! exists gx compute firewall-rules describe p2pfs-allow-ssh; then
    log "firewall : 22 (depuis $SSH_SRC)…"
    gx compute firewall-rules create p2pfs-allow-ssh --network="$NETWORK" \
      --direction=INGRESS --action=ALLOW --rules=tcp:22 \
      --source-ranges="$SSH_SRC" --target-tags="$NETWORK_TAG"
  fi

  # 4) IP externe statique (sinon le DNS casse à chaque redémarrage)
  if ! exists gx compute addresses describe "$IP_NAME" --region "$REGION"; then
    log "réservation de l'IP statique ${IP_NAME}…"
    gx compute addresses create "$IP_NAME" --region "$REGION"
  fi
  IP="$(gx compute addresses describe "$IP_NAME" --region "$REGION" --format='value(address)')"

  # 5) VM Compute Engine (Debian 12, Shielded VM, sur le réseau dédié)
  if exists gx compute instances describe "$VM_NAME" --zone "$ZONE"; then
    log "VM $VM_NAME : déjà présente"
  else
    log "création de la VM $VM_NAME ($MACHINE_TYPE)…"
    gx compute instances create "$VM_NAME" \
      --zone="$ZONE" --machine-type="$MACHINE_TYPE" \
      --image-family=debian-12 --image-project=debian-cloud \
      --boot-disk-size="$BOOT_SIZE" --boot-disk-type="$BOOT_TYPE" --boot-disk-device-name="$VM_NAME" \
      --network="$NETWORK" --subnet="$NETWORK" \
      --address="$IP_NAME" --tags="$NETWORK_TAG" \
      --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring \
      --scopes=https://www.googleapis.com/auth/devstorage.read_write,https://www.googleapis.com/auth/logging.write,https://www.googleapis.com/auth/monitoring.write
  fi

  # 6) Snapshots planifiés + chiffrés du disque de boot (= les données /var/lib/p2pfs)
  if ! exists gx compute resource-policies describe "$SNAP_POLICY" --region "$REGION"; then
    log "politique de snapshots quotidiens (rétention ${SNAP_RETENTION}j)…"
    gx compute resource-policies create snapshot-schedule "$SNAP_POLICY" \
      --region="$REGION" --max-retention-days="$SNAP_RETENTION" \
      --daily-schedule --start-time=02:00 --storage-location="$REGION"
  fi
  log "attache de la politique de snapshots au disque de boot…"
  gx compute disks add-resource-policies "$VM_NAME" --zone "$ZONE" \
    --resource-policies="$SNAP_POLICY" 2>/dev/null || true

  cat <<EOF

\033[1;32m✓ Infra prête.\033[0m  IP statique : \033[1m$IP\033[0m
  Coût indicatif : e2-micro ~7-8 \$/mois (Paris) ou GRATUIT en free-tier (us-central1/us-west1/us-east1).

PROCHAINES ÉTAPES
  1) Crée l'enregistrement DNS  A   $DOMAIN  ->  $IP
     (le RP ID WebAuthn = $DOMAIN et il est IMMUABLE : choisis-le définitivement)
  2) Une fois le DNS propagé :   ./deploy/gcp-provision.sh deploy
EOF
}

# --------------------------------------------------------------------------- #
deploy() {
  exists gx compute instances describe "$VM_NAME" --zone "$ZONE" || die "VM absente : lance d'abord 'provision'."
  IP="$(gx compute addresses describe "$IP_NAME" --region "$REGION" --format='value(address)')"

  # Garde-fou DNS : Caddy ne peut obtenir le certificat que si DOMAIN -> IP.
  resolved="$(dig +short "$DOMAIN" A 2>/dev/null | tail -1 || true)"
  if [[ "$resolved" != "$IP" ]]; then
    warn "$DOMAIN résout vers « ${resolved:-rien} » ≠ $IP."
    warn "Caddy échouera à obtenir le certificat tant que le DNS ne pointe pas sur $IP."
    read -rp "Continuer quand même ? [y/N] " ans; [[ "$ans" == "y" || "$ans" == "Y" ]] || die "Annulé."
  fi

  log "build du binaire statique (linux/amd64)…"
  ( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o p2pfs ./cmd/p2pfs )

  log "copie du binaire + deploy/ sur la VM…"
  gx compute ssh "$VM_NAME" --zone "$ZONE" --command "mkdir -p ~/p2pfs"
  gx compute scp --zone "$ZONE" --recurse "$ROOT/p2pfs" "$ROOT/deploy" "$VM_NAME:~/p2pfs/"

  log "durcissement + installation (harden.sh) sur la VM…"
  gx compute ssh "$VM_NAME" --zone "$ZONE" --command \
    "cd ~/p2pfs && chmod +x deploy/*.sh && sudo DOMAIN='$DOMAIN' SSH_PORT=22 ${ADMIN_USER:+ADMIN_USER='$ADMIN_USER'} bash deploy/harden.sh"

  cat <<EOF

\033[1;32m✓ Déployé.\033[0m  Vérifie :
  curl -I https://$DOMAIN
  gcloud compute ssh $VM_NAME --zone $ZONE --command 'systemctl status p2pfs caddy; systemd-analyze security p2pfs'
  Sauvegarde off-VM (optionnelle) : configure deploy/backup.sh en cron (voir deploy/gcp.md §3).
EOF
}

# --------------------------------------------------------------------------- #
destroy() {
  warn "Suppression de TOUTE l'infra ($VM_NAME, réseau, firewall, IP). Les snapshots existants sont conservés."
  read -rp "Confirmer la destruction ? tape le nom de la VM ($VM_NAME) : " ans; [[ "$ans" == "$VM_NAME" ]] || die "Annulé."
  gx compute instances delete "$VM_NAME" --zone "$ZONE" --quiet 2>/dev/null || true
  gx compute firewall-rules delete p2pfs-allow-web p2pfs-allow-ssh --quiet 2>/dev/null || true
  gx compute addresses delete "$IP_NAME" --region "$REGION" --quiet 2>/dev/null || true
  gx compute networks delete "$NETWORK" --quiet 2>/dev/null || true
  log "détruit. (la politique de snapshots $SNAP_POLICY et les snapshots restent — supprime-les à la main si besoin)"
}

case "${1:-all}" in
  provision) provision ;;
  deploy)    deploy ;;
  destroy)   destroy ;;
  all)       provision ;;
  *) die "usage: $0 {provision|deploy|destroy}" ;;
esac
