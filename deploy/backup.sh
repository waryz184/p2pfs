#!/usr/bin/env bash
# =============================================================================
# backup.sh — sauvegarde applicative cohérente de p2pfs.
#
# Cohérence : `index.json` est écrit atomiquement + fsync (write-temp + rename +
# fsync), et les blobs sont adressés par contenu et write-once (temp `.tmp.<alea>`
# puis rename). Un tar du répertoire de données est donc crash-consistant « assez »
# (un blob en cours d'écriture n'est qu'un `.tmp.*`, exclu ; l'index n'apparaît
# jamais à moitié écrit). Pour une cohérence forte au niveau bloc, préférez un
# snapshot GCP du disque (voir deploy/gcp.md §3).
#
#   sudo DATA=/var/lib/p2pfs OUT=/var/backups/p2pfs ./backup.sh
#   sudo DATA=/var/lib/p2pfs GCS=gs://mon-bucket/p2pfs ./backup.sh   # envoi GCS
#
# À planifier (cron/systemd timer) ET à TESTER avec une restauration réelle.
# =============================================================================
set -euo pipefail

DATA="${DATA:-/var/lib/p2pfs}"
OUT="${OUT:-/var/backups/p2pfs}"
GCS="${GCS:-}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE="${OUT}/p2pfs-${STAMP}.tar.gz"
RETENTION_DAYS="${RETENTION_DAYS:-14}"

[[ -d "$DATA" ]] || { echo "répertoire de données introuvable : $DATA" >&2; exit 1; }
mkdir -p "$OUT"

echo "[backup] archive de $DATA -> $ARCHIVE"
# --exclude des fichiers temporaires d'uploads interrompus
tar --exclude='*.tmp' --exclude='*.tmp.*' -czf "$ARCHIVE" -C "$(dirname "$DATA")" "$(basename "$DATA")"

# vérif d'intégrité de l'archive
gzip -t "$ARCHIVE"
echo "[backup] OK ($(du -h "$ARCHIVE" | cut -f1))"

# envoi off-VM optionnel vers GCS (chiffré au repos côté Google)
if [[ -n "$GCS" ]]; then
  echo "[backup] envoi vers $GCS/"
  gsutil cp "$ARCHIVE" "${GCS%/}/"
fi

# rotation locale
find "$OUT" -name 'p2pfs-*.tar.gz' -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
echo "[backup] terminé. Pensez à TESTER une restauration : tar xzf <archive> -C /tmp/restore"
