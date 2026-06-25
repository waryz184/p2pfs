# Déploiement sur GCP Compute Engine

Guide spécifique GCP, en complément du `README` (§6/§6 ter). Topologie cible :
**une VM Compute Engine**, **Caddy sur la VM** (TLS Let's Encrypt), `p2pfs` en
loopback derrière. Pas de Load Balancer GCP (cf. note plus bas si vous en ajoutez un).

> Le modèle de menace ne change pas : Google opère l'hyperviseur et le disque,
> mais tout est chiffré côté client — l'hébergeur ne voit que du ciphertext.
> Les risques prod sur GCP sont **opérationnels**, pas cryptographiques.

---

## 1. IP statique + DNS (obligatoire pour WebAuthn/WebCrypto)

WebCrypto (`crypto.subtle`) et WebAuthn **n'existent que dans un *secure context*** :
il faut **HTTPS sur un vrai domaine**. Servir l'app via l'IP publique GCP la casse
silencieusement.

```bash
# IP externe statique (sinon le DNS casse à chaque redémarrage de VM)
gcloud compute addresses create vault-ip --region=europe-west1
gcloud compute addresses describe vault-ip --region=europe-west1 --format='value(address)'
# → créez un enregistrement DNS A : vault.exemple.fr -> cette IP
# puis attachez l'IP à la VM (ou créez la VM avec --address=vault-ip)
```

> ⚠️ **Le RP ID WebAuthn = le domaine, et il est IMMUABLE.** Les passkeys enrôlées
> sont liées à `vault.exemple.fr`. **Changer de domaine invalide toutes les clés
> de sécurité** (les utilisateurs devront rouvrir à la seed puis ré-enrôler).
> Choisissez le domaine définitif **avant** d'enrôler des clés.

---

## 2. Pare-feu VPC (la vraie frontière sur GCP, pas UFW)

`harden.sh` configure UFW au niveau OS, mais sur GCP **le pare-feu VPC est la
frontière effective**. Règles minimales (par tag réseau `vault`) :

```bash
# 80/443 ouverts à tous (HTTP pour l'ACME, HTTPS pour la WebUI)
gcloud compute firewall-rules create vault-web \
  --direction=INGRESS --action=ALLOW --rules=tcp:80,tcp:443 \
  --source-ranges=0.0.0.0/0 --target-tags=vault

# SSH uniquement depuis VOTRE IP (remplacez X.X.X.X/32)
gcloud compute firewall-rules create vault-ssh \
  --direction=INGRESS --action=ALLOW --rules=tcp:22 \
  --source-ranges=X.X.X.X/32 --target-tags=vault

# taguez la VM
gcloud compute instances add-tags VM_NAME --tags=vault --zone=ZONE
```

**Ne JAMAIS ouvrir le port 8000.** `p2pfs` écoute sur `127.0.0.1:8000` ; il ne doit
être joignable que par Caddy, sur la même VM. Vérifiez qu'aucune règle large
(`default-allow-internal` trop permissive, autre service du projet) n'expose 8000.

---

## 3. Chiffrement disque & sauvegardes (DR)

Un coffre zero-knowledge perdu est **irrécupérable** (la seed n'est pas chez vous) :
la perte du volume `/var/lib/p2pfs` = perte définitive pour l'utilisateur. Donc :

```bash
# Snapshots planifiés et CHIFFRÉS du disque de données (crash-consistants pour un
# disque unique). Adaptez le calendrier/rétention.
gcloud compute resource-policies create snapshot-schedule vault-daily \
  --region=europe-west1 --max-retention-days=14 \
  --daily-schedule --start-time=02:00 --storage-location=eu

gcloud compute disks add-resource-policies DATA_DISK \
  --resource-policies=vault-daily --zone=ZONE
```

- Par défaut Google chiffre les disques ; pour un contrôle des clés, utilisez **CMEK**
  (`--kms-key=...` à la création du disque). Les **snapshots héritent** du chiffrement.
- Mettez **les données sur un disque persistant dédié** monté sur `/var/lib/p2pfs`
  (pas le disque de boot), pour snapshotter/restaurer les données seules.
- Sauvegarde applicative complémentaire (off-VM) : voir `deploy/backup.sh` (tar +
  envoi GCS optionnel). À tester **avec une restauration réelle** au moins une fois.

---

## 4. Installation

```bash
# build (sur votre machine)
./build.sh                                   # binaire Linux statique
scp -r p2pfs deploy/ DEPLOY_USER@VM:/root/p2pfs/

# sur la VM
cd /root/p2pfs
sudo DOMAIN=vault.exemple.fr ADMIN_USER=deploy SSH_PORT=22 ./deploy/harden.sh

# vérifications
systemd-analyze security p2pfs     # vise un score d'exposition faible
journalctl -u p2pfs -f             # doit logguer un arrêt PROPRE sur restart
curl -I https://vault.exemple.fr
```

`p2pfs` s'arrête désormais **proprement** sur `SIGTERM` (drain des uploads), et
`flush()` est **durable** (fsync) : un `systemctl restart` ou une maintenance GCE ne
corrompt plus l'index ni n'interrompt brutalement un transfert.

---

## 5. Quotas (rappel)

`p2pfs.service` lance avec des plafonds par défaut (`-max-account-bytes 5 Go`,
`-max-total-bytes 50 Go`). Ajustez-les à la taille de votre disque de données dans
l'unité systemd, et gardez une **marge** sous la taille réelle du disque.

---

## Si vous mettez un Load Balancer GCP / Cloud Armor devant (hors topologie par défaut)

Alors Caddy/p2pfs ne voient plus l'IP client mais celle du LB Google ; le vrai
client est dans le `X-Forwarded-For` posé par Google. Il faut **déclarer les plages
des Google Front Ends comme proxies de confiance**, sinon le rate-limit s'indexe sur
l'IP du LB (un seul bucket pour tout le monde) :

```
p2pfs ... -trusted-proxies "130.211.0.0/22,35.191.0.0/16"
```

Et activez **Cloud Armor** (WAF + rate-limit au bord) en première ligne. Sans LB,
ne touchez pas à `-trusted-proxies` : le défaut loopback est correct pour Caddy-sur-VM.

---

## Contraintes à verrouiller (mono-VM)

- **Pas d'autoscaling / MIG multi-instances** : sessions et rate-limit sont en
  mémoire d'un seul process. Plusieurs instances partageant le même disque casseraient
  l'index et les sessions. Restez à **une instance**.
- **Domaine définitif avant enrôlement de clés** (RP ID immuable, cf. §1).
- **Jamais le port 8000 exposé**, jamais l'IP publique servie directement.
