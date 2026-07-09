# p2pfs — POC de stockage chiffré zero-knowledge

Coffre-fort de fichiers chiffré **de bout en bout**, auto-hébergé sur un VPS, accessible
via une **WebUI**. Le client ouvre son coffre avec une **seed phrase** (12 mots BIP-39) ;
toute la cryptographie se passe **dans le navigateur**. Le serveur ne stocke que des
octets opaques : il ne peut lire ni le contenu, ni les noms de fichiers, même si on le
compromet entièrement.

> POC testé : **15/15** tests crypto + **18/18** tests d'intégration HTTP, et opacité
> serveur démontrée (aucune donnée en clair sur disque). Voir `TESTS` plus bas.

---

## 1. Principe en une image

```
 NAVIGATEUR (client)                          VPS (serveur "dumb storage")
 ─────────────────────                        ─────────────────────────────
 seed phrase (12 mots)                         Caddy :443  ── TLS auto (LE)
   │ BIP-39 (PBKDF2-SHA512)                       │ reverse-proxy
   ▼                                              ▼
 seed 64 o                                     p2pfs  (binaire Go, :8000 loopback)
   │ HKDF-SHA256                                  ├─ /api/*   auth + métadonnées
   ├──► clé Ed25519  ──── challenge/réponse ────► │   (vérif signature, sessions)
   │    (identité, jamais transmise)              ├─ index.json   pubkey + métas CHIFFRÉES
   └──► KEK AES-256                               └─ blobs/       ciphertext opaque (sha256)
        │                                                        
        ├─ chiffre chaque fichier (DEK aléatoire, AES-256-GCM)  
        ├─ enveloppe la DEK avec la KEK                          
        └─ chiffre les noms de fichiers                          
                                                                 
   ───── n'envoie QUE : pubkey, ciphertext, DEK enveloppée, noms chiffrés ─────►
```

Le serveur ne voit jamais : la seed, les clés privées, la KEK, les DEK en clair,
le contenu, les noms en clair.

---

## 2. Stack technique (et pourquoi)

| Couche | Choix | Justification |
|---|---|---|
| **Serveur** | **Go**, stdlib `net/http` uniquement | Binaire statique unique (~5,5 Mo), zéro runtime, zéro dépendance externe → surface d'attaque et CVE minimales. Routing `mux` natif (Go 1.22). |
| **WebUI** | **JS vanilla + ES modules**, embarquée via `embed.FS` | Gestionnaire de fichiers façon Drive/Nextcloud (barre latérale, vues grille/liste, dossiers, glisser-déposer). Pas de framework, pas de build step, tout est inspectable. Servie depuis le même binaire. |
| **Crypto navigateur** | **WebCrypto** (AES-GCM, HKDF, PBKDF2) + **@noble/ed25519** + **@scure/bip39** | Libs auditées, minimales (40 ko bundlées), même auteur (Paul Miller). WebCrypto pour le chiffrement symétrique natif/rapide. |
| **Identité / auth** | **Ed25519** challenge-réponse | Aucun secret transmis : le client signe un nonce, le serveur vérifie la signature. Pas de mot de passe à stocker/fuiter. |
| **Chiffrement fichiers** | **AES-256-GCM**, DEK par fichier enveloppée par la KEK | GCM = chiffrement authentifié (intègre + confidentiel). Une DEK par fichier limite l'impact d'une fuite et permet le partage futur. |
| **Stockage blobs** | Fichiers sur disque, **adressés par contenu** (sha256) | Déduplication gratuite, intégrité vérifiable, pas de base lourde. |
| **Métadonnées** | **SQLite** (prod) / JSON (POC) | Un seul fichier, pas de serveur DB à sécuriser/patcher. |
| **TLS / exposition** | **Caddy** | Let's Encrypt automatique, renouvellement auto, config 3 lignes, robuste. |
| **Exécution** | **systemd** sandboxé (ou Docker `scratch`) | Sandboxing noyau gratuit (`ProtectSystem`, `NoNewPrivileges`, seccomp…). |
| **Durcissement VPS** | `harden.sh` idempotent | SSH clés-only, UFW deny-par-défaut, fail2ban, sysctl, MAJ auto. |

**Pourquoi pas Docker par défaut ?** Pour un service auto-suffisant, systemd offre un
sandboxing aussi fort sans ajouter le daemon Docker (et son contournement classique d'UFW
via la chaîne `DOCKER` iptables) à la surface d'attaque. Le `Dockerfile` `scratch` reste
fourni si tu préfères la repro conteneurisée.

---

## 3. Détail cryptographique

### 3.1 Dérivation des clés (client, `crypto.js`)
```
mnémonique ──BIP-39──► seed (512 bits)
seed ──HKDF-SHA256(info="vault-auth-ed25519-v1")──► 32 o ──► clé privée Ed25519 ──► pubkey (identité)
seed ──HKDF-SHA256(info="vault-enc-master-v1")────► 32 o ──► KEK (AES-256-GCM)
```
La pubkey **est** l'identité du coffre (pas de username/email). Déterministe : la même
seed rouvre toujours le même coffre depuis n'importe quel navigateur.

### 3.2 Authentification (challenge-réponse)
1. `POST /api/challenge {pubkey}` → le serveur tire un **nonce** aléatoire (TTL 60 s).
2. Le client **signe** le nonce avec sa clé Ed25519.
3. `POST /api/login {pubkey, nonce, sig}` → le serveur **vérifie** la signature contre la
   pubkey, consomme le nonce (usage unique, anti-rejeu) et émet un **token de session**.
   Le token n'est **jamais stocké en clair** : la base ne contient que son `sha256`.

### 3.3 Chiffrement d'un fichier (par morceaux)
- **DEK** aléatoire par fichier (256 bits), **enveloppée une seule fois** par la KEK.
- Le fichier est découpé en **morceaux de 8 Mio** ; chaque morceau est chiffré en
  AES-256-GCM avec **son propre IV**. Taille de fichier arbitraire, et à l'upload on ne
  charge qu'un morceau en mémoire à la fois (`Blob.slice`).
- Chaque morceau → un blob, `blob_id = sha256(ciphertext)` revérifié par le serveur.
- Le **manifeste** (liste ordonnée `{blob_id, iv, size}`) est stocké dans la métadonnée.
  Il ne révèle rien : un `blob_id` est un hash de ciphertext, indistinguable d'aléa ; le
  nombre de morceaux ne dit que la taille, déjà exposée par `size`.
- **Liaison de contexte (AAD).** Chaque morceau est chiffré avec l'AAD
  `vault-chunk-v1:{fileID}:{index}:{total}` ; le nom avec `vault-name-v1:{fileID}` et la
  DEK enveloppée avec `vault-dek-v1:{fileID}`. Comme le tag GCM couvre l'AAD, le serveur
  ne peut **ni réordonner, ni tronquer, ni dupliquer** les morceaux, ni **associer le nom
  d'un fichier au contenu/clé d'un autre** : toute incohérence fait échouer GCM. L'`id`
  logique est donc généré **avant** le chiffrement.
- Au download, le client récupère chaque morceau, le déchiffre avec la DEK **et l'AAD
  reconstruit depuis sa position réelle**, puis réassemble.

---

## 4. Modèle de menace — ce contre quoi le POC protège

| Menace | Protection |
|---|---|
| **Serveur compromis / admin malveillant / vol de disque** | Zero-knowledge : tout est chiffré côté client. L'attaquant n'obtient que du ciphertext et des noms chiffrés. **Démontré** (grep disque = aucune fuite). |
| **Vol de la base de métadonnées** | Ne contient que pubkeys + champs chiffrés + hash de tokens. Aucune session ni donnée exploitable. |
| **Rejeu de login** | Nonce à usage unique + TTL court + comparaison à temps constant. |
| **Brute-force auth** | Pas de mot de passe (signature obligatoire) + rate-limit par IP sur `/challenge` et `/login`. |
| **Énumération des blobs d'autrui** | Un blob n'est servi que s'il est référencé par un fichier de l'appelant (contrôle d'ownership). **Démontré** (403 cross-coffre). |
| **Altération du ciphertext** | AES-GCM (authentifié) → déchiffrement rejeté. **Démontré**. |
| **Réordonnancement / troncature / permutation de champs par le serveur** | Chaque opération GCM est **liée à son contexte par AAD** : les morceaux à `(fileID, index, total)`, le nom et la DEK enveloppée au `fileID`. Un serveur qui réordonne/tronque le manifeste, ou associe le nom du fichier A au contenu de B, fait **échouer le déchiffrement**. **Démontré** (tests crypto + e2e). |
| **DoS basique** | Limites de taille (corps, blobs 64 MiB, headers), timeouts HTTP, `MemoryMax`/`TasksMax`. Blobs lus/écrits **en flux** (pas de chargement intégral en RAM). **Quotas** par compte + plafond global (anti remplissage disque). Rate-limit indexé sur une **IP non falsifiable**. |
| **Injection JS / vol de seed via XSS** | **CSP stricte** (`default-src 'none'`, `script-src 'self'`, `connect-src 'self'`), token en mémoire volatile (pas de `localStorage`), no inline script/style. |
| **Capture de la seed à la saisie (keylogger)** | **Déverrouillage par clé matérielle** (WebAuthn/PRF) : aucune saisie de la seed au quotidien, secret dérivé dans le matériel, présence physique requise. La seed reste la récupération hors-ligne. Voir §6 bis. |
| **MITM réseau** | TLS obligatoire (WebCrypto exige un secure context), HSTS. |
| **Attaques niveau OS** | `harden.sh` + sandboxing systemd (seccomp, no-new-privs, FS read-only, capabilities vidées). |

### Limites assumées du POC (à connaître)
- **Tu sers toi-même le code crypto.** Un serveur compromis pourrait servir un JS
  malveillant qui exfiltre la seed à la saisie. C'est la limite structurelle de **toute**
  app crypto web (Proton, Bitwarden web…). La CSP réduit le risque mais ne l'élimine pas
  (et `connect-src 'self'` ne protège pas d'un serveur malveillant, qui contrôle aussi
  l'endpoint). Atténuations possibles en prod : SRI inter-origine, extension/app native,
  **build reproductible publié** (la vraie réponse).
- **Anti-rollback partiel.** L'AAD empêche la permutation/troncature/réordonnancement
  *au sein d'un état*, mais un serveur malveillant peut toujours resservir un **état
  global ancien et cohérent** (rollback). S'en prémunir totalement exige une ancre de
  fraîcheur côté client (racine signée mémorisée) — hors scope POC, documenté ici.
- **Pas de rotation/révocation de clés** : la seed perdue = données perdues ; seed
  compromise = re-chiffrement nécessaire (pas encore implémenté). Les **sessions** sont
  en revanche révocables (déconnexion → invalidation serveur immédiate).
- **Pas de partage entre utilisateurs** (le cryptree de Peergos fait ça ; hors scope POC).
- **Rate-limiter en mémoire** : ne survit pas à un redémarrage, ne couvre pas un cluster.
  L'IP client est déterminée de façon **non falsifiable** (X-Forwarded-For honoré
  uniquement depuis les `-trusted-proxies`).
- **Store JSON** : pour le POC. Passe en SQLite pour la prod (§7).
- **Quotas** : plafond **par compte** (`-max-account-bytes`, 5 Go défaut) et **global**
  (`-max-total-bytes`, 50 Go défaut). Facturation non implémentée.

---

## 5. Lancer en local (POC)

```bash
# 1. build (binaire statique, WebUI embarquée)
CGO_ENABLED=0 go build -ldflags "-s -w" -o p2pfs ./cmd/p2pfs

# 2. run
./p2pfs -addr 127.0.0.1:8000 -data ./p2pfsdata

# 3. ouvrir http://127.0.0.1:8000
#    - clique « Générer une nouvelle seed » (NOTE-LA : c'est ta seule clé)
#    - « Ouvrir », puis glisse des fichiers
```
> En local, `http://localhost` est un *secure context* valide → WebCrypto fonctionne sans
> TLS. En accès distant, **TLS obligatoire** (sinon WebCrypto est désactivé).

---

## 6. Déployer en production

### Option A — systemd (recommandée)
```bash
# sur ta machine : build
CGO_ENABLED=0 go build -ldflags "-s -w" -o p2pfs ./cmd/p2pfs
scp -r p2pfs deploy/ root@VPS:/root/p2pfs/

# sur le VPS : durcissement + install (idempotent)
cd /root/p2pfs
sudo DOMAIN=vault.tondomaine.fr ADMIN_USER=deploy SSH_PORT=22 ./deploy/harden.sh

# vérifs
systemd-analyze security p2pfs     # vise un score "OK"/exposure faible
ufw status verbose
curl -I https://vault.tondomaine.fr
```
`harden.sh` installe le binaire, l'unit systemd sandboxée, Caddy (TLS auto), configure
SSH/UFW/fail2ban/sysctl et les MAJ de sécurité automatiques.

### Option B — Docker
```bash
docker build -t p2pfs:latest .
docker run -d --name vault --restart=unless-stopped \
  -p 127.0.0.1:8000:8000 -v p2pfsdata:/data p2pfs:latest
# Caddy (sur l'hôte) reverse-proxy 127.0.0.1:8000 et gère le TLS.
```

### Option C — Docker Compose (p2pfs + Caddy conteneurisés)
```bash
cp .env.example .env        # renseigner DOMAIN=vault.tondomaine.fr (jamais une IP)
docker compose up -d --build
```
`docker-compose.yml` lance deux services sur un réseau Docker dédié : `p2pfs` (non
publié sur l'hôte) et `caddy` (seul à publier 80/443, TLS auto Let's Encrypt via
`deploy/Caddyfile.docker`). Le conteneur Caddy a une IP statique sur ce réseau ; p2pfs
ne fait confiance qu'à cette IP pour `X-Forwarded-For` (F2). Les données persistent
dans le volume nommé `p2pfs_data`.

### Option D — Docker Compose + Tailscale (aucune exposition publique)
Si le serveur tourne déjà `tailscale` (hôte) et que le coffre n'a besoin d'être
accessible que depuis tes propres appareils, pas besoin de Caddy/Let's Encrypt :
Tailscale fournit déjà du TLS valide via son certificat `*.ts.net`.
```bash
docker compose -f docker-compose.tailscale.yml up -d --build

# une fois, sur l'hôte (pas dans un conteneur) — nécessite MagicDNS + "HTTPS
# Certificates" activés sur le tailnet (login.tailscale.com/admin/dns) :
sudo tailscale serve https / http://127.0.0.1:8000
tailscale serve status   # affiche l'URL du vault, ex. https://monserveur.tailxxxx.ts.net
```
Aucun port n'est publié sur l'hôte à part `127.0.0.1:8000` (loopback, inatteignable
depuis l'extérieur) ; `tailscale serve` s'en charge et persiste après reboot. La
config `tailscale serve` est à faire une seule fois, hors Portainer (c'est une
commande hôte, pas un conteneur).

---

## 6 bis. Déverrouillage par clé matérielle (WebAuthn/PRF)

En plus de la seed phrase, un coffre peut être déverrouillé par une **clé de sécurité,
une passkey ou Touch ID / Windows Hello**, via WebAuthn et l'extension **PRF**
(`hmac-secret`). Objectif : ne plus **taper** la seed au quotidien (le vecteur n°1 —
keylogger) et ne pas la garder en clair.

**Principe (le serveur reste zero-knowledge).**
```
clé matérielle ──PRF(sel app)──► secret 32 o (jamais hors du matériel)
                                   │ HKDF
                                   ▼
                            clé d'enveloppe ──AES-GCM──► master key ENVELOPPÉ (wrap)
                                                          └─ stocké côté serveur, OPAQUE
```
- **Enrôler** (coffre déverrouillé) : `registerKey()` crée un credential résident avec
  PRF ; on enveloppe le master key (= la seed 64 o) sous la PRF et on dépose le wrap via
  `PUT /api/unlock/{credentialId}`.
- **Déverrouiller** : `unlockWithKey()` fait une assertion découvrable → sortie PRF +
  `credentialId` ; on récupère le wrap (`GET /api/unlock/{credentialId}`, non authentifié
  car pré-identité, mais indexé par un id opaque à haute entropie et ne renvoyant que du
  ciphertext), on désenveloppe le master key, on dérive l'identité, on se logue.
- La **seed phrase reste la récupération** hors-ligne (perte de la clé).

**Code** : `web/webauthn.js` (cérémonie), `web/crypto.js` (`deriveUnlockKey`/`wrapMaster`/
`unwrapMaster`), endpoints `internal/server` (`/api/unlock`). Boutons « Déverrouiller avec
une clé de sécurité » (écran d'accueil) et « Ajouter une clé de sécurité » (coffre ouvert),
affichés seulement si WebAuthn est disponible (HTTPS ou `localhost`).

**Ce que ça apporte — et la limite honnête.**
- **Keylogger / seed jamais tapée** : éliminé pour le déverrouillage quotidien. ✅
- **Pas de seed en clair au repos** : le wrap est illisible sans le matériel. ✅
- **Présence physique** requise (toucher la clé) par déverrouillage. ✅
- **Serveur malveillant qui sert un JS hostile (F7)** : au déverrouillage par clé, le
  master key **réapparaît en mémoire JS** (il faut bien dériver le KEK) → ce vecteur n'est
  **pas** totalement clos. Le butin passe néanmoins de « tout, pour toujours » à « cette
  session-ci, sous présence physique ». La fermeture complète de F7 passe par une **app
  native / extension** (ancre de confiance hors du serveur) — hors scope POC.

**Tester WebAuthn/PRF** : nécessite un vrai navigateur + authentificateur. En local, Chrome
DevTools → onglet *WebAuthn* → activer un *authenticator virtuel* (CTAP2, **PRF/largeBlob**),
puis ouvrir `http://localhost:PORT`. Le **cœur cryptographique** (enveloppe/désenveloppe,
même identité seed↔clé) est lui prouvé hors navigateur : `node tests/unlock.test.mjs` et
`node e2e-unlock.test.mjs` (PRF simulée par un secret stable).

---

## 6 ter. Déploiement sur GCP Compute Engine

**Guide complet et commandes `gcloud` : [`deploy/gcp.md`](deploy/gcp.md).** En bref, l'archi
(Caddy TLS + p2pfs loopback) convient telle quelle ; les risques prod sur GCP sont
**opérationnels**, pas cryptographiques. Points qui bloquent ou risquent vraiment :

1. **Domaine obligatoire, jamais l'IP.** WebAuthn et WebCrypto exigent un *secure context* +
   un **RP ID = domaine enregistrable** (`vault.exemple.fr`). Servir via l'IP publique GCP
   **désactive WebAuthn/WebCrypto**. Le **RP ID est immuable** : changer de domaine invalide
   toutes les passkeys enrôlées → fixe le domaine **avant** d'enrôler des clés. IP statique.
2. **Pare-feu VPC (la vraie frontière), pas seulement UFW** : règles d'ingress `tcp:80,443`
   (0.0.0.0/0), `tcp:22` depuis ton IP, et **jamais le port 8000**.
3. **Disque chiffré + sauvegardes** : un coffre zero-knowledge perdu est **irrécupérable**
   (la seed n'est pas chez toi). Données sur un **disque persistant dédié**, **snapshots
   chiffrés planifiés**, et `deploy/backup.sh` (tar cohérent + GCS optionnel) — **teste la
   restauration**.
4. **`-trusted-proxies` (F2)** : Caddy-sur-VM → défaut loopback correct, rien à changer. Si tu
   ajoutes un **GCP HTTPS LB / Cloud Armor**, déclare les plages Google Front End
   (`130.211.0.0/22,35.191.0.0/16`) sinon le rate-limit s'effondre.
5. **Mono-instance** : sessions et rate-limit sont en mémoire → **pas d'autoscaling/MIG**.

> **Durcissement prod déjà intégré** : `flush()` est **durable** (fsync fichier+répertoire),
> `p2pfs` s'arrête **proprement** sur SIGTERM (drain des uploads — chaque `systemctl restart`
> / maintenance GCE), il **refuse de démarrer** si l'index est corrompu (au lieu d'écraser des
> données), et nettoie les fichiers d'upload interrompus au boot. Le modèle de menace ne change
> pas sur GCP : Google opère l'hyperviseur, mais tout est chiffré côté client.

---

## 7. Passage en prod : SQLite + BLAKE3

Le store est derrière l'interface `Store` (`internal/server/store.go`). Pour la prod :

1. **SQLite** (métadonnées) — pilote pur Go, pas de CGO :
   ```bash
   go get modernc.org/sqlite
   ```
   Réimplémente `Store` avec des requêtes paramétrées (table `accounts`, `files`).
   Active le mode WAL (`PRAGMA journal_mode=WAL`) pour la concurrence.
2. **BLAKE3** au lieu de sha256 (plus rapide) :
   ```bash
   go get lukechampine.com/blake3
   ```
   Remplace `sha256.Sum256` dans `BlobStore.Put` **et** côté navigateur (le bundle noble
   inclut blake3) — les deux doivent utiliser le même hash.

> Dans ce POC, sha256 (stdlib) + store JSON ont été choisis pour un build **sans aucune
> dépendance externe**, donc 100 % testable hors-ligne. Le swap est local et isolé.

---

## 8. Interface — gestionnaire de fichiers

La WebUI reprend les codes de Google Drive / Nextcloud : barre latérale (en **tiroir**
sur mobile), bouton **Nouveau** (importer / créer un dossier), vues **grille** et **liste**,
icônes par type, **fil d'Ariane**, recherche, glisser-déposer, renommage, **déplacement**,
suppression, et une jauge de coffre avec l'empreinte de la clé. Mise en page **responsive**.

**Dossiers sans toucher au serveur.** Le serveur ne stocke qu'un *nom chiffré opaque*. On y
encode le **chemin complet** (`Documents/factures/cv.pdf`). Le navigateur déchiffre tous les
chemins et **reconstruit l'arborescence** ; un dossier vide est matérialisé par une entrée
« marqueur » dont le chemin se termine par `/`. Conséquence : la hiérarchie est une vue
purement cliente, le serveur reste un pur magasin de blobs et **ne voit aucune structure**
(ni noms, ni dossiers).

**Renommer / déplacer = re-chiffrer un préfixe de chemin.** Le renommage change le dernier
segment ; le **déplacement** change le dossier parent — dans les deux cas on ré-encode le nom
avec le **même `id` (donc même DEK/chunks)**, sans aucune ré-écriture du contenu. Déplacer un
dossier re-pathue son marqueur **et tous ses descendants**. Le déplacement vérifie les
collisions de nom et interdit de placer un dossier dans lui-même ou un de ses sous-dossiers.

> Validé : round-trip des chemins chiffrés, reconstruction d'arbo, marqueurs de dossiers
> vides, renommage, **déplacement fichier+dossier avec intégrité du contenu** (`e2e-move.test.mjs`,
> 6/6), et **aucun chemin en clair côté serveur**.

## 9. Arborescence
```
p2pfs/
├── go.mod
├── assets.go                  # //go:embed all:web  (WebUI dans le binaire)
├── cmd/p2pfs/main.go         # point d'entrée
├── internal/server/
│   ├── server.go              # routing, handlers, CSP, rate-limit, clientIP durci, graceful shutdown
│   ├── auth.go                # Ed25519 challenge-réponse, sessions (+révocation), rate-limiter
│   ├── store.go               # Store + JSON store (flush durable/fsync) + BlobStore (flux, quota, GC)
│   ├── server_test.go         # tests Go (F2/F3/F4/F5/F9/F10 + unlock + isolation)
│   └── store_test.go          # tests durabilité (fail-closed index corrompu, nettoyage .tmp)
├── tests/                     # tests Node hors-bundle (NON embarqués/servis)
│   ├── crypto.test.mjs        # tests crypto (liaison AAD, anti reorder/troncature/splice)
│   └── unlock.test.mjs        # tests du cœur crypto de déverrouillage (PRF simulée)
├── e2e.test.mjs               # e2e (Node ↔ binaire) : flux fichiers
├── e2e-unlock.test.mjs        # e2e : déverrouillage par clé matérielle
├── e2e-move.test.mjs          # e2e : déplacement fichier/dossier
├── web/                       # WebUI (servie embarquée — plus aucun fichier de test)
│   ├── index.html             # aucun script/style inline (CSP-compatible)
│   ├── style.css
│   ├── crypto.js              # dérivation master, AES-GCM+AAD, sign, wrap/unwrap — TOUTE la crypto
│   ├── webauthn.js            # déverrouillage par clé matérielle (WebAuthn/PRF)
│   ├── app.js                 # appels API, upload/download/delete, déplacement, enrôlement/déverrouillage
│   └── vendor/crypto.bundle.js# @noble/ed25519 + @noble/hashes + @scure/bip39 (40 ko)
├── Dockerfile                 # image scratch (binaire statique)
└── deploy/
    ├── Caddyfile              # TLS auto + headers
    ├── p2pfs.service         # systemd durci (sandboxing)
    ├── harden.sh              # durcissement VPS idempotent
    ├── gcp.md                 # guide de déploiement GCP Compute Engine (firewall VPC, snapshots…)
    └── backup.sh              # sauvegarde applicative cohérente (tar + GCS optionnel)
```

## TESTS (rejouables)
```bash
go test ./...              # tests serveur (Go) : F2/F3/F4/F5/F9/F10 + durabilité + isolation
node tests/crypto.test.mjs # tests crypto (Node) : liaison AAD, attaques reorder/troncature/splice
node tests/unlock.test.mjs # tests du déverrouillage matériel (cœur crypto, PRF simulée)
# end-to-end contre le binaire :
go build -o /tmp/p2pfs ./cmd/p2pfs && DATA=$(mktemp -d) && \
  /tmp/p2pfs -addr 127.0.0.1:18080 -data "$DATA" -trusted-proxies "" & \
  sleep 1 && node e2e.test.mjs http://127.0.0.1:18080 && \
  node e2e-unlock.test.mjs http://127.0.0.1:18080 && node e2e-move.test.mjs http://127.0.0.1:18080
```
- **Crypto (Node, `crypto.test.mjs`)** : dérivation déterministe, round-trip nom/DEK/morceaux,
  et **rejet** des attaques de réordonnancement, troncature et permutation de champs (AAD) → **12/12**.
- **Déverrouillage matériel (Node, `unlock.test.mjs` + `e2e-unlock.test.mjs`)** : enveloppe/
  désenveloppe du master key, seed et clé dérivant le **même** coffre, mauvaise PRF rejetée,
  et flux complet enrôlement → verrouillage → déverrouillage par clé → lecture du fichier,
  contre le vrai binaire (PRF matérielle simulée) → **8/8 + 8/8**.
- **Serveur (Go, `server_test.go`)** : `clientIP` non falsifiable (F2), GC des blobs à la
  suppression + blob partagé conservé (F3), quota compte 413 + plafond global 507 (F4),
  round-trip blob en flux (F5), refus de blob inexistant (F10), révocation de session (F9),
  isolation cross-coffre 403 → **tous verts**.
- **End-to-end (`e2e.test.mjs`)** : flux complet login → upload multi-morceaux → download →
  déchiffrement intègre, + attaque réordonnancement rejetée bout-en-bout → **10/10**.
- Opacité serveur : `grep` des données sensibles sur le disque → **aucune fuite**.
