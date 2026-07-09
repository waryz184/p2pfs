# =============================================================================
# Dockerfile — image minimale FROM scratch (binaire statique + WebUI embarquée).
# Surface d'attaque quasi nulle : pas de shell, pas de libc, pas de package.
#
#   docker build -t p2pfs:latest .
#   docker run -p 127.0.0.1:8000:8000 -v p2pfsdata:/data p2pfs:latest
#
# Note : derrière Caddy, publier sur 127.0.0.1 uniquement (-p 127.0.0.1:8000:8000)
# et laisser Caddy (sur l'hôte) gérer le TLS et l'exposition publique.
# =============================================================================

# ---- build ----
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags "-s -w" -o /p2pfs ./cmd/p2pfs
# /data pré-créé et possédé par l'UID non-root ci-dessous : "scratch" n'a pas
# de mkdir/chown, et un volume monté sur un chemin absent de l'image serait
# initialisé root:root par Docker, illisible pour USER 10001:10001.
RUN mkdir -p /data && chown 10001:10001 /data

# ---- runtime ----
FROM scratch
COPY --from=build /p2pfs /p2pfs
COPY --from=build --chown=10001:10001 /data /data
# p2pfs écoute en clair sur 8000 ; data dans /data (volume).
ENV P2PFS_DATA=/data
EXPOSE 8000
USER 10001:10001
# IMPORTANT (F2) : par défaut, p2pfs ne fait confiance qu'à la loopback pour le
# X-Forwarded-For (fail-closed). Derrière Caddy en conteneur, le proxy se connecte
# via la passerelle du bridge Docker (ex. 172.17.0.1) : il faut alors déclarer
# EXPLICITEMENT le sous-réseau du proxy (le plus étroit possible), ex. :
#   docker run ... -e ou en surchargeant la commande :
#   /p2pfs -addr 0.0.0.0:8000 -data /data -trusted-proxies "172.17.0.1/32"
# Ne JAMAIS coder en dur une plage large (172.16.0.0/12) ni publier sans loopback :
#   docker run -p 127.0.0.1:8000:8000 ...
ENTRYPOINT ["/p2pfs", "-addr", "0.0.0.0:8000", "-data", "/data"]
