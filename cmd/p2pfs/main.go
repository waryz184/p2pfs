// Command p2pfs démarre le serveur de stockage chiffré zero-knowledge.
package main

import (
	"context"
	"flag"
	"io/fs"
	"log"
	"net"
	"os/signal"
	"strings"
	"syscall"

	p2pfs "p2pfs"
	"p2pfs/internal/server"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8000", "adresse d'écoute (host:port)")
	data := flag.String("data", "./p2pfsdata", "répertoire de données (index + blobs)")
	trustedProxiesFlag := flag.String("trusted-proxies", "127.0.0.0/8,::1/128",
		"CIDR séparés par des virgules autorisés à poser X-Forwarded-For (F2)")
	maxAccountBytes := flag.Int64("max-account-bytes", 5<<30, "quota par compte en octets (0 = illimité)")
	maxTotalBytes := flag.Int64("max-total-bytes", 50<<30, "plafond global de stockage en octets (0 = illimité)")
	flag.Parse()

	trustedProxies, err := parseCIDRs(*trustedProxiesFlag)
	if err != nil {
		log.Fatalf("-trusted-proxies invalide : %v", err)
	}

	store, err := server.NewJSONStore(*data)
	if err != nil {
		log.Fatalf("ouverture du store : %v", err)
	}
	blobs, err := server.NewBlobStore(*data, *maxTotalBytes)
	if err != nil {
		log.Fatalf("ouverture du blob store : %v", err)
	}

	webFS, err := fs.Sub(p2pfs.WebFS, "web")
	if err != nil {
		log.Fatalf("chargement de la WebUI embarquée : %v", err)
	}

	srv := server.New(store, blobs, webFS, trustedProxies, *maxAccountBytes)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.ListenAndServe(ctx, *addr); err != nil {
		log.Fatalf("serveur arrêté en erreur : %v", err)
	}
}

// parseCIDRs découpe une liste de CIDR séparés par des virgules. Une entrée
// vide (flag "") produit une liste vide (aucun proxy de confiance).
func parseCIDRs(csv string) ([]*net.IPNet, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil, nil
	}
	var nets []*net.IPNet
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, err
		}
		nets = append(nets, n)
	}
	return nets, nil
}
