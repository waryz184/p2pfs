package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// SERVER — assemble store, blobs, auth, rate-limit et sert l'API + la WebUI.
// Tout tient dans un seul binaire (la WebUI est embarquée via embed.FS).
// ============================================================================

const maxBlobBytes = 64 << 20 // 64 MiB par blob (anti-DoS ; ajustable)

var (
	reHex64  = regexp.MustCompile(`^[0-9a-f]{64}$`) // sha256 / pubkey hex
	reID     = regexp.MustCompile(`^[0-9a-zA-Z_-]{1,64}$`)
	reUnlock = regexp.MustCompile(`^[0-9A-Za-z_-]{1,512}$`) // credentialId WebAuthn (b64url)
)

type Server struct {
	store           Store
	blobs           *BlobStore
	auth            *Auth
	rlAuth          *RateLimiter // strict, sur /challenge + /login
	rlAPI           *RateLimiter // large, sur le reste
	webFS           fs.FS
	trustedProxies  []*net.IPNet // proxies dont on accepte X-Forwarded-For (F2)
	maxAccountBytes int64        // quota par compte (0 = illimité) (F4)
	// gcMu sérialise « adopter un blob » (PutFile) et « ramasser un blob orphelin »
	// (Delete + BlobReferenced) pour qu'un PUT concurrent ne fasse pas supprimer un
	// blob qu'il vient de référencer (course TOCTOU du GC).
	gcMu sync.Mutex
}

// New construit le serveur. `trustedProxies` liste les réseaux (CIDR) du/des
// reverse-proxy(ies) de confiance : seul un X-Forwarded-For provenant de l'un
// d'eux est cru (F2). `maxAccountBytes` plafonne le volume par compte (F4).
func New(store Store, blobs *BlobStore, webFS fs.FS, trustedProxies []*net.IPNet, maxAccountBytes int64) *Server {
	return &Server{
		store:           store,
		blobs:           blobs,
		auth:            NewAuth(),
		rlAuth:          NewRateLimiter(0.5, 10), // ~1 tentative / 2s, burst 10
		rlAPI:           NewRateLimiter(20, 100),
		webFS:           webFS,
		trustedProxies:  trustedProxies,
		maxAccountBytes: maxAccountBytes,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// --- API ---
	mux.HandleFunc("POST /api/challenge", s.handleChallenge)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/files", s.authed(s.handleListFiles))
	mux.HandleFunc("POST /api/files", s.authed(s.handlePutFile))
	mux.HandleFunc("DELETE /api/files/{id}", s.authed(s.handleDeleteFile))
	mux.HandleFunc("PUT /api/blob/{id}", s.authed(s.handlePutBlob))
	mux.HandleFunc("GET /api/blob/{id}", s.authed(s.handleGetBlob))

	// --- déverrouillage par clé matérielle (WebAuthn/PRF) ---
	mux.HandleFunc("GET /api/unlock/{id}", s.handleGetUnlock) // non authentifié : bootstrap pré-login
	mux.HandleFunc("GET /api/unlock", s.authed(s.handleListUnlocks))
	mux.HandleFunc("PUT /api/unlock/{id}", s.authed(s.handlePutUnlock))
	mux.HandleFunc("DELETE /api/unlock/{id}", s.authed(s.handleDeleteUnlock))

	// --- WebUI statique (embarquée) ---
	mux.Handle("GET /", http.FileServer(http.FS(s.webFS)))

	return securityHeaders(s.globalLimit(mux))
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

// clientIP détermine l'IP réelle du client de façon NON falsifiable (F2).
//
// On ne fait JAMAIS confiance à X-Forwarded-For tel quel : un attaquant peut le
// forger pour obtenir un compteur de rate-limit neuf à chaque requête. On part
// donc de l'IP de la connexion TCP (RemoteAddr) ; on n'honore X-Forwarded-For
// QUE si cette connexion vient d'un proxy déclaré de confiance, et on prend
// alors l'entrée la plus à DROITE (celle ajoutée par ce proxy), pas la première
// (qui est sous contrôle du client).
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer != nil && s.isTrustedProxy(peer) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			cand := strings.TrimSpace(parts[len(parts)-1]) // ajoutée par le proxy de confiance
			if net.ParseIP(cand) != nil {
				return cand
			}
		}
	}
	return host
}

func (s *Server) isTrustedProxy(ip net.IP) bool {
	for _, n := range s.trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) globalLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if !s.rlAPI.Allow(s.clientIP(r)) {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders : CSP stricte (clé de voûte du zero-knowledge côté navigateur :
// on interdit tout script/connexion hors origine pour rendre l'exfiltration de
// la seed bien plus difficile), + HSTS, no-sniff, anti-clickjacking.
func securityHeaders(next http.Handler) http.Handler {
	csp := strings.Join([]string{
		"default-src 'none'",
		"script-src 'self'",
		"style-src 'self'",
		"img-src 'self' data:",
		"connect-src 'self'",
		"font-src 'self'",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
	}, "; ")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// authed : exige un token de session valide, injecte la pubkey dans le contexte
// via un paramètre simple (on la passe par header interne pour rester stdlib).
type authedHandler func(w http.ResponseWriter, r *http.Request, owner string)

func (s *Server) authed(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		owner, ok := s.auth.Resolve(tok)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r, owner)
	}
}

func bearer(r *http.Request) string {
	a := r.Header.Get("Authorization")
	if strings.HasPrefix(a, "Bearer ") {
		return strings.TrimPrefix(a, "Bearer ")
	}
	return ""
}

// ---------------------------------------------------------------------------
// Helpers JSON
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any, maxBytes int64) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBytes))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// limitAuth applique le rate-limit strict (challenge/login/unlock pré-login).
// Répond 429 et renvoie false si la limite est dépassée.
func (s *Server) limitAuth(w http.ResponseWriter, r *http.Request) bool {
	if !s.rlAuth.Allow(s.clientIP(r)) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return false
	}
	return true
}

// pathID lit le paramètre {id} et valide son format ; répond 400 et renvoie
// ok=false sinon. Évite de répéter le même préambule dans chaque handler.
func pathID(w http.ResponseWriter, r *http.Request, re *regexp.Regexp) (string, bool) {
	id := r.PathValue("id")
	if !re.MatchString(id) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return "", false
	}
	return id, true
}

// httpError mappe une erreur du store vers un code HTTP, sans fuiter de détail.
func httpError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, ErrForbidden):
		http.Error(w, "forbidden", http.StatusForbidden)
	default:
		http.Error(w, "server error", http.StatusInternalServerError)
	}
}

// ---------------------------------------------------------------------------
// Handlers AUTH
// ---------------------------------------------------------------------------

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if !s.limitAuth(w, r) {
		return
	}
	var req struct {
		PubKey string `json:"pubkey"`
	}
	if err := readJSON(r, &req, 4096); err != nil || !reHex64.MatchString(req.PubKey) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	nonce, err := s.auth.NewChallenge(req.PubKey)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"nonce": hex.EncodeToString(nonce)})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.limitAuth(w, r) {
		return
	}
	var req struct {
		PubKey string `json:"pubkey"`
		Nonce  string `json:"nonce"`
		Sig    string `json:"sig"`
	}
	if err := readJSON(r, &req, 8192); err != nil || !reHex64.MatchString(req.PubKey) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	nonce, err1 := hex.DecodeString(req.Nonce)
	sig, err2 := hex.DecodeString(req.Sig)
	if err1 != nil || err2 != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token, ok := s.auth.Verify(req.PubKey, nonce, sig)
	if !ok {
		http.Error(w, "auth failed", http.StatusUnauthorized)
		return
	}
	// crée le compte au premier login réussi (clé publique = identité)
	if err := s.store.UpsertAccount(req.PubKey); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_in": int(sessionTTL.Seconds()),
	})
}

// handleLogout révoque la session présentée (F9). Idempotent, ne révèle rien.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.Revoke(bearer(r))
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Handlers UNLOCK — wraps opaques (master key chiffré par une clé matérielle).
// Le serveur ne voit qu'un blob chiffré ; il ne peut pas déverrouiller le coffre.
// ---------------------------------------------------------------------------

// handleGetUnlock : NON authentifié (le client n'a pas encore d'identité — il a
// besoin du wrap pour la reconstituer). Indexé par un credentialId opaque à haute
// entropie ; ne renvoie que du ciphertext. Rate-limité comme /login.
func (s *Server) handleGetUnlock(w http.ResponseWriter, r *http.Request) {
	if !s.limitAuth(w, r) {
		return
	}
	id, ok := pathID(w, r, reUnlock)
	if !ok {
		return
	}
	rec, err := s.store.GetUnlock(id)
	if errors.Is(err, ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"wrap": rec.Wrap})
}

// handlePutUnlock : enrôle/met à jour un wrap pour le coffre authentifié (il faut
// être déverrouillé pour enrôler une nouvelle clé). Ne peut pas détourner un
// credential appartenant à un autre coffre.
func (s *Server) handlePutUnlock(w http.ResponseWriter, r *http.Request, owner string) {
	id, ok := pathID(w, r, reUnlock)
	if !ok {
		return
	}
	var req struct {
		Wrap string `json:"wrap"`
	}
	if err := readJSON(r, &req, 8192); err != nil || req.Wrap == "" || len(req.Wrap) > 4096 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.store.PutUnlock(owner, id, req.Wrap); err != nil {
		httpError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteUnlock(w http.ResponseWriter, r *http.Request, owner string) {
	id, ok := pathID(w, r, reUnlock)
	if !ok {
		return
	}
	if err := s.store.DeleteUnlock(owner, id); err != nil {
		httpError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListUnlocks(w http.ResponseWriter, r *http.Request, owner string) {
	ids, err := s.store.ListUnlocks(owner)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": ids})
}

// ---------------------------------------------------------------------------
// Handlers FICHIERS (métadonnées chiffrées)
// ---------------------------------------------------------------------------

func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request, owner string) {
	files, err := s.store.ListFiles(owner)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": files})
}

func (s *Server) handlePutFile(w http.ResponseWriter, r *http.Request, owner string) {
	var m FileMeta
	if err := readJSON(r, &m, 1<<20); err != nil { // manifeste peut être gros (bcp de chunks)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !reID.MatchString(m.ID) || m.EncName == "" || m.WrappedKey == "" || len(m.Chunks) == 0 {
		http.Error(w, "invalid metadata", http.StatusBadRequest)
		return
	}
	// Section critique GC : la vérif de présence des blobs + l'écriture de la
	// métadonnée (l'« adoption ») doivent être atomiques vis-à-vis du ramassage,
	// sinon un Delete concurrent pourrait supprimer un blob entre le Has() et le
	// PutFile. Sérialisé avec handleDeleteFile via gcMu.
	s.gcMu.Lock()
	defer s.gcMu.Unlock()

	var declared int64
	for _, c := range m.Chunks {
		if !reHex64.MatchString(c.BlobID) || c.IV == "" {
			http.Error(w, "invalid chunk", http.StatusBadRequest)
			return
		}
		// F10 : on n'accepte une référence que vers un blob réellement présent
		// (uploadé au préalable). Empêche les métadonnées « fantômes » et le fait
		// de réclamer un blob qu'on n'a jamais déposé.
		if !s.blobs.Has(c.BlobID) {
			http.Error(w, "unknown blob", http.StatusBadRequest)
			return
		}
		declared += c.Size
	}
	m.Owner = owner
	m.Size = declared // taille de confiance = somme des morceaux, pas un champ client libre

	// F4 : quota par compte. On exclut l'id courant (cas renommage/réécriture).
	if s.maxAccountBytes > 0 {
		used, err := s.store.AccountUsage(owner, m.ID)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		if used+m.Size > s.maxAccountBytes {
			http.Error(w, "quota exceeded", http.StatusRequestEntityTooLarge)
			return
		}
	}

	m.CreatedAt = time.Time{} // le store fixe/conserve la date
	if err := s.store.PutFile(m); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": m.ID})
}

func (s *Server) handleDeleteFile(w http.ResponseWriter, r *http.Request, owner string) {
	id, ok := pathID(w, r, reID)
	if !ok {
		return
	}
	// Section critique GC (voir handlePutFile) : suppression de la métadonnée puis
	// ramassage des blobs orphelins, atomiques vis-à-vis de l'adoption concurrente.
	s.gcMu.Lock()
	defer s.gcMu.Unlock()

	meta, err := s.store.DeleteFile(owner, id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// F3 : suppression RÉELLE. Après avoir retiré la métadonnée, on efface du
	// disque chaque blob qui n'est plus référencé par AUCUN fichier (dédup
	// globale → on vérifie tous propriétaires confondus avant de supprimer).
	for _, c := range meta.Chunks {
		if ref, rerr := s.store.BlobReferenced(c.BlobID); rerr == nil && !ref {
			_ = s.blobs.Delete(c.BlobID)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Handlers BLOBS (ciphertext opaque)
// ---------------------------------------------------------------------------

func (s *Server) handlePutBlob(w http.ResponseWriter, r *http.Request, owner string) {
	id, ok := pathID(w, r, reHex64)
	if !ok {
		return
	}
	// F5 : Put consomme le corps EN FLUX (jamais 64 MiB en RAM), revérifie
	// sha256(contenu)==id et applique le plafond global de stockage.
	_, err := s.blobs.Put(id, r.Body, maxBlobBytes)
	switch {
	case errors.Is(err, ErrTooLarge):
		http.Error(w, "blob too large", http.StatusRequestEntityTooLarge)
		return
	case errors.Is(err, ErrStorageFull):
		http.Error(w, "storage full", http.StatusInsufficientStorage)
		return
	case err != nil:
		http.Error(w, "blob rejected", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"blob_id": id})
}

func (s *Server) handleGetBlob(w http.ResponseWriter, r *http.Request, owner string) {
	id, ok := pathID(w, r, reHex64)
	if !ok {
		return
	}
	// Contrôle d'accès : le blob doit être référencé par un fichier de l'owner.
	owned, err := s.store.BlobOwned(owner, id)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if !owned {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// F5 : on sert le fichier EN FLUX (io.Copy depuis le disque).
	f, size, err := s.blobs.Open(id)
	if errors.Is(err, ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	_, _ = io.Copy(w, f)
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

// ListenAndServe démarre le serveur et s'arrête PROPREMENT quand `ctx` est annulé
// (SIGTERM/SIGINT envoyés par systemd à chaque restart, ou par GCE lors d'un
// arrêt/maintenance/live-migration) : on cesse d'accepter de nouvelles requêtes
// et on laisse les uploads/downloads en cours se terminer (drain) avant de rendre.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // gros uploads
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 16,
	}

	errc := make(chan error, 1)
	go func() {
		log.Printf("p2pfs écoute sur %s", addr)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err // échec de démarrage / erreur fatale
	case <-ctx.Done():
		log.Printf("arrêt demandé : drain des requêtes en cours…")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("arrêt forcé : %v", err)
			return err
		}
		log.Printf("arrêt propre terminé")
		return nil
	}
}
