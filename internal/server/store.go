package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// STORE — couche de persistance, zero-knowledge.
//
// Le serveur ne voit JAMAIS : la seed, les clés, les noms de fichiers en clair,
// le contenu en clair. Il ne stocke que :
//   - Account : la clé PUBLIQUE Ed25519 du client (= identité du coffre)
//   - FileMeta : des champs déjà chiffrés côté navigateur (nom, DEK enveloppée)
//   - Blobs    : des octets opaques (ciphertext AES-GCM), adressés par hash
//
// Implémentation POC : JSON sur disque + mutex. Suffisant, testable, zéro
// dépendance externe. Pour la prod, remplacer par SQLite (modernc.org/sqlite,
// pur Go) en réimplémentant l'interface Store — voir README §"Passage en prod".
// ============================================================================

var (
	ErrNotFound    = errors.New("not found")
	ErrForbidden   = errors.New("forbidden")
	ErrTooLarge    = errors.New("blob too large")
	ErrStorageFull = errors.New("storage full")
)

// Account : un coffre, identifié par la clé publique du client (hex).
type Account struct {
	PubKey    string    `json:"pubkey"` // Ed25519 public key, hex (64 chars)
	CreatedAt time.Time `json:"created_at"`
}

// UnlockRecord : un moyen de déverrouillage par clé matérielle (WebAuthn/PRF).
// Le serveur ne stocke QUE le master key enveloppé (opaque) + le propriétaire.
// Indexé par l'identifiant de credential (b64url), opaque et à haute entropie.
type UnlockRecord struct {
	Owner     string    `json:"owner"` // pubkey du coffre auquel ce wrap appartient
	Wrap      string    `json:"wrap"`  // master key chiffré (base64), illisible côté serveur
	CreatedAt time.Time `json:"created_at"`
}

// Chunk : un morceau chiffré du fichier. BlobID = sha256 du ciphertext du chunk,
// IV = nonce AES-GCM de ce chunk (base64). Le manifeste (liste ordonnée) suffit
// à reconstruire le fichier ; il ne révèle rien (un blobId est un hash de
// ciphertext, indistinguable d'aléa).
type Chunk struct {
	BlobID string `json:"blob_id"`
	IV     string `json:"iv"`
	Size   int64  `json:"size"`
}

// FileMeta : métadonnées d'un fichier. Champs sensibles (nom, DEK) chiffrés côté
// navigateur. Le contenu est éclaté en `Chunks` (un seul pour les petits fichiers).
type FileMeta struct {
	ID         string     `json:"id"`          // id logique (random, généré client)
	Owner      string     `json:"owner"`       // pubkey du propriétaire
	EncName    string     `json:"enc_name"`    // nom/chemin CHIFFRÉ (base64)
	WrappedKey string     `json:"wrapped_key"` // DEK du fichier, enveloppée par la KEK (base64)
	Size       int64      `json:"size"`        // taille totale du ciphertext (octets)
	Chunks     []Chunk    `json:"chunks"`      // manifeste ordonné des morceaux
	CreatedAt  time.Time  `json:"created_at"`
	// DeletedAt : non-nil = dans la corbeille (soft delete). La métadonnée et
	// ses blobs restent intacts (récupérables via RestoreFile) ; seul Purge
	// (DeleteFile, endpoint existant) supprime réellement et ramasse les blobs.
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// Store : l'interface que la prod réimplémentera avec SQLite.
type Store interface {
	UpsertAccount(pubkey string) error
	AccountExists(pubkey string) (bool, error)

	PutFile(m FileMeta) error
	ListFiles(owner string) ([]FileMeta, error)
	GetFile(owner, id string) (FileMeta, error)
	// DeleteFile supprime RÉELLEMENT (purge) : métadonnée retirée, blobs orphelins
	// ramassés par l'appelant. Utilisé par la suppression définitive (corbeille).
	DeleteFile(owner, id string) (FileMeta, error)
	// TrashFile / RestoreFile : suppression réversible (corbeille). Ne touchent
	// jamais aux blobs — seule DeleteFile (purge) ramasse.
	TrashFile(owner, id string) error
	RestoreFile(owner, id string) error
	// FileByEncName vérifie les collisions de noms chiffrés (anti-TOCTOU)
	FileByEncName(owner, encName string) (FileMeta, error)

	// BlobOwned : un blob n'est lisible que s'il est référencé par un fichier
	// appartenant à `owner`. Empêche l'énumération des blobs d'autrui.
	BlobOwned(owner, blobID string) (bool, error)

	// BlobReferenced : un blob est-il encore référencé par UN fichier, tous
	// propriétaires confondus ? Sert au ramasse-miettes (F3) : on ne supprime
	// du disque que les blobs que plus personne n'utilise (dédup globale).
	BlobReferenced(blobID string) (bool, error)

	// AccountUsage : somme des tailles des fichiers d'un compte, en excluant un
	// id donné (le fichier en cours de réécriture/renommage). Sert au quota (F4).
	AccountUsage(owner, excludeID string) (int64, error)

	// --- déverrouillage par clé matérielle (WebAuthn/PRF) ---
	// PutUnlock enregistre (ou met à jour) un wrap pour `owner`. Refuse d'écraser
	// un enregistrement appartenant à un AUTRE propriétaire (ErrForbidden).
	PutUnlock(owner, recordID, wrap string) error
	GetUnlock(recordID string) (UnlockRecord, error)
	DeleteUnlock(owner, recordID string) error
	ListUnlocks(owner string) ([]string, error)
}

// ---------------------------------------------------------------------------
// Implémentation JSON (POC)
// ---------------------------------------------------------------------------

type jsonStore struct {
	mu       sync.RWMutex
	path     string
	Accounts map[string]Account             `json:"accounts"`
	Files    map[string]map[string]FileMeta `json:"files"`   // owner -> id -> meta
	Unlocks  map[string]UnlockRecord        `json:"unlocks"` // recordID(b64url) -> wrap opaque
}

func NewJSONStore(dataDir string) (Store, error) {
	p := filepath.Join(dataDir, "index.json")
	s := &jsonStore{
		path:     p,
		Accounts: map[string]Account{},
		Files:    map[string]map[string]FileMeta{},
		Unlocks:  map[string]UnlockRecord{},
	}
	// FAIL-CLOSED : si l'index existe mais ne parse pas, on REFUSE de démarrer.
	// Démarrer en ignorant l'erreur reviendrait à repartir d'un coffre vide, puis
	// la première écriture écraserait la seule copie des données (perte silencieuse).
	if b, err := os.ReadFile(p); err == nil {
		if err := json.Unmarshal(b, s); err != nil {
			return nil, fmt.Errorf("index.json illisible (corrompu ?) : %w — refus de démarrer pour ne pas écraser des données", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("lecture index.json : %w", err)
	}
	if s.Accounts == nil {
		s.Accounts = map[string]Account{}
	}
	if s.Files == nil {
		s.Files = map[string]map[string]FileMeta{}
	}
	if s.Unlocks == nil {
		s.Unlocks = map[string]UnlockRecord{}
	}
	return s, nil
}

// flush écrit l'index de façon atomique ET DURABLE (write-temp + fsync + rename
// + fsync du répertoire). Sans le fsync, le rename est atomique pour les lecteurs
// mais PAS durable : un crash / une live-migration GCE peut perdre la dernière
// transaction (le noyau n'avait pas encore écrit sur le disque).
func (s *jsonStore) flush() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil { // le contenu atteint réellement le disque
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(s.path)) // le rename lui-même devient durable
}

func (s *jsonStore) UpsertAccount(pubkey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Accounts[pubkey]; !ok {
		s.Accounts[pubkey] = Account{PubKey: pubkey, CreatedAt: time.Now().UTC()}
		return s.flush()
	}
	return nil
}

func (s *jsonStore) AccountExists(pubkey string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.Accounts[pubkey]
	return ok, nil
}

func (s *jsonStore) PutFile(m FileMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Files[m.Owner] == nil {
		s.Files[m.Owner] = map[string]FileMeta{}
	}
	// si l'entrée existe déjà (ex. renommage), on conserve sa date de création
	// ET son état de corbeille (seuls TrashFile/RestoreFile le modifient).
	if old, ok := s.Files[m.Owner][m.ID]; ok {
		if !old.CreatedAt.IsZero() {
			m.CreatedAt = old.CreatedAt
		}
		m.DeletedAt = old.DeletedAt
	} else if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Now().UTC()
	}
	s.Files[m.Owner][m.ID] = m
	return s.flush()
}

// TrashFile marque un fichier comme supprimé (soft delete) : métadonnée et
// blobs restent intacts, récupérables via RestoreFile.
func (s *jsonStore) TrashFile(owner, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.Files[owner][id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now().UTC()
	m.DeletedAt = &now
	s.Files[owner][id] = m
	return s.flush()
}

// RestoreFile annule une mise à la corbeille.
func (s *jsonStore) RestoreFile(owner, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.Files[owner][id]
	if !ok {
		return ErrNotFound
	}
	m.DeletedAt = nil
	s.Files[owner][id] = m
	return s.flush()
}

// FileByEncName vérifie s'il existe déjà un fichier avec ce nom chiffré pour un owner donné.
// Renvoie le fichier existant si trouvé, ErrNotFound sinon.
func (s *jsonStore) FileByEncName(owner, encName string) (FileMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.Files[owner] {
		if m.EncName == encName {
			return m, nil
		}
	}
	return FileMeta{}, ErrNotFound
}

func (s *jsonStore) ListFiles(owner string) ([]FileMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []FileMeta{}
	for _, m := range s.Files[owner] {
		out = append(out, m)
	}
	return out, nil
}

func (s *jsonStore) GetFile(owner, id string) (FileMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.Files[owner][id]
	if !ok {
		return FileMeta{}, ErrNotFound
	}
	return m, nil
}

func (s *jsonStore) DeleteFile(owner, id string) (FileMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.Files[owner][id]
	if !ok {
		return FileMeta{}, ErrNotFound
	}
	delete(s.Files[owner], id)
	return m, s.flush()
}

func (s *jsonStore) BlobOwned(owner, blobID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, m := range s.Files[owner] {
		for _, c := range m.Chunks {
			if c.BlobID == blobID {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s *jsonStore) BlobReferenced(blobID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, files := range s.Files {
		for _, m := range files {
			for _, c := range m.Chunks {
				if c.BlobID == blobID {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func (s *jsonStore) AccountUsage(owner, excludeID string) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var total int64
	for id, m := range s.Files[owner] {
		if id == excludeID {
			continue
		}
		total += m.Size
	}
	return total, nil
}

func (s *jsonStore) PutUnlock(owner, recordID, wrap string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.Unlocks[recordID]; ok && old.Owner != owner {
		return ErrForbidden // un credential ne peut pas être détourné d'un autre coffre
	}
	s.Unlocks[recordID] = UnlockRecord{Owner: owner, Wrap: wrap, CreatedAt: time.Now().UTC()}
	return s.flush()
}

func (s *jsonStore) GetUnlock(recordID string) (UnlockRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.Unlocks[recordID]
	if !ok {
		return UnlockRecord{}, ErrNotFound
	}
	return rec, nil
}

func (s *jsonStore) DeleteUnlock(owner, recordID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.Unlocks[recordID]
	if !ok {
		return ErrNotFound
	}
	if rec.Owner != owner {
		return ErrForbidden
	}
	delete(s.Unlocks, recordID)
	return s.flush()
}

func (s *jsonStore) ListUnlocks(owner string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []string{}
	for id, rec := range s.Unlocks {
		if rec.Owner == owner {
			out = append(out, id)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// BLOB STORE — ciphertext sur disque, adressé par contenu (sha256).
// Chemin shardé /blobs/ab/cd/abcd... pour éviter trop de fichiers par dossier.
// ---------------------------------------------------------------------------

type BlobStore struct {
	dir      string
	mu       sync.Mutex // protège curTotal
	curTotal int64      // octets actuellement sur disque
	maxTotal int64      // plafond global (0 = illimité) — anti remplissage disque (F4)
}

// NewBlobStore initialise le magasin et calcule la taille déjà occupée (pour
// faire respecter le plafond global dès le démarrage).
func NewBlobStore(dataDir string, maxTotal int64) (*BlobStore, error) {
	d := filepath.Join(dataDir, "blobs")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, err
	}
	b := &BlobStore{dir: d, maxTotal: maxTotal}
	_ = filepath.Walk(d, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		// Nettoyage : un upload interrompu (crash / SIGKILL) laisse un fichier
		// temporaire « <blob>.tmp.<alea> ». On le supprime au boot au lieu de le
		// compter, sinon il fausse le quota et s'accumule indéfiniment.
		if strings.Contains(info.Name(), ".tmp.") {
			_ = os.Remove(p)
			return nil
		}
		b.curTotal += info.Size()
		return nil
	})
	return b, nil
}

func (b *BlobStore) pathFor(id string) string {
	return filepath.Join(b.dir, id[0:2], id[2:4], id)
}

// Has indique si un blob est déjà présent sur disque (référence valide).
func (b *BlobStore) Has(id string) bool {
	_, err := os.Stat(b.pathFor(id))
	return err == nil
}

// Total renvoie le nombre d'octets actuellement stockés (pour les métriques/tests).
func (b *BlobStore) Total() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.curTotal
}

// Put lit le ciphertext EN FLUX (F5 : jamais plus d'un buffer en RAM), vérifie en
// continu que sha256(contenu)==id (anti-corruption / anti-empoisonnement), applique
// la limite par blob et le plafond global (F4), puis écrit atomiquement.
// Renvoie le nombre d'octets effectivement ajoutés (0 si déjà présent = dédup).
func (b *BlobStore) Put(id string, r io.Reader, maxBytes int64) (int64, error) {
	p := b.pathFor(id)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return 0, err
	}
	if b.Has(id) {
		return 0, nil // déduplication : déjà présent, rien à ajouter
	}

	tmp := p + ".tmp." + randSuffix()
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	h := sha256.New()
	// LimitReader à maxBytes+1 pour détecter le dépassement sans tout charger.
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, maxBytes+1))
	cerr := f.Close()
	if err != nil || cerr != nil {
		os.Remove(tmp)
		if err != nil {
			return 0, err
		}
		return 0, cerr
	}
	if n > maxBytes {
		os.Remove(tmp)
		return 0, ErrTooLarge
	}
	if hex.EncodeToString(h.Sum(nil)) != id {
		os.Remove(tmp)
		return 0, errors.New("blob id does not match content hash")
	}

	// Réservation du quota global sous verrou (et re-vérif d'absence pour éviter
	// le double-comptage si deux Put concurrents portaient le même id neuf).
	b.mu.Lock()
	if b.Has(id) {
		b.mu.Unlock()
		os.Remove(tmp)
		return 0, nil
	}
	if b.maxTotal > 0 && b.curTotal+n > b.maxTotal {
		b.mu.Unlock()
		os.Remove(tmp)
		return 0, ErrStorageFull
	}
	if err := os.Rename(tmp, p); err != nil {
		b.mu.Unlock()
		os.Remove(tmp)
		return 0, err
	}
	b.curTotal += n
	b.mu.Unlock()
	return n, nil
}

// Delete retire un blob du disque et décompte sa taille (F3 : suppression réelle).
func (b *BlobStore) Delete(id string) error {
	p := b.pathFor(id)
	info, err := os.Stat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.Remove(p); err != nil {
		return err
	}
	b.mu.Lock()
	b.curTotal -= info.Size()
	if b.curTotal < 0 {
		b.curTotal = 0
	}
	b.mu.Unlock()
	return nil
}

// Open ouvre un blob pour le servir EN FLUX (F5 : pas de lecture intégrale en RAM).
func (b *BlobStore) Open(id string) (*os.File, int64, error) {
	f, err := os.Open(b.pathFor(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, info.Size(), nil
}

// randSuffix : suffixe aléatoire pour les fichiers temporaires (évite les
// collisions entre Put concurrents du même blob).
func randSuffix() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
