package server

import (
	"os"
	"path/filepath"
	"testing"
)

// Durabilité — l'index corrompu doit FAIRE ÉCHOUER le démarrage (fail-closed),
// jamais démarrer en coffre vide puis écraser la seule copie des données.
func TestJSONStore_FailClosedOnCorruptIndex(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte("{ ceci n'est pas du json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewJSONStore(dir); err == nil {
		t.Fatal("NewJSONStore a démarré malgré un index corrompu (risque d'écrasement des données)")
	}
}

func TestJSONStore_LoadsValidIndex(t *testing.T) {
	dir := t.TempDir()
	s, err := NewJSONStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAccount("a1b2"); err != nil { // déclenche un flush durable
		t.Fatal(err)
	}
	// rechargement : l'index doit reparser et retrouver le compte.
	s2, err := NewJSONStore(dir)
	if err != nil {
		t.Fatalf("rechargement d'un index valide a échoué : %v", err)
	}
	ok, _ := s2.AccountExists("a1b2")
	if !ok {
		t.Error("compte perdu au rechargement")
	}
}

// Au boot, un fichier temporaire d'upload interrompu (« <blob>.tmp.<alea> ») doit
// être supprimé et NE PAS être compté dans le total (sinon il fausse le quota).
func TestBlobStore_CleansStaleTmpAtBoot(t *testing.T) {
	dir := t.TempDir()
	blobsDir := filepath.Join(dir, "blobs", "ab", "cd")
	if err := os.MkdirAll(blobsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realBlob := filepath.Join(blobsDir, "abcd0000")
	staleTmp := filepath.Join(blobsDir, "abcd1111.tmp.deadbeef")
	if err := os.WriteFile(realBlob, make([]byte, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staleTmp, make([]byte, 500), 0o600); err != nil {
		t.Fatal(err)
	}

	bs, err := NewBlobStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staleTmp); !os.IsNotExist(err) {
		t.Error("le fichier .tmp orphelin n'a pas été nettoyé au boot")
	}
	if got := bs.Total(); got != 100 {
		t.Errorf("Total = %d (attendu 100 : le .tmp ne doit pas être compté)", got)
	}
}
