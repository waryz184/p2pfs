package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestServer(t *testing.T, maxAccount, maxTotal int64) (*httptest.Server, *Server) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewJSONStore(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	blobs, err := NewBlobStore(dir, maxTotal)
	if err != nil {
		t.Fatalf("blobs: %v", err)
	}
	_, loop, _ := net.ParseCIDR("127.0.0.0/8")
	s := New(store, blobs, fstest.MapFS{}, []*net.IPNet{loop}, maxAccount)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, s
}

func postJSON(t *testing.T, ts *httptest.Server, path string, body any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := ts.Client().Post(ts.URL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s -> %d", path, resp.StatusCode)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func loginTest(t *testing.T, ts *httptest.Server) (token, pubHex string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubHex = hex.EncodeToString(pub)
	ch := postJSON(t, ts, "/api/challenge", map[string]string{"pubkey": pubHex})
	nonceHex, _ := ch["nonce"].(string)
	nonce, _ := hex.DecodeString(nonceHex)
	msg := append([]byte("p2pfs-auth-v1:"), nonce...)
	sig := ed25519.Sign(priv, msg)
	res := postJSON(t, ts, "/api/login", map[string]string{
		"pubkey": pubHex, "nonce": nonceHex, "sig": hex.EncodeToString(sig),
	})
	token, _ = res["token"].(string)
	if token == "" {
		t.Fatal("login: token vide")
	}
	return
}

func authReq(t *testing.T, ts *httptest.Server, method, path, token string, body []byte, ctype string) *http.Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, ts.URL+path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// putBlobResp dépose un blob et renvoie (id, statusHTTP).
func putBlobResp(t *testing.T, ts *httptest.Server, token string, data []byte) (string, int) {
	t.Helper()
	sum := sha256.Sum256(data)
	id := hex.EncodeToString(sum[:])
	resp := authReq(t, ts, "PUT", "/api/blob/"+id, token, data, "application/octet-stream")
	resp.Body.Close()
	return id, resp.StatusCode
}

// putFileResp dépose une métadonnée de fichier (un seul chunk) et renvoie le statut.
func putFileResp(t *testing.T, ts *httptest.Server, token, id, blobID string, size int64) int {
	t.Helper()
	// enc_name dérivé de id : unique par fichier logique (sinon la vérification
	// anti-collision de handlePutFile rejette le 2e appel avec un même nom).
	encName := base64.StdEncoding.EncodeToString([]byte("enc-name-" + id))
	body, _ := json.Marshal(map[string]any{
		"id":          id,
		"enc_name":    encName,
		"wrapped_key": "d3JhcHBlZC1rZXk=",
		"size":        size,
		"chunks":      []map[string]any{{"blob_id": blobID, "iv": "aXYxMjM0NTY3OA==", "size": size}},
	})
	resp := authReq(t, ts, "POST", "/api/files", token, body, "application/json")
	resp.Body.Close()
	return resp.StatusCode
}

// ---------------------------------------------------------------------------
// F2 — clientIP non falsifiable
// ---------------------------------------------------------------------------

func TestClientIP_XForwardedForTrust(t *testing.T) {
	_, loop, _ := net.ParseCIDR("127.0.0.0/8")
	s := &Server{trustedProxies: []*net.IPNet{loop}}

	cases := []struct {
		name, remote, xff, want string
	}{
		{"proxy de confiance honore XFF", "127.0.0.1:5000", "9.9.9.9", "9.9.9.9"},
		{"attaquant direct : XFF forgé IGNORÉ", "8.8.8.8:5000", "1.1.1.1", "8.8.8.8"},
		{"chaîne multi-hop : on prend la plus à droite", "127.0.0.1:5000", "1.1.1.1, 2.2.2.2", "2.2.2.2"},
		{"sans XFF : IP de connexion", "5.5.5.5:5000", "", "5.5.5.5"},
		{"proxy de confiance + XFF non-IP : repli sur la connexion", "127.0.0.1:5000", "garbage", "127.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: c.remote, Header: http.Header{}}
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if got := s.clientIP(r); got != c.want {
				t.Errorf("clientIP = %q, attendu %q", got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F3 — suppression réelle des blobs (GC)
// ---------------------------------------------------------------------------

func TestBlobGC_OnDelete(t *testing.T) {
	ts, s := newTestServer(t, 0, 0)
	token, _ := loginTest(t, ts)

	data := []byte("contenu chiffré du fichier 1")
	id, code := putBlobResp(t, ts, token, data)
	if code != http.StatusOK {
		t.Fatalf("putBlob -> %d", code)
	}
	if c := putFileResp(t, ts, token, "file1", id, int64(len(data))); c != http.StatusOK {
		t.Fatalf("putFile -> %d", c)
	}
	if !s.blobs.Has(id) {
		t.Fatal("blob absent après upload")
	}

	resp := authReq(t, ts, "DELETE", "/api/files/file1", token, nil, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE -> %d", resp.StatusCode)
	}
	if s.blobs.Has(id) {
		t.Error("F3 : le blob existe encore après suppression du fichier (pas de GC)")
	}
}

func TestBlobGC_SharedBlobRetained(t *testing.T) {
	ts, s := newTestServer(t, 0, 0)
	token, _ := loginTest(t, ts)

	data := []byte("blob partagé par deux fichiers")
	id, _ := putBlobResp(t, ts, token, data)
	putFileResp(t, ts, token, "fileA", id, int64(len(data)))
	putFileResp(t, ts, token, "fileB", id, int64(len(data)))

	// Supprimer A ne doit PAS effacer le blob (encore référencé par B).
	authReq(t, ts, "DELETE", "/api/files/fileA", token, nil, "").Body.Close()
	if !s.blobs.Has(id) {
		t.Error("blob partagé supprimé à tort alors que B le référence encore")
	}
	// Supprimer B libère le blob.
	authReq(t, ts, "DELETE", "/api/files/fileB", token, nil, "").Body.Close()
	if s.blobs.Has(id) {
		t.Error("blob non libéré après suppression du dernier référent")
	}
}

// ---------------------------------------------------------------------------
// F4 — quotas
// ---------------------------------------------------------------------------

func TestAccountQuota(t *testing.T) {
	ts, _ := newTestServer(t, 100, 0) // quota compte = 100 o, stockage global illimité
	token, _ := loginTest(t, ts)

	data := make([]byte, 200)
	rand.Read(data)
	id, code := putBlobResp(t, ts, token, data)
	if code != http.StatusOK {
		t.Fatalf("putBlob -> %d", code)
	}
	if c := putFileResp(t, ts, token, "big", id, 200); c != http.StatusRequestEntityTooLarge {
		t.Errorf("F4 : quota compte non appliqué, statut = %d (attendu 413)", c)
	}
}

func TestGlobalStorageCap(t *testing.T) {
	ts, _ := newTestServer(t, 0, 100) // plafond global = 100 o
	token, _ := loginTest(t, ts)

	data := make([]byte, 200)
	rand.Read(data)
	_, code := putBlobResp(t, ts, token, data)
	if code != http.StatusInsufficientStorage {
		t.Errorf("F4 : plafond global non appliqué, statut = %d (attendu 507)", code)
	}
}

// ---------------------------------------------------------------------------
// F10 — référence vers un blob inexistant rejetée
// ---------------------------------------------------------------------------

func TestUnknownBlobRejected(t *testing.T) {
	ts, _ := newTestServer(t, 0, 0)
	token, _ := loginTest(t, ts)

	fakeBlob := hex.EncodeToString(sha256.New().Sum(nil)) // hash valide mais jamais uploadé
	if c := putFileResp(t, ts, token, "ghost", fakeBlob, 10); c != http.StatusBadRequest {
		t.Errorf("F10 : référence vers blob inexistant acceptée, statut = %d (attendu 400)", c)
	}
}

// ---------------------------------------------------------------------------
// F5 — round-trip blob en flux (le contenu servi est intact)
// ---------------------------------------------------------------------------

func TestBlobRoundTrip(t *testing.T) {
	ts, _ := newTestServer(t, 0, 0)
	token, _ := loginTest(t, ts)

	data := make([]byte, 1<<20) // 1 MiB
	rand.Read(data)
	id, code := putBlobResp(t, ts, token, data)
	if code != http.StatusOK {
		t.Fatalf("putBlob -> %d", code)
	}
	putFileResp(t, ts, token, "rt", id, int64(len(data)))

	resp := authReq(t, ts, "GET", "/api/blob/"+id, token, nil, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET blob -> %d", resp.StatusCode)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, data) {
		t.Errorf("F5 : contenu servi != contenu déposé (%d vs %d octets)", len(got), len(data))
	}
}

// ---------------------------------------------------------------------------
// F9 — révocation de session au logout
// ---------------------------------------------------------------------------

func TestLogoutRevokesSession(t *testing.T) {
	ts, _ := newTestServer(t, 0, 0)
	token, _ := loginTest(t, ts)

	// Le token marche avant le logout.
	r1 := authReq(t, ts, "GET", "/api/files", token, nil, "")
	r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/files avant logout -> %d", r1.StatusCode)
	}
	// Logout.
	r2 := authReq(t, ts, "POST", "/api/logout", token, nil, "")
	r2.Body.Close()
	if r2.StatusCode != http.StatusNoContent {
		t.Fatalf("logout -> %d", r2.StatusCode)
	}
	// Le token est invalide après le logout (F9).
	r3 := authReq(t, ts, "GET", "/api/files", token, nil, "")
	r3.Body.Close()
	if r3.StatusCode != http.StatusUnauthorized {
		t.Errorf("F9 : session toujours valide après logout, statut = %d (attendu 401)", r3.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Déverrouillage par clé matérielle : endpoints /api/unlock (wraps opaques)
// ---------------------------------------------------------------------------

func TestUnlockEndpoints(t *testing.T) {
	ts, _ := newTestServer(t, 0, 0)
	tokenA, _ := loginTest(t, ts)
	cid := "Y3JlZGVudGlhbC1pZC1leGFtcGxl"  // credentialId b64url factice
	wrap := "bWFzdGVyLWtleS1lbnZlbG9wcGU=" // wrap opaque (base64)

	// Enrôlement (authentifié).
	r := authReq(t, ts, "PUT", "/api/unlock/"+cid, tokenA,
		[]byte(`{"wrap":"`+wrap+`"}`), "application/json")
	r.Body.Close()
	if r.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT unlock -> %d", r.StatusCode)
	}

	// Récupération NON authentifiée (bootstrap pré-login) : renvoie le wrap opaque.
	r2 := authReq(t, ts, "GET", "/api/unlock/"+cid, "", nil, "")
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("GET unlock (unauth) -> %d", r2.StatusCode)
	}
	var got map[string]string
	json.NewDecoder(r2.Body).Decode(&got)
	if got["wrap"] != wrap {
		t.Errorf("wrap renvoyé = %q, attendu %q", got["wrap"], wrap)
	}

	// Listing (authentifié) : contient le credential.
	r3 := authReq(t, ts, "GET", "/api/unlock", tokenA, nil, "")
	defer r3.Body.Close()
	var list map[string][]string
	json.NewDecoder(r3.Body).Decode(&list)
	found := false
	for _, c := range list["credentials"] {
		if c == cid {
			found = true
		}
	}
	if !found {
		t.Error("le credential enrôlé n'apparaît pas dans la liste")
	}

	// Un AUTRE coffre ne peut pas détourner ce credential (PUT -> 403, DELETE -> 403).
	tokenB, _ := loginTest(t, ts)
	rb := authReq(t, ts, "PUT", "/api/unlock/"+cid, tokenB, []byte(`{"wrap":"eA=="}`), "application/json")
	rb.Body.Close()
	if rb.StatusCode != http.StatusForbidden {
		t.Errorf("PUT unlock par un autre coffre = %d (attendu 403)", rb.StatusCode)
	}
	rbd := authReq(t, ts, "DELETE", "/api/unlock/"+cid, tokenB, nil, "")
	rbd.Body.Close()
	if rbd.StatusCode != http.StatusForbidden {
		t.Errorf("DELETE unlock par un autre coffre = %d (attendu 403)", rbd.StatusCode)
	}

	// Le propriétaire peut supprimer ; ensuite GET -> 404.
	rd := authReq(t, ts, "DELETE", "/api/unlock/"+cid, tokenA, nil, "")
	rd.Body.Close()
	if rd.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE unlock (owner) -> %d", rd.StatusCode)
	}
	r4 := authReq(t, ts, "GET", "/api/unlock/"+cid, "", nil, "")
	r4.Body.Close()
	if r4.StatusCode != http.StatusNotFound {
		t.Errorf("GET unlock après suppression = %d (attendu 404)", r4.StatusCode)
	}
}

func TestUnlockPutRequiresAuth(t *testing.T) {
	ts, _ := newTestServer(t, 0, 0)
	r := authReq(t, ts, "PUT", "/api/unlock/abc", "", []byte(`{"wrap":"eA=="}`), "application/json")
	r.Body.Close()
	if r.StatusCode != http.StatusUnauthorized {
		t.Errorf("PUT unlock sans token = %d (attendu 401)", r.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Garde-fou : isolation cross-coffre (le blob d'autrui reste inaccessible)
// ---------------------------------------------------------------------------

func TestCrossVaultBlobForbidden(t *testing.T) {
	ts, _ := newTestServer(t, 0, 0)
	tokenA, _ := loginTest(t, ts)
	tokenB, _ := loginTest(t, ts)

	data := []byte("le secret de A")
	id, _ := putBlobResp(t, ts, tokenA, data)
	putFileResp(t, ts, tokenA, "secretA", id, int64(len(data)))

	// B connaît l'id (hypothèse pessimiste) mais ne le référence pas : accès refusé.
	resp := authReq(t, ts, "GET", "/api/blob/"+id, tokenB, nil, "")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("isolation cross-coffre brisée, statut = %d (attendu 403)", resp.StatusCode)
	}
}
