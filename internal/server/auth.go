package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"
)

// ============================================================================
// AUTH — preuve de possession de la clé privée, SANS jamais transmettre de
// secret. Le client signe un nonce aléatoire ; le serveur vérifie la signature
// contre la clé publique (= l'identité du coffre).
//
//   1. POST /api/challenge {pubkey}      -> serveur renvoie un nonce (TTL court)
//   2. client signe le nonce (Ed25519)
//   3. POST /api/login {pubkey, nonce, sig} -> serveur vérifie -> session token
//
// Anti-rejeu : un nonce est à usage unique et expire vite.
// Le token de session n'est JAMAIS stocké en clair : on stocke son sha256,
// donc une fuite de la base ne donne aucune session valide.
// ============================================================================

const (
	challengeTTL = 60 * time.Second
	sessionTTL   = 2 * time.Hour  // Réduit de 12h à 2h pour limiter la fenêtre d'attaque
	nonceBytes   = 32
	tokenBytes   = 32
)

type challenge struct {
	nonce   []byte
	expires time.Time
}

type session struct {
	pubkey  string
	expires time.Time
}

type Auth struct {
	mu         sync.Mutex
	challenges map[string]challenge // pubkey -> challenge en cours
	sessions   map[string]session   // sha256(token) hex -> session
}

func NewAuth() *Auth {
	a := &Auth{
		challenges: map[string]challenge{},
		sessions:   map[string]session{},
	}
	go a.gc()
	return a
}

// gc purge périodiquement challenges et sessions expirés (anti-fuite mémoire).
func (a *Auth) gc() {
	t := time.NewTicker(time.Minute)
	for range t.C {
		now := time.Now()
		a.mu.Lock()
		for k, c := range a.challenges {
			if now.After(c.expires) {
				delete(a.challenges, k)
			}
		}
		for k, s := range a.sessions {
			if now.After(s.expires) {
				delete(a.sessions, k)
			}
		}
		a.mu.Unlock()
	}
}

// NewChallenge génère un nonce pour une clé publique donnée.
func (a *Auth) NewChallenge(pubkey string) ([]byte, error) {
	n := make([]byte, nonceBytes)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.challenges[pubkey] = challenge{nonce: n, expires: time.Now().Add(challengeTTL)}
	a.mu.Unlock()
	return n, nil
}

// Verify valide une signature contre le challenge en cours. Si OK, le challenge
// est consommé (usage unique) et un token de session est émis.
func (a *Auth) Verify(pubkeyHex string, nonce, sig []byte) (string, bool) {
	pub, err := hex.DecodeString(pubkeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return "", false
	}

	a.mu.Lock()
	c, ok := a.challenges[pubkeyHex]
	a.mu.Unlock()
	if !ok || time.Now().After(c.expires) {
		return "", false
	}
	// le nonce signé doit être exactement celui émis (comparaison constante)
	if subtle.ConstantTimeCompare(c.nonce, nonce) != 1 {
		return "", false
	}
	// Contextualiser la signature pour éviter le rejeu inter-protocole
	msg := append([]byte("p2pfs-auth-v1:"), nonce...)
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return "", false
	}

	// consommer le challenge (anti-rejeu)
	a.mu.Lock()
	delete(a.challenges, pubkeyHex)
	a.mu.Unlock()

	// émettre un token aléatoire ; n'en stocker que le hash
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", false
	}
	token := hex.EncodeToString(raw)
	h := sha256.Sum256([]byte(token))
	a.mu.Lock()
	a.sessions[hex.EncodeToString(h[:])] = session{pubkey: pubkeyHex, expires: time.Now().Add(sessionTTL)}
	a.mu.Unlock()
	return token, true
}

// Revoke invalide immédiatement une session (déconnexion explicite, F9). Idempotent.
func (a *Auth) Revoke(token string) {
	if token == "" {
		return
	}
	h := sha256.Sum256([]byte(token))
	a.mu.Lock()
	delete(a.sessions, hex.EncodeToString(h[:]))
	a.mu.Unlock()
}

// Resolve renvoie la pubkey associée à un token de session valide.
func (a *Auth) Resolve(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	h := sha256.Sum256([]byte(token))
	a.mu.Lock()
	s, ok := a.sessions[hex.EncodeToString(h[:])]
	a.mu.Unlock()
	if !ok || time.Now().After(s.expires) {
		return "", false
	}
	return s.pubkey, true
}

// ---------------------------------------------------------------------------
// RATE LIMITER — token bucket par IP. Protège /challenge et /login du
// brute-force et limite l'abus général. En mémoire (POC) : pour un cluster,
// utiliser un store partagé (Redis) ou s'appuyer sur le reverse-proxy (Caddy).
// ---------------------------------------------------------------------------

type bucket struct {
	tokens float64
	last   time.Time
}

type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // jetons par seconde
	capacity float64 // burst max
}

func NewRateLimiter(ratePerSec, burst float64) *RateLimiter {
	rl := &RateLimiter{
		buckets:  map[string]*bucket{},
		rate:     ratePerSec,
		capacity: burst,
	}
	go func() {
		t := time.NewTicker(10 * time.Minute)
		for range t.C {
			rl.mu.Lock()
			for k, b := range rl.buckets {
				if time.Since(b.last) > 30*time.Minute {
					delete(rl.buckets, k)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[key]
	now := time.Now()
	if !ok {
		rl.buckets[key] = &bucket{tokens: rl.capacity - 1, last: now}
		return true
	}
	// recharge proportionnelle au temps écoulé
	b.tokens += now.Sub(b.last).Seconds() * rl.rate
	if b.tokens > rl.capacity {
		b.tokens = rl.capacity
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
