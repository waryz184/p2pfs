// ============================================================================
// crypto.js — TOUTE la cryptographie vit ici, dans le navigateur.
// Le serveur ne reçoit jamais : la seed, les clés, les noms en clair, le contenu.
//
// Chaîne de dérivation depuis la seed phrase (BIP-39) :
//
//   mnémonique ──BIP39(PBKDF2-SHA512)──► seed (64 o)
//                                          │
//        ┌─────────────────HKDF-SHA256─────┴───────────────┐
//        ▼                                                  ▼
//   info="vault-auth-ed25519-v1"                   info="vault-enc-master-v1"
//        │ 32 o                                            │ 32 o
//        ▼                                                  ▼
//   clé privée Ed25519  ──► clé publique (= identité)   KEK (AES-256-GCM)
//        (authentification, jamais transmise)         (enveloppe les DEK + noms)
//
// Chiffrement d'un fichier :
//   DEK aléatoire 256 bits ──AES-GCM──► contenu chiffré
//   KEK ──AES-GCM──► DEK enveloppée (stockée dans la métadonnée)
// ============================================================================

import { ed25519, hkdf, sha256, sha512, bip39, wordlistEN }
  from './vendor/crypto.bundle.js';

// Câble SHA-512 pour les opérations Ed25519 synchrones de noble.
ed25519.etc.sha512Sync = (...m) => sha512(ed25519.etc.concatBytes(...m));

const enc = new TextEncoder();
const dec = new TextDecoder();
const subtle = globalThis.crypto.subtle;

// --- helpers encodage -------------------------------------------------------
export const toHex = (u8) => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
export const fromHex = (h) => new Uint8Array(h.match(/.{1,2}/g).map(x => parseInt(x, 16)));
export const b64 = (u8) => btoa(String.fromCharCode(...u8));
export const unb64 = (s) => new Uint8Array(atob(s).split('').map(c => c.charCodeAt(0)));
// base64url (sans padding) — pour les identifiants de credential WebAuthn.
export const b64url = (u8) => b64(u8).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
export const unb64url = (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return unb64(s); };

// --- seed phrase ------------------------------------------------------------
export function newMnemonic(strength = 128) {        // 128 bits = 12 mots
  return bip39.generateMnemonic(wordlistEN, strength);
}
export function validMnemonic(m) {
  return bip39.validateMnemonic(m.trim(), wordlistEN);
}

// --- master key du coffre ---------------------------------------------------
// Le "master key" (MK) est la seed BIP-39 (64 o). Toute l'identité et le KEK en
// dérivent. La seed phrase le REPRODUIT (récupération) ; une clé matérielle peut
// l'ENVELOPPER (déverrouillage sans saisie) — voir webauthn.js.
export function masterFromMnemonic(mnemonic) {
  return bip39.mnemonicToSeedSync(mnemonic.trim()); // 64 octets
}

// --- dérivation des clés depuis le master key -------------------------------
// Renvoie un "identity" : { pubHex, sign(msg), kek (CryptoKey AES-GCM) }
export async function deriveIdentityFromMaster(master) {
  const authSeed = hkdf(sha256, master, undefined, enc.encode('vault-auth-ed25519-v1'), 32);
  const kekRaw   = hkdf(sha256, master, undefined, enc.encode('vault-enc-master-v1'),   32);

  const pub = ed25519.getPublicKey(authSeed);          // 32 octets
  const kek = await subtle.importKey('raw', kekRaw, 'AES-GCM', false, ['encrypt', 'decrypt']);

  return {
    pubHex: toHex(pub),
    sign: (msg) => ed25519.sign(msg, authSeed),        // Uint8Array -> Uint8Array
    kek,
  };
}

// Compat : dérivation directe depuis la seed phrase (chemin "récupération").
export async function deriveIdentity(mnemonic) {
  return deriveIdentityFromMaster(masterFromMnemonic(mnemonic));
}

// --- enveloppe du master key par un secret de déverrouillage ----------------
// `secretBytes` = sortie PRF d'une clé matérielle (32 o, stable, jamais exposée
// hors de l'authentificateur). On en dérive une clé d'enveloppe AES-GCM, puis on
// chiffre/déchiffre le master key. L'AAD fige la version du schéma.
const UNLOCK_AAD = () => enc.encode('p2pfs-master-wrap-v1');

export async function deriveUnlockKey(secretBytes) {
  const raw = hkdf(sha256, secretBytes, undefined, enc.encode('p2pfs-unlock-v1'), 32);
  return subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
export async function wrapMaster(unlockKey, master) {        // -> base64
  return b64(await gcmEncrypt(unlockKey, master, UNLOCK_AAD()));
}
export async function unwrapMaster(unlockKey, wrapB64) {     // -> Uint8Array (master 64 o)
  return await gcmDecrypt(unlockKey, unb64(wrapB64), UNLOCK_AAD());
}

// --- AES-GCM bas niveau -----------------------------------------------------
// `aad` (Additional Authenticated Data) LIE le ciphertext à son contexte : le
// tag GCM couvre l'AAD, donc tout déplacement/permutation d'un champ chiffré
// vers un autre contexte fait ÉCHOUER le déchiffrement. C'est ce qui protège
// l'intégrité STRUCTURELLE face à un serveur malveillant (réordonnancement de
// chunks, troncature, permutation nom↔contenu↔clé), au-delà du simple bit-flip.
async function gcmEncrypt(key, plaintext, aad) {       // -> Uint8Array (iv||ct)
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const params = { name: 'AES-GCM', iv };
  if (aad) params.additionalData = aad;
  const ct = new Uint8Array(await subtle.encrypt(params, key, plaintext));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0); out.set(ct, iv.length);
  return out;
}
async function gcmDecrypt(key, blob, aad) {             // blob = iv||ct
  const iv = blob.slice(0, 12), ct = blob.slice(12);
  const params = { name: 'AES-GCM', iv };
  if (aad) params.additionalData = aad;
  return new Uint8Array(await subtle.decrypt(params, key, ct));
}

// --- contextes d'authentification (AAD) -------------------------------------
// Domaines séparés et liés à l'identité logique du fichier (`fileID`).
const aadName  = (fileID) => enc.encode('vault-name-v1:'  + fileID);
const aadDEK   = (fileID) => enc.encode('vault-dek-v1:'   + fileID);
const aadChunk = (fileID, index, total) =>
  enc.encode(`vault-chunk-v1:${fileID}:${index}:${total}`);

// --- chiffrement d'un nom de fichier (avec la KEK) --------------------------
// Le nom est lié au fileID : le serveur ne peut pas servir le nom du fichier A
// avec le contenu/la clé du fichier B (le déchiffrement échouerait).
export async function encryptName(id3, name, fileID) {
  return b64(await gcmEncrypt(id3.kek, enc.encode(name), aadName(fileID)));
}
export async function decryptName(id3, encB64, fileID) {
  return dec.decode(await gcmDecrypt(id3.kek, unb64(encB64), aadName(fileID)));
}

// --- chiffrement par CHUNKS -------------------------------------------------
// Un fichier = une DEK (enveloppée une fois) + N morceaux chiffrés, chacun avec
// son propre IV. Permet des fichiers de taille arbitraire sans tout charger en
// mémoire (upload morceau par morceau via Blob.slice côté app.js).
export const CHUNK_SIZE = 8 * 1024 * 1024; // 8 MiB

// Crée une DEK fraîche pour un fichier et l'enveloppe avec la KEK.
// La DEK enveloppée est liée au fileID (anti-permutation de clé entre fichiers).
export async function newWrappedDEK(id3, fileID) {
  const dekRaw = crypto.getRandomValues(new Uint8Array(32));
  const dek = await subtle.importKey('raw', dekRaw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const wrapped = await gcmEncrypt(id3.kek, dekRaw, aadDEK(fileID));
  return { dek, wrappedKey: b64(wrapped) };
}

// Récupère la DEK d'un fichier à partir de sa version enveloppée.
export async function unwrapDEK(id3, wrappedKeyB64, fileID) {
  const dekRaw = await gcmDecrypt(id3.kek, unb64(wrappedKeyB64), aadDEK(fileID));
  return subtle.importKey('raw', dekRaw, 'AES-GCM', false, ['decrypt']);
}

// Chiffre un morceau avec la DEK du fichier. blobId = sha256(ciphertext) :
// le serveur le revérifie (intégrité), comme pour un blob simple.
// L'AAD lie le morceau à (fileID, index, total) : réordonner, dupliquer ou
// retirer des morceaux fait échouer le déchiffrement, même si la DEK est bonne.
export async function encryptChunk(dek, bytes, fileID, index, total) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aadChunk(fileID, index, total) }, dek, bytes));
  return { ciphertext: ct, blobId: toHex(sha256(ct)), iv: b64(iv), size: ct.length };
}

// Déchiffre un morceau (GCM rejette tout ciphertext altéré OU déplacé).
export async function decryptChunk(dek, ct, ivB64, fileID, index, total) {
  const iv = unb64(ivB64);
  return new Uint8Array(await subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: aadChunk(fileID, index, total) }, dek, ct));
}
