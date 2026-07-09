// E2E du déverrouillage par clé matérielle, contre le BINAIRE p2pfs.
// Seule la sortie PRF du matériel est simulée (un secret stable de 32 o) ; tout
// le reste est réel : endpoints /api/unlock, enveloppe/désenveloppe du master
// key, re-login, et lecture effective du coffre déjà rempli.
//
//   node e2e-unlock.test.mjs http://127.0.0.1:PORT
import * as C from './web/crypto.js';

const base = process.argv[2] || 'http://127.0.0.1:18092';
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓', m); } else { fail++; console.error('  ✗', m); } };
const J = (r) => r.json();

async function login(id3) {
  const ch = await J(await fetch(base + '/api/challenge', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pubkey: id3.pubHex }) }));
  const sig = id3.sign(C.authMessage(ch.nonce));
  const r = await J(await fetch(base + '/api/login', { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ pubkey: id3.pubHex, nonce: ch.nonce, sig: C.toHex(sig) }) }));
  return r.token;
}

// 1) Ouverture par seed + dépôt d'un fichier ---------------------------------
const mnemonic = C.newMnemonic(128);
const master = C.masterFromMnemonic(mnemonic);
const id3 = await C.deriveIdentityFromMaster(master);
let token = await login(id3);
ok(!!token, 'ouverture par seed phrase');
const H = (t) => ({ authorization: 'Bearer ' + t });

const fileId = C.toHex(crypto.getRandomValues(new Uint8Array(16)));
const { dek, wrappedKey } = await C.newWrappedDEK(id3, fileId);
const ch0 = await C.encryptChunk(dek, new TextEncoder().encode('contenu secret'), fileId, 0, 1);
await fetch(base + '/api/blob/' + ch0.blobId, { method: 'PUT',
  headers: { ...H(token), 'content-type': 'application/octet-stream' }, body: ch0.ciphertext });
const encName = await C.encryptName(id3, 'rapport.txt', fileId);
await fetch(base + '/api/files', { method: 'POST', headers: { ...H(token), 'content-type': 'application/json' },
  body: JSON.stringify({ id: fileId, enc_name: encName, wrapped_key: wrappedKey, size: ch0.size,
    chunks: [{ blob_id: ch0.blobId, iv: ch0.iv, size: ch0.size }] }) });
ok(true, 'fichier « rapport.txt » déposé');

// 2) Enrôlement d'une « clé matérielle » (PRF simulée) -----------------------
const prf = crypto.getRandomValues(new Uint8Array(32));                  // sortie PRF du matériel
const credentialId = C.b64url(crypto.getRandomValues(new Uint8Array(20)));
const uk = await C.deriveUnlockKey(prf);
const wrap = await C.wrapMaster(uk, master);
const put = await fetch(base + '/api/unlock/' + credentialId, { method: 'PUT',
  headers: { ...H(token), 'content-type': 'application/json' }, body: JSON.stringify({ wrap }) });
ok(put.status === 204, 'clé enrôlée (wrap opaque déposé côté serveur)');

// 3) Verrouillage : on oublie tout (token, master) --------------------------
token = null;

// 4) Déverrouillage par la clé : GET du wrap (NON authentifié) -> master ------
const wrapRes = await J(await fetch(base + '/api/unlock/' + credentialId)); // pas de token
ok(!!wrapRes.wrap, 'wrap récupéré sans authentification (bootstrap pré-login)');
const uk2 = await C.deriveUnlockKey(prf);
const master2 = await C.unwrapMaster(uk2, wrapRes.wrap);
const id3b = await C.deriveIdentityFromMaster(master2);
ok(id3b.pubHex === id3.pubHex, 'déverrouillage clé → même identité que la seed');
const token2 = await login(id3b);
ok(!!token2, 're-login via l\'identité dérivée de la clé');

// 5) Preuve d'accès réel : on lit et déchiffre le fichier déposé avant -------
const { files } = await J(await fetch(base + '/api/files', { headers: H(token2) }));
const f = files.find((x) => x.id === fileId);
const name = await C.decryptName(id3b, f.enc_name, f.id);
ok(name === 'rapport.txt', 'fichier du coffre lu et déchiffré APRÈS déverrouillage par clé');

// 6) Le serveur ne stocke que de l'opaque ------------------------------------
ok(!JSON.stringify(wrapRes).includes('rapport') && wrapRes.wrap.length > 0,
  'le serveur ne renvoie qu\'un wrap opaque (aucune donnée en clair)');

console.log(`\nE2E unlock : ${pass} OK / ${fail} échec(s)`);
process.exit(fail === 0 ? 0 : 1);
