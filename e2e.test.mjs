// Test end-to-end : rejoue le flux réel d'app.js (challenge/login -> chiffrement
// multi-morceaux lié par AAD -> upload blobs+méta -> download -> déchiffrement)
// contre le BINAIRE p2pfs en cours d'exécution. Prouve que toute la chaîne
// (F1 AAD + F4 quota/cap + F5 streaming + F10 blob-exists) fonctionne ensemble.
//
//   node e2e.test.mjs http://127.0.0.1:PORT
import * as C from './web/crypto.js';

const base = process.argv[2] || 'http://127.0.0.1:18080';
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓', m); } else { fail++; console.error('  ✗', m); } };
const j = (r) => r.json();
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

const id3 = await C.deriveIdentity(C.newMnemonic(128));

// --- login (challenge-réponse Ed25519) --------------------------------------
const ch = await j(await fetch(base + '/api/challenge', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ pubkey: id3.pubHex }) }));
const sig = id3.sign(C.authMessage(ch.nonce));
const login = await j(await fetch(base + '/api/login', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ pubkey: id3.pubHex, nonce: ch.nonce, sig: C.toHex(sig) }) }));
ok(!!login.token, 'login réussi (token de session reçu)');
const token = login.token;
const H = { authorization: 'Bearer ' + token };

// --- upload d'un fichier multi-morceaux -------------------------------------
const fileId = C.toHex(crypto.getRandomValues(new Uint8Array(16)));
const { dek, wrappedKey } = await C.newWrappedDEK(id3, fileId);
const original = crypto.getRandomValues(new Uint8Array(50_000));
const SZ = 20_000, total = Math.ceil(original.length / SZ);
const chunks = [];
for (let i = 0; i < total; i++) {
  const piece = original.slice(i * SZ, Math.min((i + 1) * SZ, original.length));
  const c = await C.encryptChunk(dek, piece, fileId, i, total);
  const put = await fetch(base + '/api/blob/' + c.blobId, {
    method: 'PUT', headers: { ...H, 'content-type': 'application/octet-stream' }, body: c.ciphertext });
  ok(put.ok, `morceau ${i + 1}/${total} uploadé (blob ${c.blobId.slice(0, 8)}…)`);
  chunks.push({ blob_id: c.blobId, iv: c.iv, size: c.size });
}
const encName = await C.encryptName(id3, 'Documents/secret.bin', fileId);
const meta = await fetch(base + '/api/files', {
  method: 'POST', headers: { ...H, 'content-type': 'application/json' },
  body: JSON.stringify({ id: fileId, enc_name: encName, wrapped_key: wrappedKey, size: original.length, chunks }) });
ok(meta.ok, 'métadonnée du fichier enregistrée');

// --- download + déchiffrement + vérification d'intégrité ---------------------
const { files } = await j(await fetch(base + '/api/files', { headers: H }));
const f = files.find((x) => x.id === fileId);
ok(!!f, 'fichier listé côté serveur');
ok((await C.decryptName(id3, f.enc_name, f.id)) === 'Documents/secret.bin', 'nom déchiffré correctement');

const dek2 = await C.unwrapDEK(id3, f.wrapped_key, f.id);
const parts = [];
const totalC = f.chunks.length;
for (let i = 0; i < totalC; i++) {
  const c = f.chunks[i];
  const ct = new Uint8Array(await (await fetch(base + '/api/blob/' + c.blob_id, { headers: H })).arrayBuffer());
  parts.push(await C.decryptChunk(dek2, ct, c.iv, f.id, i, totalC));
}
const reassembled = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
{ let off = 0; for (const p of parts) { reassembled.set(p, off); off += p.length; } }
ok(eq(reassembled, original), 'round-trip intègre : le fichier déchiffré == l\'original');

// --- preuve que l'attaque réordonnancement échoue via le vrai serveur --------
// On récupère le morceau 0 et on tente de le déchiffrer comme s'il était en pos. 1.
{
  const c0 = f.chunks[0];
  const ct0 = new Uint8Array(await (await fetch(base + '/api/blob/' + c0.blob_id, { headers: H })).arrayBuffer());
  let rejected = false;
  try { await C.decryptChunk(dek2, ct0, c0.iv, f.id, 1, totalC); } catch { rejected = true; }
  ok(rejected, 'ATTAQUE réordonnancement bout-en-bout : déchiffrement rejeté');
}

// --- F10 : référencer un blob jamais uploadé est refusé ----------------------
{
  const ghost = 'a'.repeat(64);
  const r = await fetch(base + '/api/files', {
    method: 'POST', headers: { ...H, 'content-type': 'application/json' },
    body: JSON.stringify({ id: 'ghostfile', enc_name: 'eA==', wrapped_key: 'eA==', size: 1,
      chunks: [{ blob_id: ghost, iv: 'eA==', size: 1 }] }) });
  ok(r.status === 400, 'F10 : référence vers un blob inexistant refusée (400)');
}

console.log(`\nE2E : ${pass} OK / ${fail} échec(s)`);
process.exit(fail === 0 ? 0 : 1);
