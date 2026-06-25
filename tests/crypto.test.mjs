// Tests crypto (Node) — prouvent la liaison AAD (F1) :
//   - round-trip nominal OK
//   - réordonnancement de morceaux  -> REJETÉ
//   - troncature (mauvais "total")  -> REJETÉ
//   - permutation nom↔contenu↔DEK   -> REJETÉ
// Lancer : node tests/crypto.test.mjs   (depuis p2pfs/)
import * as C from '../web/crypto.js';

let pass = 0, fail = 0;
const ok  = (cond, msg) => { if (cond) { pass++; console.log('  ✓', msg); } else { fail++; console.error('  ✗', msg); } };
// "doit lever" : la promesse de déchiffrement doit être rejetée (auth GCM échoue)
const mustReject = async (p, msg) => {
  try { await p; fail++; console.error('  ✗', msg, '(n\'a PAS été rejeté !)'); }
  catch { pass++; console.log('  ✓', msg, '(rejeté comme attendu)'); }
};

const enc = new TextEncoder();
const eq  = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

console.log('— Dérivation & round-trips —');
const mnemonic = C.newMnemonic(128);
ok(C.validMnemonic(mnemonic), 'mnémonique générée valide');
const id3 = await C.deriveIdentity(mnemonic);
ok(/^[0-9a-f]{64}$/.test(id3.pubHex), 'pubkey hex 64 chars');

const FILE_A = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const FILE_B = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

// --- Nom lié au fileID -------------------------------------------------------
console.log('— Nom de fichier (AAD = fileID) —');
const encNameA = await C.encryptName(id3, 'Documents/cv.pdf', FILE_A);
ok((await C.decryptName(id3, encNameA, FILE_A)) === 'Documents/cv.pdf', 'nom déchiffré avec le bon fileID');
await mustReject(C.decryptName(id3, encNameA, FILE_B), 'nom du fichier A refusé sous l\'identité B (anti-permutation)');

// --- DEK enveloppée liée au fileID ------------------------------------------
console.log('— DEK enveloppée (AAD = fileID) —');
const { dek, wrappedKey } = await C.newWrappedDEK(id3, FILE_A);
const dekBack = await C.unwrapDEK(id3, wrappedKey, FILE_A);
ok(!!dekBack, 'DEK désenveloppée avec le bon fileID');
await mustReject(C.unwrapDEK(id3, wrappedKey, FILE_B), 'DEK du fichier A refusée sous l\'identité B (anti-permutation de clé)');

// --- Morceaux liés à (fileID, index, total) ---------------------------------
console.log('— Morceaux (AAD = fileID:index:total) —');
const TOTAL = 3;
const plains = [enc.encode('--- morceau 0 ---'), enc.encode('=== morceau 1 ==='), enc.encode('*** morceau 2 ***')];
const chunks = [];
for (let i = 0; i < TOTAL; i++) chunks.push(await C.encryptChunk(dek, plains[i], FILE_A, i, TOTAL));

// nominal : chaque morceau déchiffre à sa place
for (let i = 0; i < TOTAL; i++) {
  const blob = new Uint8Array([...C.unb64(chunks[i].iv), ...chunks[i].ciphertext]);
  const out  = await C.decryptChunk(dek, chunks[i].ciphertext, chunks[i].iv, FILE_A, i, TOTAL);
  ok(eq(out, plains[i]), `morceau ${i} déchiffré à sa position`);
}

// ATTAQUE 1 — réordonnancement : déchiffrer le morceau 0 comme s'il était à la position 1
await mustReject(
  C.decryptChunk(dek, chunks[0].ciphertext, chunks[0].iv, FILE_A, 1, TOTAL),
  'ATTAQUE réordonnancement (morceau 0 servi en position 1)');

// ATTAQUE 2 — troncature : le serveur ne renvoie que 2 morceaux et annonce total=2
await mustReject(
  C.decryptChunk(dek, chunks[0].ciphertext, chunks[0].iv, FILE_A, 0, 2),
  'ATTAQUE troncature (total falsifié 3 -> 2)');

// ATTAQUE 3 — splice cross-fichier : déchiffrer un morceau du fichier A sous l\'identité B
await mustReject(
  C.decryptChunk(dek, chunks[0].ciphertext, chunks[0].iv, FILE_B, 0, TOTAL),
  'ATTAQUE splice (morceau du fichier A réclamé pour le fichier B)');

console.log(`\nRésultat : ${pass} OK / ${fail} échec(s)`);
process.exit(fail === 0 ? 0 : 1);
