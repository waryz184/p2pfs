// E2E du DÉPLACEMENT entre dossiers, contre le binaire p2pfs. Reproduit
// exactement ce que fait app.js (rePath = re-chiffrer le nom avec un nouveau
// préfixe, même id/DEK/chunks) et vérifie via le serveur réel que :
//   - un fichier déplacé apparaît au nouveau chemin et son contenu reste intègre
//   - un dossier déplacé emporte son marqueur ET ses enfants
//
//   node e2e-move.test.mjs http://127.0.0.1:PORT
import * as C from './web/crypto.js';

const base = process.argv[2] || 'http://127.0.0.1:18097';
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓', m); } else { fail++; console.error('  ✗', m); } };
const J = (r) => r.json();
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

const id3 = await C.deriveIdentityFromMaster(C.masterFromMnemonic(C.newMnemonic(128)));
const ch = await J(await fetch(base + '/api/challenge', { method: 'POST',
  headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pubkey: id3.pubHex }) }));
const sig = id3.sign(C.fromHex(ch.nonce));
const token = (await J(await fetch(base + '/api/login', { method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ pubkey: id3.pubHex, nonce: ch.nonce, sig: C.toHex(sig) }) }))).token;
const H = { authorization: 'Bearer ' + token };

// upload d'un fichier à `fullPath` ; renvoie l'entrée {id, wrappedKey, chunks, content}
async function upload(fullPath, content) {
  const id = C.toHex(crypto.getRandomValues(new Uint8Array(16)));
  const { dek, wrappedKey } = await C.newWrappedDEK(id3, id);
  const c = await C.encryptChunk(dek, content, id, 0, 1);
  await fetch(base + '/api/blob/' + c.blobId, { method: 'PUT',
    headers: { ...H, 'content-type': 'application/octet-stream' }, body: c.ciphertext });
  const encName = await C.encryptName(id3, fullPath, id);
  await fetch(base + '/api/files', { method: 'POST', headers: { ...H, 'content-type': 'application/json' },
    body: JSON.stringify({ id, enc_name: encName, wrapped_key: wrappedKey, size: c.size,
      chunks: [{ blob_id: c.blobId, iv: c.iv, size: c.size }] }) });
  return { id, wrappedKey, chunks: [{ blob_id: c.blobId, iv: c.iv, size: c.size }], content };
}
// marqueur de dossier (chemin finissant par "/")
async function folder(path) { return upload(path, new TextEncoder().encode('.vaultfolder')); }
// rePath : re-chiffre le nom avec le nouveau chemin, même id/DEK/chunks
async function rePath(entry, newFullPath, isFolder) {
  const encName = await C.encryptName(id3, newFullPath + (isFolder ? '/' : ''), entry.id);
  await fetch(base + '/api/files', { method: 'POST', headers: { ...H, 'content-type': 'application/json' },
    body: JSON.stringify({ id: entry.id, enc_name: encName, wrapped_key: entry.wrappedKey,
      size: entry.chunks[0].size, chunks: entry.chunks }) });
}
// charge la liste et déchiffre tous les chemins -> [{id, path}]
async function paths() {
  const { files } = await J(await fetch(base + '/api/files', { headers: H }));
  const out = [];
  for (const f of files) out.push({ id: f.id, f, path: await C.decryptName(id3, f.enc_name, f.id) });
  return out;
}

// --- 1) déplacement d'un FICHIER -------------------------------------------
const original = crypto.getRandomValues(new Uint8Array(2048));
await folder('Photos/');
const file = await upload('Docs/cv.txt', original);
await rePath(file, 'Photos/cv.txt', false);            // déplacement Docs -> Photos

let p = await paths();
const moved = p.find(x => x.id === file.id);
ok(moved && moved.path === 'Photos/cv.txt', 'fichier déplacé : nouveau chemin « Photos/cv.txt »');
ok(!p.some(x => x.path === 'Docs/cv.txt'), 'plus aucune trace à l\'ancien emplacement');

// contenu toujours intègre après déplacement
const dek = await C.unwrapDEK(id3, moved.f.wrapped_key, moved.f.id);
const c0 = moved.f.chunks[0];
const ct = new Uint8Array(await (await fetch(base + '/api/blob/' + c0.blob_id, { headers: H })).arrayBuffer());
const dec = await C.decryptChunk(dek, ct, c0.iv, moved.f.id, 0, 1);
ok(eq(dec, original), 'contenu déchiffré intact après déplacement (aucune ré-écriture)');

// --- 2) déplacement d'un DOSSIER avec enfants -------------------------------
const marker = await folder('Work/sub/');
const child = await upload('Work/sub/a.txt', new TextEncoder().encode('enfant'));
// move "Work/sub" -> "Archive/sub" : re-pathue marqueur + enfant
await folder('Archive/');
await rePath(marker, 'Archive/sub', true);
await rePath(child, 'Archive/sub/a.txt', false);

p = await paths();
ok(p.some(x => x.id === marker.id && x.path === 'Archive/sub/'), 'dossier déplacé : marqueur « Archive/sub/ »');
ok(p.some(x => x.id === child.id && x.path === 'Archive/sub/a.txt'), 'enfant suivi : « Archive/sub/a.txt »');
ok(!p.some(x => x.path.startsWith('Work/sub')), 'plus rien sous l\'ancien dossier « Work/sub »');

console.log(`\nE2E move : ${pass} OK / ${fail} échec(s)`);
process.exit(fail === 0 ? 0 : 1);
