// Tests (Node) du cœur cryptographique du déverrouillage par clé matérielle.
// La cérémonie WebAuthn ne peut pas tourner sans navigateur+authentificateur ;
// or le SEUL rôle du matériel est de fournir un secret STABLE de 32 o (sortie
// PRF). On le simule ici par un buffer fixe et on prouve que :
//   - la seed et la clé matérielle déverrouillent LE MÊME coffre (même identité)
//   - une mauvaise sortie PRF échoue (clé/credential incorrect)
//   - l'enveloppe du master key est intègre (AAD)
import * as C from '../web/crypto.js';

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓', m); } else { fail++; console.error('  ✗', m); } };
const mustReject = async (p, m) => { try { await p; fail++; console.error('  ✗', m, '(non rejeté !)'); } catch { pass++; console.log('  ✓', m); } };
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

const mnemonic = C.newMnemonic(128);
const master = C.masterFromMnemonic(mnemonic);
ok(master.length === 64, 'master key = 64 octets (seed BIP-39)');

// Identité dérivée du master, et identité dérivée de la seed phrase : identiques.
const idFromSeed   = await C.deriveIdentity(mnemonic);
const idFromMaster = await C.deriveIdentityFromMaster(master);
ok(idFromSeed.pubHex === idFromMaster.pubHex, 'seed et master dérivent la MÊME identité');

// --- enrôlement clé matérielle : enveloppe du master sous la sortie PRF -------
const prf = crypto.getRandomValues(new Uint8Array(32));        // sortie PRF simulée
const uk = await C.deriveUnlockKey(prf);
const wrap = await C.wrapMaster(uk, master);                    // stocké côté serveur (opaque)
ok(typeof wrap === 'string' && wrap.length > 0, 'master enveloppé (wrap base64 produit)');

// --- déverrouillage clé : on retrouve le master depuis le wrap + la même PRF ---
const uk2 = await C.deriveUnlockKey(prf);
const recovered = await C.unwrapMaster(uk2, wrap);
ok(eq(recovered, master), 'déverrouillage clé : master key reconstitué à l\'identique');
const idFromKey = await C.deriveIdentityFromMaster(recovered);
ok(idFromKey.pubHex === idFromSeed.pubHex, 'déverrouillage clé → MÊME coffre que la seed');

// --- mauvaise PRF (autre clé / credential) → échec --------------------------
const wrongPrf = crypto.getRandomValues(new Uint8Array(32));
const ukWrong = await C.deriveUnlockKey(wrongPrf);
await mustReject(C.unwrapMaster(ukWrong, wrap), 'mauvaise sortie PRF refusée (désenveloppe échoue)');

// --- wrap altéré → échec (intégrité AAD/GCM) --------------------------------
const tampered = C.unb64(wrap); tampered[tampered.length - 1] ^= 0x01;
await mustReject(C.unwrapMaster(uk2, C.b64(tampered)), 'wrap altéré rejeté (GCM)');

// --- base64url round-trip (identifiants de credential) ----------------------
const cid = crypto.getRandomValues(new Uint8Array(20));
ok(eq(C.unb64url(C.b64url(cid)), cid), 'base64url round-trip (credentialId)');

console.log(`\nUnlock : ${pass} OK / ${fail} échec(s)`);
process.exit(fail === 0 ? 0 : 1);
