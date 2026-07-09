// ============================================================================
// webauthn.js — déverrouillage du coffre par CLÉ MATÉRIELLE (passkey, clé de
// sécurité, Touch ID / Windows Hello) via WebAuthn + l'extension PRF.
//
// L'extension PRF (basée sur CTAP2 hmac-secret) fait dériver par l'AUTHENTIFI-
// CATEUR un secret symétrique stable de 32 o pour un (credential, sel) donné.
// Ce secret ne quitte jamais le matériel ; le JS n'en reçoit que la sortie, et
// seulement pendant une cérémonie avec présence de l'utilisateur. On s'en sert
// pour envelopper/désenvelopper le master key du coffre (voir crypto.js).
//
// Le serveur reste "dumb" : il ne stocke qu'un wrap opaque (master chiffré).
// ============================================================================
import { b64url, unb64url } from './crypto.js';
import { sha256 } from './vendor/crypto.bundle.js';

const enc = new TextEncoder();
// Sel PRF : constante d'application (non secret). Fige le contexte de dérivation.
const PRF_SALT = sha256(enc.encode('p2pfs-prf-salt-v1')); // 32 o
// RP ID = le domaine. En prod ce doit être le domaine enregistrable (ex.
// "vault.exemple.fr"), JAMAIS une IP. En local, "localhost" est accepté.
// Configurable via window.P2PFS_CONFIG.rpId pour la production.
const RP_ID = window.P2PFS_CONFIG?.rpId || location.hostname;

// Disponibilité de WebAuthn (la prise en charge réelle de PRF se confirme à
// l'usage : on lit les résultats d'extension et on échoue proprement sinon).
export function webauthnAvailable() {
  const secure = location.protocol === 'https:' || RP_ID === 'localhost' || RP_ID === '127.0.0.1';
  return !!(window.PublicKeyCredential && navigator.credentials && secure);
}

// Enrôle une nouvelle clé : crée un credential résident (découvrable) avec PRF,
// puis récupère la sortie PRF. Renvoie { credentialId (b64url), prf (Uint8Array) }.
export async function registerKey() {
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { name: 'p2pfs', id: RP_ID },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: 'coffre@' + RP_ID, displayName: 'Coffre',
      },
      challenge: crypto.getRandomValues(new Uint8Array(32)), // pas d'attestation vérifiée
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'preferred' },
      timeout: 60000,
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  if (!cred) throw new Error('création de la clé annulée');
  const credentialId = new Uint8Array(cred.rawId);

  // Certains authentificateurs renvoient la PRF dès la création ; sinon on fait
  // une assertion immédiate pour l'obtenir.
  const ext = cred.getClientExtensionResults?.().prf;
  if (ext && ext.results && ext.results.first) {
    return { credentialId: b64url(credentialId), prf: new Uint8Array(ext.results.first) };
  }
  const got = await unlockWithKey(b64url(credentialId));
  return { credentialId: got.credentialId, prf: got.prf };
}

// Déverrouille : assertion (découvrable si credentialIdB64 absent) avec eval PRF.
// Renvoie { credentialId (b64url), prf (Uint8Array) }.
export async function unlockWithKey(credentialIdB64) {
  const allowCredentials = credentialIdB64
    ? [{ type: 'public-key', id: unb64url(credentialIdB64) }]
    : []; // [] = laisser l'authentificateur proposer ses credentials résidents
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: RP_ID,
      allowCredentials,
      userVerification: 'preferred',
      timeout: 60000,
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  if (!assertion) throw new Error('déverrouillage annulé');
  const prf = assertion.getClientExtensionResults().prf;
  if (!prf || !prf.results || !prf.results.first) {
    throw new Error('Cet authentificateur ne prend pas en charge l\'extension PRF.');
  }
  return {
    credentialId: b64url(new Uint8Array(assertion.rawId)),
    prf: new Uint8Array(prf.results.first),
  };
}
