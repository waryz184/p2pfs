// ============================================================================
// app.js — gestionnaire de fichiers chiffré, façon Drive/Nextcloud.
//
// DOSSIERS SANS CHANGER LE SERVEUR : le serveur ne stocke qu'un nom CHIFFRÉ
// opaque. On y encode le CHEMIN COMPLET ("Documents/factures/cv.pdf"). Le client
// déchiffre tous les chemins et reconstruit l'arborescence. Un dossier vide est
// matérialisé par une entrée "marqueur" dont le chemin se termine par "/".
// Le serveur reste un pur magasin de blobs : il ne voit aucune structure.
// ============================================================================
import * as C from './crypto.js';
import * as WA from './webauthn.js';

const FOLDER_MARK = '/';            // un chemin finissant par "/" = dossier explicite
let identity = null, token = null, masterKey = null;
let seedJustGenerated = false;      // pour inviter à enrôler une clé après la 1ʳᵉ ouverture
let entries = [];                   // [{id, blobId, wrappedKey, contentIV, size, createdAt, deletedAt, path, isFolder}]
let cwd = [];                       // dossier courant, ex. ['Documents','factures']
let nav = 'files';                  // 'files' | 'recent' | 'trash'
let view = 'grid';
let query = '';
let sortBy = 'name';                // 'name' | 'size' | 'date' (vue « Mes fichiers » uniquement)
let sortDir = 'asc';                // 'asc' | 'desc'
let selected = new Set();           // ids sélectionnés (fichiers uniquement, multi-sélection)
let sessionTimer = null;            // renouvellement silencieux avant expiration
const thumbCache = new Map();       // id -> URL objet (miniature image déchiffrée, revoquée au verrouillage)
let thumbObserver = null;           // IntersectionObserver : décryptage paresseux des miniatures

const $ = (id) => document.getElementById(id);
const el = (tag, cls) => { const e = document.createElement(tag); if (cls) e.className = cls; return e; };
// Préfixe de chemin du dossier courant (vide à la racine), ex. "Documents/factures/".
const cwdPrefix = () => cwd.length ? cwd.join('/') + '/' : '';

// --- API --------------------------------------------------------------------
async function api(path, { method = 'GET', json, raw } = {}) {
  const headers = {};
  if (token) headers['Authorization'] = 'Bearer ' + token;
  let body;
  if (json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(json); }
  if (raw !== undefined)  { headers['Content-Type'] = 'application/octet-stream'; body = raw; }
  const r = await fetch(path, { method, headers, body });
  if (!r.ok) throw new Error(`${method} ${path} → ${r.status}`);
  const ct = r.headers.get('Content-Type') || '';
  if (ct.includes('json')) return r.json();
  if (ct.includes('octet-stream')) return new Uint8Array(await r.arrayBuffer());
  return null;
}

// --- connexion (challenge-réponse) -----------------------------------------
// Coeur commun : prouve la possession de la clé privée dérivée du master key.
async function loginWithIdentity(id3) {
  identity = id3;
  const { nonce } = await api('/api/challenge', { method: 'POST', json: { pubkey: identity.pubHex } });
  const sig = identity.sign(C.authMessage(nonce));
  const res = await api('/api/login', { method: 'POST',
    json: { pubkey: identity.pubHex, nonce, sig: C.toHex(sig) } });
  token = res.token;
  if (res.expires_in) scheduleSessionRefresh(res.expires_in);
}

// Renouvelle la session AVANT expiration, sans ré-intervention de l'utilisateur :
// l'identité (clé Ed25519 dérivée) reste en mémoire, il suffit de rejouer le
// challenge/réponse. Ne redemande jamais la seed.
function scheduleSessionRefresh(expiresIn) {
  clearTimeout(sessionTimer);
  const marginMs = Math.min(120_000, expiresIn * 1000 / 4); // 2 min avant expiration (ou 1/4 si TTL très court)
  const delay = Math.max(5_000, expiresIn * 1000 - marginMs);
  sessionTimer = setTimeout(async () => {
    try { await loginWithIdentity(identity); }
    catch { toast('Votre session va bientôt expirer — reconnectez-vous si besoin.', 'err', 8000); }
  }, delay);
}

// Déverrouillage par seed phrase (récupération / 1ʳᵉ ouverture).
async function connect(mnemonic) {
  if (!C.validMnemonic(mnemonic)) throw new Error('Clé invalide : vérifiez les 12 mots.');
  masterKey = C.masterFromMnemonic(mnemonic);
  $('seed').value = ''; // EFFACEMENT IMMÉDIAT après dérivation (anti-XSS/keylogger)
  try {
    await loginWithIdentity(await C.deriveIdentityFromMaster(masterKey));
  } catch (e) {
    $('seed').value = mnemonic; // Restore only on error for UX
    throw e;
  }
}

// Déverrouillage par CLÉ MATÉRIELLE (WebAuthn/PRF) : aucune saisie de la seed.
// La clé fournit un secret PRF → clé d'enveloppe → on désenveloppe le master key
// récupéré (opaque) auprès du serveur, puis on dérive l'identité.
async function connectWithKey() {
  const { credentialId, prf } = await WA.unlockWithKey(null); // credential découvrable
  let wrapRes;
  try { wrapRes = await api('/api/unlock/' + credentialId); }
  catch { throw new Error('Cette clé n\'est associée à aucun coffre sur ce serveur.'); }
  const uk = await C.deriveUnlockKey(prf);
  // Note : on ne peut pas passer pubHex ici car on ne l'a pas encore dérivé
  // Le wrap est donc lié au credentialId qui est déjà unique et opaque
  masterKey = await C.unwrapMaster(uk, wrapRes.wrap, 'pre-login');
  await loginWithIdentity(await C.deriveIdentityFromMaster(masterKey));
}

// Enrôle une clé matérielle pour le coffre déverrouillé : enveloppe le master key
// sous la PRF de la clé et dépose le wrap opaque côté serveur.
async function enrollKey() {
  if (!masterKey) throw new Error('Coffre verrouillé.');
  const { credentialId, prf } = await WA.registerKey();
  const uk = await C.deriveUnlockKey(prf);
  // Lie le wrap à l'identité du coffre (anti-détournement)
  const wrap = await C.wrapMaster(uk, masterKey, identity.pubHex);
  await api('/api/unlock/' + credentialId, { method: 'PUT', json: { wrap } });
}

// --- chargement + déchiffrement des chemins --------------------------------
async function loadAll() {
  const { files } = await api('/api/files');
  const out = [];
  for (const f of files) {
    let path;
    try { path = await C.decryptName(identity, f.enc_name, f.id); } catch { continue; }
    const isFolder = path.endsWith(FOLDER_MARK);
    out.push({
      id: f.id, wrappedKey: f.wrapped_key, chunks: f.chunks || [],
      size: f.size, createdAt: f.created_at, deletedAt: f.deleted_at || null,
      path: isFolder ? path.slice(0, -1) : path, isFolder,
    });
  }
  entries = out;
}

// --- dérive le contenu du dossier courant ----------------------------------
function currentItems() {
  if (nav === 'trash') return trashItems();

  const prefix = cwdPrefix();
  const folders = new Map();   // nom -> {createdAt}
  const files = [];

  for (const e of entries) {
    if (e.deletedAt) continue;                    // dans la corbeille : invisible ici
    if (nav === 'recent') {                       // vue plate, tous les fichiers
      if (!e.isFolder) files.push(e);
      continue;
    }
    if (!e.path.startsWith(prefix)) continue;
    const rest = e.path.slice(prefix.length);
    if (rest === '') continue;
    const slash = rest.indexOf('/');
    if (e.isFolder && slash === -1) {             // marqueur de dossier à ce niveau
      if (!folders.has(rest)) folders.set(rest, { createdAt: e.createdAt, marker: e });
    } else if (!e.isFolder && slash === -1) {     // fichier à ce niveau
      files.push(e);
    } else {                                      // sous-dossier implicite (déduit du chemin)
      const top = rest.slice(0, slash);
      if (!folders.has(top)) folders.set(top, { createdAt: e.createdAt });
    }
  }

  let folderList = [...folders.entries()].map(([name, v]) => ({ name, ...v }));
  let fileList = files.map(f => ({ ...f, name: f.path.split('/').pop() }));

  if (query) {
    const q = query.toLowerCase();
    folderList = folderList.filter(f => f.name.toLowerCase().includes(q));
    fileList = fileList.filter(f => f.name.toLowerCase().includes(q));
  }
  folderList.sort((a, b) => a.name.localeCompare(b.name));
  if (nav === 'recent') {
    fileList.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    folderList = [];
  } else {
    sortInPlace(fileList);
  }
  return { folderList, fileList };
}

// Tri configurable (nom/taille/date, asc/desc) — vue « Mes fichiers » uniquement.
function sortInPlace(list) {
  const dir = sortDir === 'desc' ? -1 : 1;
  list.sort((a, b) => {
    let cmp;
    if (sortBy === 'size') cmp = a.size - b.size;
    else if (sortBy === 'date') cmp = new Date(a.createdAt) - new Date(b.createdAt);
    else cmp = a.name.localeCompare(b.name);
    return cmp * dir;
  });
  return list;
}

// Vue « Corbeille » : liste plate de tout ce qui est marqué deletedAt, triée
// par date de suppression décroissante (le plus récent en premier).
function trashItems() {
  let fileList = entries.filter(e => e.deletedAt).map(e => ({ ...e, name: e.path.split('/').pop() || e.path }));
  if (query) {
    const q = query.toLowerCase();
    fileList = fileList.filter(f => f.name.toLowerCase().includes(q) || f.path.toLowerCase().includes(q));
  }
  fileList.sort((a, b) => new Date(b.deletedAt) - new Date(a.deletedAt));
  return { folderList: [], fileList };
}

// --- icônes par type --------------------------------------------------------
const EXT = {
  img:['png','jpg','jpeg','gif','webp','svg','heic','bmp','avif'],
  pdf:['pdf'], doc:['doc','docx','odt','rtf','txt','md','pages'],
  sheet:['xls','xlsx','csv','ods','numbers'], slide:['ppt','pptx','odp','key'],
  zip:['zip','tar','gz','7z','rar','xz'], code:['js','ts','go','py','rs','java','c','cpp','html','css','json','yml','yaml','sh','sql'],
  audio:['mp3','wav','flac','aac','ogg','m4a'], video:['mp4','mov','mkv','webm','avi'],
};
function kindOf(name) {
  const e = name.split('.').pop().toLowerCase();
  for (const k in EXT) if (EXT[k].includes(e)) return k;
  return 'file';
}
const PATHS = {
  folder: `<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/>`,
  file:`<path d="M6 2h8l4 4v16H6z"/><path d="M14 2v4h4"/>`,
  img:`<rect x="4" y="4" width="16" height="16" rx="2"/><circle cx="9" cy="9" r="1.6"/><path d="m4 16 4-4 5 5 3-3 4 4"/>`,
  pdf:`<path d="M6 2h8l4 4v16H6z"/><path d="M14 2v4h4"/><path d="M8.5 18v-4h1.2a1.3 1.3 0 0 1 0 2.6H8.5M13 14v4M13 14h1.6M13 16h1.4"/>`,
  doc:`<path d="M6 2h8l4 4v16H6z"/><path d="M14 2v4h4"/><path d="M9 12h6M9 15h6M9 18h4"/>`,
  sheet:`<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M4 10h16M4 15h16M10 4v16"/>`,
  slide:`<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M12 17v3M9 20h6"/>`,
  zip:`<path d="M6 2h8l4 4v16H6z"/><path d="M14 2v4h4"/><path d="M11 6h2M11 9h2M11 12h2M11 15h2"/>`,
  code:`<path d="M6 2h8l4 4v16H6z"/><path d="M14 2v4h4"/><path d="m10 12-2 2 2 2M14 12l2 2-2 2"/>`,
  audio:`<path d="M9 18V6l10-2v12"/><circle cx="6" cy="18" r="3"/><circle cx="16" cy="16" r="3"/>`,
  video:`<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m10 9 5 3-5 3z"/>`,
};
function iconSVG(kind, cls) {
  const k = kind === 'folder' ? ' k-folder' : '';
  return `<svg class="${cls}${k}" viewBox="0 0 24 24">${PATHS[kind] || PATHS.file}</svg>`;
}

// --- rendu ------------------------------------------------------------------
function render() {
  renderCrumbs();
  $('trash-bar').classList.toggle('hidden', nav !== 'trash');
  $('sort-tools').classList.toggle('hidden', nav !== 'files');
  if (thumbObserver) { thumbObserver.disconnect(); thumbObserver = null; } // pas d'observations mortes entre rendus
  const { folderList, fileList } = currentItems();
  const grid = $('grid'), listBody = $('list-body'), empty = $('empty');
  grid.innerHTML = ''; listBody.innerHTML = '';

  if (!folderList.length && !fileList.length) {
    empty.classList.remove('hidden'); $('grid').classList.add('hidden'); $('list').classList.add('hidden');
    empty.innerHTML = query
      ? `<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></svg><h2>Aucun résultat</h2><p>Rien ne correspond à « ${escapeHtml(query)} ».</p>`
      : nav === 'trash'
      ? `<svg viewBox="0 0 24 24"><path d="M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13"/></svg><h2>Corbeille vide</h2><p>Les fichiers supprimés apparaissent ici.</p>`
      : `<svg viewBox="0 0 24 24"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/></svg><h2>Ce dossier est vide</h2><p>Glissez des fichiers ici, ou utilisez le bouton Nouveau.</p>`;
    return;
  }
  empty.classList.add('hidden');
  grid.classList.toggle('hidden', view !== 'grid');
  $('list').classList.toggle('hidden', view !== 'list');

  if (nav === 'trash') {
    for (const f of fileList) view === 'grid' ? grid.appendChild(trashTile(f)) : listBody.appendChild(trashRow(f));
  } else {
    for (const f of folderList) view === 'grid' ? grid.appendChild(folderTile(f)) : listBody.appendChild(folderRow(f));
    for (const f of fileList)   view === 'grid' ? grid.appendChild(fileTile(f))   : listBody.appendChild(fileRow(f));
  }
  updateBulkBar();
}

function renderCrumbs() {
  const c = $('crumbs'); c.innerHTML = '';
  const label = nav === 'recent' ? 'Récents' : nav === 'trash' ? 'Corbeille' : 'Mes fichiers';
  const root = el('button'); root.textContent = label;
  if (!cwd.length || nav !== 'files') root.className = 'current';
  root.onclick = () => { if (nav === 'files') { cwd = []; render(); } };
  c.appendChild(root);
  if (nav !== 'files') return;
  cwd.forEach((seg, i) => {
    const sep = el('span', 'sep'); sep.textContent = '›'; c.appendChild(sep);
    const b = el('button'); b.textContent = seg;
    if (i === cwd.length - 1) b.className = 'current';
    b.onclick = () => { cwd = cwd.slice(0, i + 1); render(); };
    c.appendChild(b);
  });
}

// case à cocher de sélection multiple (fichiers uniquement — les dossiers ne
// sont qu'un préfixe de chemin déduit, pas une entité adressable par id seul).
function selCheckbox(id) {
  const label = el('label', 'sel-check');
  const cb = el('input'); cb.type = 'checkbox'; cb.checked = selected.has(id);
  cb.onclick = (e) => {
    e.stopPropagation();
    if (cb.checked) selected.add(id); else selected.delete(id);
    document.querySelectorAll(`[data-id="${id}"]`).forEach(n => n.classList.toggle('selected', cb.checked));
    updateBulkBar();
  };
  label.appendChild(cb);
  return label;
}

// tuiles (grille)
function folderTile(f) {
  const t = el('div', 'tile');
  t.innerHTML = iconSVG('folder', 'ico') + `<div class="t-name">${escapeHtml(f.name)}</div><div class="t-meta">Dossier</div>`;
  t.appendChild(moreMenu(() => openFolderActions(f)));
  t.ondblclick = () => { cwd = [...cwd, f.name]; query=''; $('search').value=''; render(); };
  return t;
}
function fileTile(f) {
  const t = el('div', 'tile');
  t.dataset.id = f.id;
  if (selected.has(f.id)) t.classList.add('selected');
  t.innerHTML = iconSVG(kindOf(f.name), 'ico') +
    `<div class="t-name">${escapeHtml(f.name)}</div><div class="t-meta">${humanSize(f.size)}</div>`;
  t.prepend(selCheckbox(f.id));
  t.appendChild(moreMenu(() => openFileActions(f)));
  t.ondblclick = () => openPreview(f);
  maybeThumbnail(t, f);
  return t;
}
function trashTile(f) {
  const t = el('div', 'tile');
  t.dataset.id = f.id;
  if (selected.has(f.id)) t.classList.add('selected');
  const kind = f.isFolder ? 'folder' : kindOf(f.name);
  t.innerHTML = iconSVG(kind, 'ico') +
    `<div class="t-name">${escapeHtml(f.name)}</div><div class="t-meta">${escapeHtml(f.path)}</div>`;
  t.prepend(selCheckbox(f.id));
  t.appendChild(moreMenu(() => openTrashActions(f)));
  return t;
}
function moreMenu(onClick) {
  const wrap = el('div', 't-more');
  const b = el('button', 'icon-btn'); b.innerHTML = `<svg class="ic" viewBox="0 0 24 24"><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg>`;
  b.onclick = (e) => { e.stopPropagation(); onClick(); };
  wrap.appendChild(b); return wrap;
}

// lignes (liste)
function folderRow(f) {
  const tr = el('tr');
  const td = el('td'); td.className = 'l-name'; td.innerHTML = iconSVG('folder','ico') + `<span>${escapeHtml(f.name)}</span>`;
  tr.append(tdText('', 'c-sel'), td, tdText('—','c-size'), tdText(fmtDate(f.createdAt),'c-date'));
  const act = el('td', 'c-act'); act.appendChild(rowActions([
    ['Déplacer', moveIcon(), () => moveDialog(f, true)],
    ['Renommer', renameIcon(), () => renameFolder(f)],
    ['Corbeille', trashIcon(), () => trashFolder(f), true],
  ])); tr.appendChild(act);
  tr.ondblclick = () => { cwd = [...cwd, f.name]; query=''; $('search').value=''; render(); };
  return tr;
}
function fileRow(f) {
  const tr = el('tr');
  tr.dataset.id = f.id;
  if (selected.has(f.id)) tr.classList.add('selected');
  const sel = el('td', 'c-sel'); sel.appendChild(selCheckbox(f.id));
  const td = el('td'); td.className = 'l-name'; td.innerHTML = iconSVG(kindOf(f.name),'ico') + `<span>${escapeHtml(f.name)}</span>`;
  tr.append(sel, td, tdText(humanSize(f.size),'c-size'), tdText(fmtDate(f.createdAt),'c-date'));
  const act = el('td', 'c-act'); act.appendChild(rowActions([
    ['Télécharger', dlIcon(), () => download(f)],
    ['Déplacer', moveIcon(), () => moveDialog(f, false)],
    ['Renommer', renameIcon(), () => renameFile(f)],
    ['Corbeille', trashIcon(), () => trashFile(f), true],
  ])); tr.appendChild(act);
  tr.ondblclick = () => openPreview(f);
  return tr;
}
function trashRow(f) {
  const tr = el('tr');
  tr.dataset.id = f.id;
  if (selected.has(f.id)) tr.classList.add('selected');
  const sel = el('td', 'c-sel'); sel.appendChild(selCheckbox(f.id));
  const kind = f.isFolder ? 'folder' : kindOf(f.name);
  const td = el('td'); td.className = 'l-name'; td.innerHTML = iconSVG(kind,'ico') + `<span>${escapeHtml(f.name)}</span>`;
  tr.append(sel, td, tdText(f.path, 'c-size'), tdText(fmtDate(f.deletedAt),'c-date'));
  const act = el('td', 'c-act'); act.appendChild(rowActions([
    ['Restaurer', restoreIcon(), () => restoreOne(f)],
    ['Supprimer définitivement', trashIcon(), () => purgeOne(f), true],
  ])); tr.appendChild(act);
  return tr;
}
function tdText(txt, cls) { const td = el('td', cls); td.textContent = txt; return td; }
function rowActions(items) {
  const wrap = el('div', 'row-actions');
  for (const [title, svg, fn, danger] of items) {
    const b = el('button', 'icon-btn' + (danger ? ' danger' : '')); b.title = title; b.innerHTML = svg;
    b.onclick = (e) => { e.stopPropagation(); fn(); };
    wrap.appendChild(b);
  }
  return wrap;
}
const dlIcon = () => `<svg class="ic" viewBox="0 0 24 24"><path d="M12 4v12M7 11l5 5 5-5"/><path d="M5 20h14"/></svg>`;
const renameIcon = () => `<svg class="ic" viewBox="0 0 24 24"><path d="M4 20h4l10-10-4-4L4 16v4Z"/><path d="m13.5 6.5 4 4"/></svg>`;
const trashIcon = () => `<svg class="ic" viewBox="0 0 24 24"><path d="M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13"/></svg>`;
const moveIcon = () => `<svg class="ic" viewBox="0 0 24 24"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h6a2 2 0 0 1 2 2v2"/><path d="M13 17h8M18 14l3 3-3 3"/></svg>`;
const restoreIcon = () => `<svg class="ic" viewBox="0 0 24 24"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/></svg>`;
function openFileActions(f){ openSheet([['Télécharger',()=>download(f)],['Aperçu',()=>openPreview(f)],['Déplacer',()=>moveDialog(f,false)],['Renommer',()=>renameFile(f)],['Corbeille',()=>trashFile(f)]]); }
function openFolderActions(f){ openSheet([['Ouvrir',()=>{cwd=[...cwd,f.name];render();}],['Déplacer',()=>moveDialog(f,true)],['Renommer',()=>renameFolder(f)],['Corbeille',()=>trashFolder(f)]]); }
function openTrashActions(f){ openSheet([['Restaurer',()=>restoreOne(f)],['Supprimer définitivement',()=>purgeOne(f)]]); }
function openSheet(items){ // menu d'actions flottant (utilisé par le bouton "…" en grille)
  const back = el('div','modal-back'); const m = el('div','modal');
  m.innerHTML = '<h3>Actions</h3>';
  const box = el('div','sheet-box');
  for (const [label, fn] of items){ const b=el('button','btn btn-ghost'); b.textContent=label; b.onclick=()=>{back.remove();fn();}; box.appendChild(b); }
  const cancel=el('button','btn btn-ghost'); cancel.textContent='Fermer'; cancel.onclick=()=>back.remove();
  box.appendChild(cancel); m.appendChild(box); back.appendChild(m);
  back.onclick=(e)=>{ if(e.target===back) back.remove(); }; document.body.appendChild(back);
}

// --- actions fichiers -------------------------------------------------------
async function uploadFile(file, prog, fullPathOverride) {
  // fullPathOverride : chemin relatif préservé pour un dossier glissé-déposé
  // (traverseEntry) ; sinon le fichier est importé directement dans cwd.
  const fullPath = fullPathOverride ?? (cwdPrefix() + file.name);
  // L'id logique est généré AVANT le chiffrement : il sert de contexte (AAD) qui
  // lie le nom, la DEK enveloppée et chaque morceau à CE fichier précis.
  const id = C.toHex(crypto.getRandomValues(new Uint8Array(16)));
  const { dek, wrappedKey } = await C.newWrappedDEK(identity, id);

  const total = file.size;
  const nChunks = Math.max(1, Math.ceil(total / C.CHUNK_SIZE));
  const chunks = [];
  let sent = 0;

  for (let i = 0; i < nChunks; i++) {
    const slice = file.slice(i * C.CHUNK_SIZE, Math.min((i + 1) * C.CHUNK_SIZE, total));
    const bytes = new Uint8Array(await slice.arrayBuffer());      // un seul morceau en RAM
    const ch = await C.encryptChunk(dek, bytes, id, i, nChunks);
    await api('/api/blob/' + ch.blobId, { method: 'PUT', raw: ch.ciphertext });
    chunks.push({ blob_id: ch.blobId, iv: ch.iv, size: ch.size });
    sent += ch.size;
    if (prog && nChunks > 1) prog.update(`« ${file.name} » — ${humanSize(sent)} / ${humanSize(total)}`);
  }

  const encName = await C.encryptName(identity, fullPath, id);
  await api('/api/files', { method: 'POST', json: {
    id, enc_name: encName, wrapped_key: wrappedKey,
    size: chunks.reduce((s, c) => s + c.size, 0), chunks } });
}
// `list` : mélange possible de File bruts (import classique / drop de
// fichiers) et de { file, fullPath } (dossier glissé-déposé, cf. traverseEntry).
async function uploadFiles(list) {
  const items = list.map(x => (x instanceof File) ? { file: x, fullPath: null } : x);
  const prog = progressToast(`Import de ${items.length} fichier${items.length>1?'s':''}…`);
  try {
    let n = 0;
    for (const { file, fullPath } of items) {
      prog.update(`Chiffrement de « ${file.name} » (${++n}/${items.length})…`);
      await uploadFile(file, prog, fullPath);
    }
    await loadAll(); render(); updateMeter();
    prog.done();
    toast(`${items.length} fichier${items.length>1?'s':''} ajouté${items.length>1?'s':''}`, 'ok');
  } catch (e) { prog.done(); console.error('Import error:', e.message); toast('Échec de l\'import', 'err'); }
}

async function createFolder(name) {
  const prefix = cwdPrefix();
  const path = prefix + name + FOLDER_MARK;                  // marqueur (chemin avec "/")
  // un marqueur a besoin d'au moins un chunk (le serveur exige chunks non vide)
  const id = C.toHex(crypto.getRandomValues(new Uint8Array(16)));
  const { dek, wrappedKey } = await C.newWrappedDEK(identity, id);
  const ch = await C.encryptChunk(dek, new TextEncoder().encode('.vaultfolder'), id, 0, 1);
  await api('/api/blob/' + ch.blobId, { method: 'PUT', raw: ch.ciphertext });
  const encName = await C.encryptName(identity, path, id);
  await api('/api/files', { method: 'POST', json: {
    id, enc_name: encName, wrapped_key: wrappedKey, size: ch.size,
    chunks: [{ blob_id: ch.blobId, iv: ch.iv, size: ch.size }] } });
  await loadAll(); render();
  toast(`Dossier « ${name} » créé`, 'ok');
}

// Récupère et déchiffre TOUS les morceaux d'un fichier en un seul Blob.
// Cœur commun à download(), openPreview() et aux miniatures d'images.
async function decryptFileToBlob(f, prog) {
  const dek = await C.unwrapDEK(identity, f.wrappedKey, f.id);
  const parts = [];
  let done = 0;
  const total = f.chunks.length;
  for (let i = 0; i < total; i++) {
    const c = f.chunks[i];
    const ct = await api('/api/blob/' + c.blob_id);
    // L'AAD (f.id, i, total) impose l'ordre ET le nombre de morceaux : un
    // serveur qui réordonne ou tronque le manifeste fait échouer GCM ici.
    parts.push(await C.decryptChunk(dek, ct, c.iv, f.id, i, total));
    done += c.size;
    if (prog) prog.update(`« ${f.name} » — ${humanSize(done)} / ${humanSize(f.size)}`);
  }
  return new Blob(parts);
}
async function download(f) {
  const prog = (f.chunks.length > 1) ? progressToast(`Téléchargement de « ${f.name} »…`) : null;
  try {
    const blob = await decryptFileToBlob(f, prog);
    const url = URL.createObjectURL(blob);
    const a = el('a'); a.href = url; a.download = f.name; a.click(); URL.revokeObjectURL(url);
    if (prog) prog.done();
  } catch (e) { if (prog) prog.done(); console.error('Download error:', e.message); toast('Échec du téléchargement', 'err'); }
}

// --- aperçu inline (image / PDF / texte) ------------------------------------
const TEXT_EXT = ['txt','md','json','js','ts','css','html','yml','yaml','sh','sql','csv','log','xml','go','py','rs','java','c','cpp'];
function previewKind(f) {
  const kind = kindOf(f.name);
  if (kind === 'img') return 'image';
  if (kind === 'pdf') return 'pdf';
  const ext = f.name.split('.').pop().toLowerCase();
  if (TEXT_EXT.includes(ext) && f.size <= 2 * 1024 * 1024) return 'text';
  return null;
}
async function openPreview(f) {
  const pk = previewKind(f);
  if (!pk) return download(f); // pas d'aperçu possible : téléchargement direct
  const back = $('preview-modal'), body = $('preview-body');
  $('preview-title').textContent = f.name;
  body.innerHTML = `<svg class="ic spin preview-spin" viewBox="0 0 24 24"><path d="M12 3a9 9 0 1 0 9 9"/></svg>`;
  back.classList.remove('hidden');
  $('preview-dl').onclick = () => download(f);
  const close = () => { back.classList.add('hidden'); if (currentUrl) URL.revokeObjectURL(currentUrl); };
  $('preview-close').onclick = close;
  back.onclick = (e) => { if (e.target === back) close(); };
  let currentUrl = null;
  try {
    const blob = await decryptFileToBlob(f);
    if (pk === 'image') {
      currentUrl = URL.createObjectURL(blob);
      body.innerHTML = `<img alt="${escapeHtml(f.name)}">`;
      body.querySelector('img').src = currentUrl;
    } else if (pk === 'pdf') {
      currentUrl = URL.createObjectURL(blob);
      body.innerHTML = `<embed type="application/pdf">`;
      body.querySelector('embed').src = currentUrl;
    } else {
      const text = await blob.text();
      body.innerHTML = '<pre></pre>';
      body.querySelector('pre').textContent = text; // textContent : jamais interprété comme HTML
    }
  } catch (e) {
    console.error('Preview error:', e.message);
    body.innerHTML = `<p class="modal-text">Aperçu impossible.</p>`;
  }
}

// --- miniatures d'images (grille) -------------------------------------------
// Décryptage paresseux : seules les tuiles qui entrent dans le viewport
// déclenchent le déchiffrement (une image entière, pas un vrai thumbnail —
// le serveur ne peut pas en générer, zero-knowledge oblige). Résultat mis en
// cache par id de fichier ; revoqué au verrouillage du coffre.
function ensureThumbObserver() {
  if (!thumbObserver) {
    thumbObserver = new IntersectionObserver((obs) => {
      for (const en of obs) {
        if (!en.isIntersecting) continue;
        thumbObserver.unobserve(en.target);
        loadThumb(en.target, en.target.dataset.thumbId);
      }
    }, { root: document.querySelector('.canvas'), rootMargin: '200px' });
  }
  return thumbObserver;
}
function maybeThumbnail(tileEl, f) {
  if (kindOf(f.name) !== 'img' || f.size > 8 * 1024 * 1024) return;
  tileEl.dataset.thumbId = f.id;
  ensureThumbObserver().observe(tileEl);
}
async function loadThumb(tileEl, id) {
  const f = entries.find(e => e.id === id);
  if (!f) return;
  let url = thumbCache.get(id);
  if (!url) {
    try { url = URL.createObjectURL(await decryptFileToBlob(f)); thumbCache.set(id, url); }
    catch { return; }
  }
  const ico = tileEl.querySelector('.ico');
  if (!ico || !tileEl.isConnected) return; // tuile déjà remplacée par un re-rendu
  const img = el('img', 'ico thumb-img'); img.src = url; img.alt = '';
  ico.replaceWith(img);
}

async function rePath(entry, newFullPath) {  // ré-encode le nom et réécrit la métadonnée (même id, mêmes chunks)
  // Le renommage garde le même id : le nouveau nom reste lié au même contexte AAD
  // que la DEK et les morceaux déjà stockés (aucune ré-écriture du contenu).
  const encName = await C.encryptName(identity, newFullPath + (entry.isFolder ? FOLDER_MARK : ''), entry.id);
  await api('/api/files', { method: 'POST', json: {
    id: entry.id, enc_name: encName, wrapped_key: entry.wrappedKey,
    size: entry.size, chunks: entry.chunks } });
}
// Re-pathue un dossier entier : son marqueur (chemin === oldPrefix) ET tous ses
// descendants (chemin commençant par oldPrefix + '/'). Utilisé par le renommage
// ET le déplacement de dossier.
async function rePathSubtree(oldPrefix, newPrefix) {
  for (const e of entries) {
    if (e.path === oldPrefix || e.path.startsWith(oldPrefix + '/')) {
      await rePath(e, newPrefix + e.path.slice(oldPrefix.length));
    }
  }
}
function renameFile(f) {
  modalPrompt('Renommer le fichier', f.name, async (val) => {
    const dir = f.path.split('/').slice(0, -1).join('/');
    await rePath(f, (dir ? dir + '/' : '') + val);
    await loadAll(); render(); toast('Fichier renommé', 'ok');
  });
}
function renameFolder(f) {
  modalPrompt('Renommer le dossier', f.name, async (val) => {
    // renommer un dossier = re-pathuer le marqueur ET tous les enfants
    await rePathSubtree(cwdPrefix() + f.name, cwdPrefix() + val);
    await loadAll(); render(); toast('Dossier renommé', 'ok');
  });
}
// --- corbeille (suppression réversible) -------------------------------------
// Déplacer vers la corbeille est réversible : pas de confirm() (contrairement
// à la purge définitive, qui elle demande confirmation).
async function trashFile(f) {
  try { await api('/api/files/' + f.id + '/trash', { method: 'POST' }); selected.delete(f.id);
    await loadAll(); render(); updateMeter(); toast('Déplacé vers la corbeille', 'ok'); }
  catch (e) { console.error('Error:', e.message); toast('Échec', 'err'); }
}
async function trashFolder(f) {
  const prefix = cwdPrefix() + f.name;
  const victims = entries.filter(e => e.path === prefix || e.path.startsWith(prefix + '/'));
  try {
    for (const v of victims) await api('/api/files/' + v.id + '/trash', { method: 'POST' });
    await loadAll(); render(); updateMeter(); toast('Dossier déplacé vers la corbeille', 'ok');
  } catch (e) { console.error('Error:', e.message); toast('Échec', 'err'); }
}
async function restoreOne(f) {
  try { await api('/api/files/' + f.id + '/restore', { method: 'POST' }); selected.delete(f.id);
    await loadAll(); render(); updateMeter(); toast('Fichier restauré', 'ok'); }
  catch (e) { console.error('Error:', e.message); toast('Échec', 'err'); }
}
async function purgeOne(f) {
  if (!confirm(`Supprimer définitivement « ${f.name} » ? Action irréversible.`)) return;
  try { await api('/api/files/' + f.id, { method: 'DELETE' }); selected.delete(f.id);
    await loadAll(); render(); updateMeter(); toast('Supprimé définitivement', 'ok'); }
  catch (e) { console.error('Error:', e.message); toast('Échec', 'err'); }
}
async function emptyTrash() {
  const victims = entries.filter(e => e.deletedAt);
  if (!victims.length) return;
  if (!confirm(`Supprimer définitivement ${victims.length} élément${victims.length>1?'s':''} de la corbeille ? Action irréversible.`)) return;
  try {
    for (const v of victims) await api('/api/files/' + v.id, { method: 'DELETE' });
    selected.clear(); await loadAll(); render(); updateMeter(); toast('Corbeille vidée', 'ok');
  } catch (e) { console.error('Error:', e.message); toast('Échec', 'err'); }
}

// --- sélection multiple + actions groupées ----------------------------------
function updateBulkBar() {
  const bar = $('bulk-bar');
  if (!selected.size) { bar.classList.add('hidden'); return; }
  bar.classList.remove('hidden');
  $('bulk-count').textContent = `${selected.size} sélectionné${selected.size>1?'s':''}`;
  const inTrash = nav === 'trash';
  $('bulk-move').classList.toggle('hidden', inTrash);
  $('bulk-trash').classList.toggle('hidden', inTrash);
  $('bulk-restore').classList.toggle('hidden', !inTrash);
  $('bulk-purge').classList.toggle('hidden', !inTrash);
}
function selectedEntries() { return entries.filter(e => selected.has(e.id)); }
function clearSelection() { selected.clear(); render(); }
async function bulkTrash() {
  for (const f of selectedEntries()) await api('/api/files/' + f.id + '/trash', { method: 'POST' });
  selected.clear(); await loadAll(); render(); updateMeter(); toast('Déplacés vers la corbeille', 'ok');
}
async function bulkRestore() {
  for (const f of selectedEntries()) await api('/api/files/' + f.id + '/restore', { method: 'POST' });
  selected.clear(); await loadAll(); render(); updateMeter(); toast('Fichiers restaurés', 'ok');
}
async function bulkPurge() {
  const items = selectedEntries();
  if (!confirm(`Supprimer définitivement ${items.length} élément${items.length>1?'s':''} ? Action irréversible.`)) return;
  for (const f of items) await api('/api/files/' + f.id, { method: 'DELETE' });
  selected.clear(); await loadAll(); render(); updateMeter(); toast('Supprimés définitivement', 'ok');
}
// Déplacement groupé : fichiers uniquement (les dossiers se déplacent depuis
// leur propre menu, cf. moveDialog). Ignore silencieusement les collisions de
// nom individuelles pour ne pas bloquer tout le lot.
function bulkMoveDialog() {
  const items = selectedEntries();
  const back = el('div', 'modal-back'); const m = el('div', 'modal');
  m.innerHTML = `<h3>Déplacer ${items.length} fichier${items.length>1?'s':''}</h3>`;
  const box = el('div', 'move-list');
  const dests = [''].concat(allFolderPaths());
  for (const d of dests) {
    const b = el('button', 'move-item');
    const label = d === '' ? 'Mes fichiers' : d.split('/').join(' / ');
    b.innerHTML = iconSVG('folder', 'ico') + `<span>${escapeHtml(label)}</span>`;
    b.onclick = async () => {
      back.remove();
      let moved = 0, skipped = 0;
      for (const item of items) {
        if (childNamesAt(d).has(item.name)) { skipped++; continue; }
        try { await rePath(item, d ? d + '/' + item.name : item.name); moved++; }
        catch { skipped++; }
      }
      selected.clear(); await loadAll(); render(); updateMeter();
      toast(skipped ? `${moved} déplacé(s), ${skipped} ignoré(s) (collision de nom)` : `${moved} fichier(s) déplacé(s)`, skipped ? '' : 'ok');
    };
    box.appendChild(b);
  }
  const cancel = el('button', 'btn btn-ghost'); cancel.textContent = 'Annuler'; cancel.onclick = () => back.remove();
  const actions = el('div', 'modal-actions'); actions.appendChild(cancel);
  m.appendChild(box); m.appendChild(actions); back.appendChild(m);
  back.onclick = (e) => { if (e.target === back) back.remove(); };
  document.body.appendChild(back);
}

// --- déplacement entre dossiers --------------------------------------------
// Un « dossier » n'est qu'un préfixe de chemin chiffré : déplacer = re-chiffrer
// le nom avec un nouveau préfixe parent (même id/DEK/chunks). Pour un dossier, on
// re-pathue son marqueur ET tous ses descendants, comme pour le renommage.

// Tous les chemins de dossiers existants (marqueurs ET dossiers implicites
// déduits des chemins de fichiers), sans slash final.
function allFolderPaths() {
  const set = new Set();
  for (const e of entries) {
    const parts = e.path.split('/');
    const upto = e.isFolder ? parts.length : parts.length - 1; // ancêtres = dossiers
    for (let i = 1; i <= upto; i++) set.add(parts.slice(0, i).join('/'));
  }
  set.delete('');
  return [...set].sort((a, b) => a.localeCompare(b));
}
// Noms des enfants directs d'un dossier (pour détecter une collision de nom).
function childNamesAt(folderPath) {
  const pre = folderPath ? folderPath + '/' : '';
  const set = new Set();
  for (const e of entries) {
    if (!e.path.startsWith(pre)) continue;
    const rest = e.path.slice(pre.length);
    if (rest === '') continue;
    set.add(rest.split('/')[0]);
  }
  return set;
}

function moveDialog(item, isFolder) {
  const name = item.name;
  // dossier parent actuel : pour un dossier on est dans cwd ; pour un fichier on
  // le déduit de son chemin (robuste même en vue « Récents » où cwd est vide).
  const curParent = isFolder ? cwd.join('/') : item.path.split('/').slice(0, -1).join('/');
  const selfPath = isFolder ? (cwdPrefix() + name) : null;

  const dests = [''].concat(allFolderPaths()).filter(d => {
    if (d === curParent) return false;                                   // déjà ici
    if (isFolder && (d === selfPath || d.startsWith(selfPath + '/'))) return false; // dans soi-même
    return true;
  });

  const back = el('div', 'modal-back'); const m = el('div', 'modal');
  m.innerHTML = `<h3>Déplacer « ${escapeHtml(name)} »</h3>`;
  const box = el('div', 'move-list');
  if (!dests.length) {
    const p = el('p', 'modal-text'); p.textContent = 'Aucun autre dossier de destination disponible.';
    box.appendChild(p);
  }
  for (const d of dests) {
    const b = el('button', 'move-item');
    const label = d === '' ? 'Mes fichiers' : d.split('/').join(' / ');
    b.innerHTML = iconSVG('folder', 'ico') + `<span>${escapeHtml(label)}</span>`;
    b.onclick = async () => {
      if (childNamesAt(d).has(name)) {
        toast(`« ${name} » existe déjà dans ce dossier.`, 'err'); return;
      }
      back.remove();
      try { await doMove(item, isFolder, d); toast('Déplacé', 'ok'); }
      catch (e) { console.error('Move error:', e.message); toast('Échec du déplacement', 'err'); }
    };
    box.appendChild(b);
  }
  const cancel = el('button', 'btn btn-ghost'); cancel.textContent = 'Annuler'; cancel.onclick = () => back.remove();
  const actions = el('div', 'modal-actions'); actions.appendChild(cancel);
  m.appendChild(box); m.appendChild(actions); back.appendChild(m);
  back.onclick = (e) => { if (e.target === back) back.remove(); };
  document.body.appendChild(back);
}

async function doMove(item, isFolder, dest) {
  const name = item.name;
  if (isFolder) {
    await rePathSubtree(cwdPrefix() + name, dest ? dest + '/' + name : name);
  } else {
    await rePath(item, dest ? dest + '/' + name : name);
  }
  await loadAll(); render(); updateMeter();
}

// --- compteurs --------------------------------------------------------------
function updateMeter() {
  const files = entries.filter(e => !e.isFolder);
  const total = files.reduce((s, f) => s + f.size, 0);
  $('vm-size').textContent = humanSize(total);
  $('vm-count').textContent = `${files.length} fichier${files.length>1?'s':''}`;
  const pct = Math.min(100, total / (5 * 1024**3) * 100);   // jauge indicative sur 5 Go
  $('vm-fill').style.width = pct + '%';
}

// --- modale & toasts --------------------------------------------------------
function modalPrompt(title, value, onOk) {
  const back = $('modal'); $('modal-title').textContent = title;
  const input = $('modal-input'); input.value = value || ''; $('modal-error').textContent = '';
  back.classList.remove('hidden'); input.focus(); input.select();
  const ok = $('modal-ok'), cancel = $('modal-cancel');
  const close = () => { back.classList.add('hidden'); ok.onclick = cancel.onclick = input.onkeydown = null; };
  const submit = async () => {
    const v = input.value.trim();
    if (!v) { $('modal-error').textContent = 'Le nom ne peut pas être vide.'; return; }
    if (v.includes('/')) { $('modal-error').textContent = 'Le caractère « / » n\'est pas autorisé.'; return; }
    close(); try { await onOk(v); } catch (e) { console.error('Error:', e.message); toast('Échec', 'err'); }
  };
  ok.onclick = submit; cancel.onclick = close;
  input.onkeydown = (e) => { if (e.key === 'Enter') submit(); if (e.key === 'Escape') close(); };
}
function toast(msg, kind = '', ms) {
  const t = el('div', 'toast ' + kind);
  const icon = kind === 'ok' ? '<path d="m5 12 5 5 9-9"/>' : kind === 'err' ? '<path d="M12 8v5M12 16h.01"/><circle cx="12" cy="12" r="9"/>' : '<circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/>';
  t.innerHTML = `<svg class="ic" viewBox="0 0 24 24">${icon}</svg><span>${escapeHtml(msg)}</span>`;
  $('toasts').appendChild(t);
  setTimeout(() => t.remove(), ms ?? (kind === 'err' ? 4500 : 2600));
}
// toast persistant avec texte mis à jour (progression d'upload/download)
function progressToast(label) {
  const t = el('div', 'toast');
  t.innerHTML = `<svg class="ic spin" viewBox="0 0 24 24"><path d="M12 3a9 9 0 1 0 9 9"/></svg><span></span>`;
  const span = t.querySelector('span'); span.textContent = label;
  $('toasts').appendChild(t);
  return { update: (m) => { span.textContent = m; }, done: () => t.remove() };
}

// --- utils ------------------------------------------------------------------
function humanSize(n) { const u=['o','Ko','Mo','Go','To']; let i=0; while(n>=1024&&i<u.length-1){n/=1024;i++;} return `${n.toFixed(i?1:0)} ${u[i]}`; }
function fmtDate(s) { const d=new Date(s); return d.toLocaleDateString('fr-FR',{day:'2-digit',month:'short',year:'numeric'}); }
function escapeHtml(s){ return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// --- wiring -----------------------------------------------------------------
window.addEventListener('DOMContentLoaded', () => {
  // Après une connexion réussie (seed OU clé matérielle) : affiche le coffre.
  async function afterLogin() {
    $('auth').classList.add('hidden'); $('app').classList.remove('hidden');
    $('fingerprint').textContent = fingerprint(identity.pubHex);
    await loadAll(); render(); updateMeter();
    // Coffre fraîchement créé + clé matérielle possible : encart d'accueil qui
    // propose d'enrôler une clé pour ne plus saisir la seed.
    if (seedJustGenerated && WA.webauthnAvailable() && !$('enroll-key').classList.contains('hidden')) {
      $('key-modal').classList.remove('hidden');
    }
    seedJustGenerated = false;
  }

  $('gen').onclick = () => {
    $('seed').value = C.newMnemonic(256); // 256 bits = 24 mots (sécurité renforcée)
    seedJustGenerated = true;
    const st = $('auth-status'); st.className = 'auth-status';
    st.textContent = WA.webauthnAvailable()
      ? 'Notez ces 12 mots et conservez-les hors ligne : c\'est votre seule récupération. '
        + 'Ouvrez le coffre, puis ajoutez une clé de sécurité pour ne plus jamais saisir votre seed ici.'
      : 'Notez ces 12 mots et conservez-les hors ligne : c\'est votre seule récupération.';
  };
  // Toute saisie manuelle annule l'invitation (la seed n'a pas été générée ici).
  $('seed').oninput = () => { seedJustGenerated = false; };
  $('connect').onclick = async () => {
    const st = $('auth-status'); st.className = 'auth-status'; st.textContent = 'Ouverture…';
    try { await connect($('seed').value); await afterLogin(); st.textContent = ''; }
    catch (e) { st.className = 'auth-status err'; st.textContent = e.message; }
  };
  $('seed').onkeydown = (e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) $('connect').click(); };

  // Déverrouillage par clé matérielle (affiché seulement si WebAuthn dispo).
  if (WA.webauthnAvailable()) {
    $('key-unlock-wrap').classList.remove('hidden');
    $('enroll-key').classList.remove('hidden');
    $('unlock-key').onclick = async () => {
      const st = $('auth-status'); st.className = 'auth-status'; st.textContent = 'Touchez votre clé…';
      try { await connectWithKey(); await afterLogin(); st.textContent = ''; }
      catch (e) { st.className = 'auth-status err'; st.textContent = e.message; }
    };
    // Enrôlement partagé entre le bouton latéral et l'encart d'accueil.
    const doEnroll = async () => {
      $('enroll-key').classList.remove('pulse');
      try { await enrollKey(); toast('Clé de sécurité ajoutée — vous pourrez ouvrir ce coffre sans saisir la seed.', 'ok', 5000); }
      catch (e) { console.error('Enrollment error:', e.message); toast('Échec de l\'enrôlement', 'err'); }
    };
    $('enroll-key').onclick = doEnroll;

    // Encart d'accueil : « maintenant » lance l'enrôlement, « plus tard » ferme
    // et laisse le bouton pulser comme rappel discret. Clic hors carte = plus tard.
    const closeKeyModal = () => $('key-modal').classList.add('hidden');
    const later = () => { closeKeyModal(); $('enroll-key').classList.add('pulse'); };
    $('key-now').onclick = () => { closeKeyModal(); doEnroll(); };
    $('key-later').onclick = later;
    $('key-modal').onclick = (e) => { if (e.target === $('key-modal')) later(); };
  }

  // tiroir latéral (mobile) : la barre latérale coulisse, un fond la ferme.
  const sidebar = document.querySelector('.sidebar');
  const backdrop = $('sidebar-backdrop');
  const closeNav = () => { sidebar.classList.remove('open'); backdrop.classList.remove('show'); };
  const toggleNav = () => {
    const open = sidebar.classList.toggle('open');
    backdrop.classList.toggle('show', open);
  };
  $('menu-btn').onclick = (e) => { e.stopPropagation(); toggleNav(); };
  backdrop.onclick = closeNav;

  $('lock').onclick = async () => {
    closeNav();
    // Révoque la session côté serveur (best-effort) avant d'oublier le token,
    // pour qu'un token éventuellement exfiltré ne reste pas valide 12 h.
    try { if (token) await api('/api/logout', { method: 'POST' }); } catch {}
    clearTimeout(sessionTimer); sessionTimer = null;
    if (thumbObserver) { thumbObserver.disconnect(); thumbObserver = null; }
    for (const url of thumbCache.values()) URL.revokeObjectURL(url);
    thumbCache.clear();
    identity = null; token = null; masterKey = null; entries = []; cwd = []; query = '';
    selected.clear(); nav = 'files'; sortBy = 'name'; sortDir = 'asc';
    $('seed').value = ''; $('app').classList.add('hidden'); $('auth').classList.remove('hidden');
  };

  // menu Nouveau
  const menu = $('new-menu');
  $('new-btn').onclick = (e) => { e.stopPropagation(); menu.classList.toggle('hidden'); };
  document.addEventListener('click', () => menu.classList.add('hidden'));
  menu.querySelectorAll('button').forEach(b => b.onclick = () => {
    menu.classList.add('hidden'); closeNav();
    if (b.dataset.act === 'import') $('file').click();
    else modalPrompt('Nouveau dossier', '', (name) => createFolder(name));
  });
  $('file').onchange = (ev) => { if (ev.target.files.length) uploadFiles([...ev.target.files]); ev.target.value=''; };

  // navigation latérale
  document.querySelectorAll('[data-view-nav]').forEach(b => b.onclick = () => {
    document.querySelectorAll('[data-view-nav]').forEach(x => x.classList.remove('active'));
    b.classList.add('active'); nav = b.dataset.viewNav; cwd = []; query=''; $('search').value=''; selected.clear(); render();
    closeNav();
  });

  // vues + recherche
  $('view-grid').onclick = () => setView('grid');
  $('view-list').onclick = () => setView('list');
  $('search').oninput = (e) => { query = e.target.value.trim(); render(); };

  // tri (vue « Mes fichiers »)
  $('sort-by').onchange = (e) => { sortBy = e.target.value; render(); };
  $('sort-dir').onclick = () => {
    sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    $('sort-dir').classList.toggle('desc', sortDir === 'desc');
    render();
  };

  // corbeille
  $('empty-trash').onclick = emptyTrash;

  // sélection multiple : barre d'actions groupées
  $('bulk-move').onclick = bulkMoveDialog;
  $('bulk-trash').onclick = bulkTrash;
  $('bulk-restore').onclick = bulkRestore;
  $('bulk-purge').onclick = bulkPurge;
  $('bulk-clear').onclick = clearSelection;

  // thème (clair/sombre/auto), persistant
  const THEME_ORDER = ['auto', 'light', 'dark'];
  const THEME_LABEL = { auto: 'Auto', light: 'Clair', dark: 'Sombre' };
  function applyTheme(pref) {
    if (pref === 'auto') delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = pref;
    localStorage.setItem('p2pfs-theme', pref);
    $('theme-label').textContent = THEME_LABEL[pref];
  }
  applyTheme(THEME_ORDER.includes(localStorage.getItem('p2pfs-theme')) ? localStorage.getItem('p2pfs-theme') : 'auto');
  $('theme-btn').onclick = () => {
    const cur = localStorage.getItem('p2pfs-theme') || 'auto';
    applyTheme(THEME_ORDER[(THEME_ORDER.indexOf(cur) + 1) % THEME_ORDER.length]);
  };

  // raccourcis clavier (uniquement coffre ouvert, hors saisie de texte)
  document.addEventListener('keydown', (e) => {
    if ($('app').classList.contains('hidden')) return;
    const tag = document.activeElement?.tagName;
    const typing = tag === 'INPUT' || tag === 'TEXTAREA' || document.activeElement?.isContentEditable;
    if (e.key === 'Escape') {
      if (!$('preview-modal').classList.contains('hidden')) { $('preview-close').click(); return; }
      if (selected.size) { clearSelection(); return; }
    }
    if (typing) return;
    if (e.key === '/') { e.preventDefault(); $('search').focus(); }
    else if ((e.key === 'Delete' || e.key === 'Backspace') && selected.size) {
      e.preventDefault();
      nav === 'trash' ? bulkPurge() : bulkTrash();
    } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'a') {
      e.preventDefault();
      const { fileList } = currentItems();
      fileList.forEach(f => selected.add(f.id));
      render();
    }
  });

  // glisser-déposer (fichiers ET dossiers entiers, via webkitGetAsEntry)
  const ov = $('drop-overlay'); let depth = 0;
  const content = document.querySelector('.content');
  content.addEventListener('dragenter', (e) => { e.preventDefault(); if (++depth === 1) ov.classList.remove('hidden'); });
  content.addEventListener('dragover', (e) => e.preventDefault());
  content.addEventListener('dragleave', () => { if (--depth <= 0) { depth=0; ov.classList.add('hidden'); } });
  content.addEventListener('drop', async (e) => {
    e.preventDefault(); depth = 0; ov.classList.add('hidden');
    const items = e.dataTransfer.items;
    const entriesApi = items && [...items].map(it => it.webkitGetAsEntry && it.webkitGetAsEntry()).filter(Boolean);
    if (entriesApi && entriesApi.some(en => en.isDirectory)) {
      const out = [];
      for (const en of entriesApi) await traverseEntry(en, '', out);
      if (out.length) uploadFiles(out);
    } else if (e.dataTransfer.files.length) {
      uploadFiles([...e.dataTransfer.files]);
    }
  });
});

// Traverse récursivement une DataTransferItem (fichier ou dossier déposé) et
// accumule des { file, fullPath } dans `out`, chemin relatif préservé. Un
// dossier déposé n'a pas besoin de marqueur explicite : dès qu'un fichier
// existe sous ce chemin, le dossier apparaît (déduit), comme partout ailleurs.
async function traverseEntry(entry, basePath, out) {
  if (entry.isFile) {
    const file = await new Promise((res, rej) => entry.file(res, rej));
    out.push({ file, fullPath: basePath + entry.name });
  } else if (entry.isDirectory) {
    const reader = entry.createReader();
    // readEntries() ne renvoie qu'un lot (≤100) : il faut le rappeler jusqu'à
    // un tableau vide pour tout obtenir (particularité de l'API).
    let batch = await new Promise((res, rej) => reader.readEntries(res, rej));
    while (batch.length) {
      for (const child of batch) await traverseEntry(child, basePath + entry.name + '/', out);
      batch = await new Promise((res, rej) => reader.readEntries(res, rej));
    }
  }
}
function setView(v){ view=v; $('view-grid').classList.toggle('active',v==='grid'); $('view-list').classList.toggle('active',v==='list'); render(); }
function fingerprint(hex){ return hex.slice(0,12).match(/.{1,2}/g).join(':') + '…'; }
