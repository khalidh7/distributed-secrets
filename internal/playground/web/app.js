'use strict';
const $ = (id) => document.getElementById(id);
let clusterMode = false;
let mode = 'create', busy = false, recovery = null, lastRun = null, playbackID = 0;
const stageNodes = ['node-client', 'node-auth', 'node-crypto', 'node-storage', 'node-client'];
const flows = {
  create: [
    ['Create requested', 'The new credential is submitted over verified HTTPS.'],
    ['Identity & policy checked', 'The operator token is authenticated and create permission is evaluated.'],
    ['A fresh key is generated', 'AES-256-GCM encrypts the credential with a new DEK, which is wrapped by the KEK.'],
    ['Encrypted command committed', 'Raft persists the command to a majority before applying version 1.'],
    ['Credential created', 'The service returns only path, version, and timestamp metadata.']
  ],
  update: [
    ['Update requested', 'The replacement credential is submitted to the same path.'],
    ['Identity & policy checked', 'The token and path policy are evaluated again.'],
    ['A new envelope is created', 'A fresh DEK and nonce protect the new value; the old ciphertext remains immutable.'],
    ['New version committed', 'Raft orders and commits the encrypted mutation across the cluster.'],
    ['Credential updated', 'The update is visible as a new immutable version.']
  ],
  delete: [
    ['Delete requested', 'The client requests deletion of the latest credential version.'],
    ['Delete permission checked', 'The operator identity and delete capability are verified.'],
    ['Tombstone prepared', 'The service prepares a deletion mutation; historical ciphertext is retained.'],
    ['Tombstone committed', 'Raft replicates and commits the delete marker to a majority.'],
    ['Credential deleted', 'Future reads return gone while version metadata proves the deletion persisted.']
  ],
  write: [
    ['Request received', 'Your JSON payload travels from the local proxy to the service over verified HTTPS.'],
    ['Identity & policy checked', 'The service authenticates your bearer token and checks create permission for this secret path.'],
    ['A fresh key for every version', 'A random 256-bit DEK encrypts the JSON with AES-GCM. The vault’s KEK wraps the DEK. Path and version are bound to the ciphertext.'],
    ['Encrypted record persisted', 'The service persists the ciphertext, wrapped data key, and version metadata to the local store. Plaintext values are not written to disk.'],
    ['Write confirmed', 'The API returned success. This secret now has a new immutable version.']
  ],
  read: [
    ['Read requested', 'The service receives the secret path and optional version over HTTPS.'],
    ['Read access checked', 'The bearer token identifies the caller. Path policies decide whether this identity can read the secret.'],
    ['Encrypted version loaded', 'The store selects the requested version, or the latest available version when none is specified.'],
    ['Keys unwrapped in memory', 'The KEK unwraps the version’s DEK. AES-GCM verifies and decrypts the payload using the original path and version.'],
    ['Secret returned', 'The decrypted JSON is returned over HTTPS. You can inspect it in the service response below.']
  ],
  history: [
    ['Metadata requested', 'The client asks for the version history of this secret path.'],
    ['Read access checked', 'The service checks the token and read permission for this path.'],
    ['Version history loaded', 'The store looks up the versioned records associated with the secret path.'],
    ['Version metadata collected', 'The metadata API returns version numbers and timestamps, with encrypted envelope fields redacted. It does not decrypt secret values.'],
    ['History returned', 'Inspect the exact version records in the service response below.']
  ]
};
async function api(path, method = 'GET', body, authorized = true, refreshSession = true) {
  const headers = { 'Accept': 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (authorized && $('token').value.trim()) headers.Authorization = `Bearer ${$('token').value.trim()}`;
  const start = performance.now();
  const response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store', signal: AbortSignal.timeout(35000) });
  if (response.status === 401 && clusterMode && authorized && refreshSession) {
    const session = await api('/playground/session', 'GET', undefined, false, false);
    if (session.ok && session.data.unlocked && session.data.token && session.data.token !== $('token').value.trim()) {
      $('token').value = session.data.token;
      return api(path, method, body, authorized, false);
    }
  }
  const raw = await response.text();
  let data;
  try { data = raw ? JSON.parse(raw) : null; } catch { data = { error: raw || 'Unexpected server response' }; }
  return { ok: response.ok, status: response.status, data, duration: Math.round(performance.now() - start), id: response.headers.get('X-Request-ID'), node: response.headers.get('X-Playground-Node') };
}
function message(text, error = false) { $('form-message').textContent = text; $('form-message').classList.toggle('error', error); }
async function refreshStatus() {
  if (clusterMode) return;
  try {
    const result = await api('/v1/sys/seal-status', 'GET', undefined, false);
    if (!result.ok) throw new Error(result.data?.error || 'Service unavailable');
    const state = result.data;
    $('connection').textContent = state.sealed ? 'Service connected · sealed' : 'Service connected';
    $('connection').className = 'connection online';
    $('vault-status').textContent = !state.initialized ? 'Not initialized' : state.sealed ? `Sealed · ${state.progress}/${state.threshold}` : 'Unsealed';
    $('initialize').hidden = state.initialized;
    $('unseal-fields').hidden = !state.initialized || !state.sealed;
    $('setup-hint').textContent = !state.initialized ? 'Initialize this local vault with 5 recovery shares and a threshold of 3. Your new token will fill in automatically.' : state.sealed ? `Submit ${state.threshold} distinct shares to unlock the vault. ${state.progress} received.` : 'The vault is open. Paste an existing access token above, or use the token from initialization.';
    if (!state.initialized || state.sealed) $('vault-tools').open = true;
    if (!lastRun && !busy) message(!state.initialized ? 'Initialize the vault below to get started.' : state.sealed ? 'Unseal the vault below to continue.' : 'Ready.');
  } catch (err) {
    $('connection').textContent = 'Service unavailable'; $('connection').className = 'connection offline';
    $('vault-status').textContent = 'Offline';
    if (!busy) message(err.message, true);
  }
}
function setBusy(value) {
  busy = value;
  document.querySelectorAll('#request-form button, .tab, #initialize, #unseal').forEach(button => button.disabled = value);
}
function resetAnimation() {
  playbackID++;
  document.querySelectorAll('.flow-node, .crypto-box, .connector, .timeline span').forEach(node => node.classList.remove('active', 'done'));
}
async function animate(operation, result) {
  resetAnimation();
  const thisPlayback = playbackID;
  $('replay').disabled = true;
  const nodes = ['write', 'create', 'update'].includes(operation) ? stageNodes : ['node-client', 'node-auth', 'node-storage', operation === 'read' ? 'node-crypto' : 'node-storage', 'node-client'];
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  for (let step = 0; step < 5; step++) {
    if (playbackID !== thisPlayback) return;
    document.querySelectorAll('.flow-node, .crypto-box, .connector').forEach(node => node.classList.remove('active'));
    $(nodes[step]).classList.add('active');
    $(nodes[step]).classList.add('done');
    if (step < 3) $(`link-${step}`).classList.add('active');
    document.querySelectorAll('.timeline span').forEach((node, index) => node.classList.toggle('active', index <= step));
    $('step-number').textContent = String(step + 1).padStart(2, '0');
    $('step-title').textContent = flows[operation][step][0];
    $('step-detail').textContent = flows[operation][step][1];
    $('animation-state').textContent = `PLAYBACK · STEP ${step + 1} / 5`;
    $('cipher').textContent = step >= 2 ? 'a7f2 · 9c4e · b081' : '•••• •••• •••• ••••';
    $('payload-label').textContent = operation === 'write' ? 'ILLUSTRATIVE CIPHERTEXT' : operation === 'read' ? 'DECRYPT IN MEMORY' : 'ENCRYPTED METADATA';
    if (!reduced) await new Promise(resolve => setTimeout(resolve, 1000 / Number($('speed').value)));
  }
  if (playbackID !== thisPlayback) return;
  document.querySelectorAll('.connector, .flow-node, .crypto-box').forEach(node => node.classList.remove('active'));
  $('animation-state').textContent = 'PLAYBACK COMPLETE';
  $('saved-version').textContent = ['write', 'create', 'update'].includes(operation) ? `v${result.data.version}` : operation === 'delete' ? 'TOMBSTONE' : 'DISK';
  $('replay').disabled = false;
}
function selectMode(next) {
  mode = next; resetAnimation();
  document.querySelectorAll('.tab').forEach(tab => { tab.classList.toggle('selected', tab.dataset.mode === mode); tab.setAttribute('aria-selected', String(tab.dataset.mode === mode)); });
  $('write-fields').hidden = !['create', 'update', 'write'].includes(mode);
  $('read-fields').hidden = mode !== 'read';
  $('version').disabled = mode !== 'read';
  document.querySelectorAll('#pairs input').forEach(input => input.required = ['create', 'update', 'write'].includes(mode));
  $('submit').firstElementChild.textContent = { create: 'Create credential', update: 'Save new version', read: 'Read & decrypt', delete: 'Delete credential', write: 'Encrypt & save', history: 'View versions' }[mode];
  $('submit').classList.toggle('delete-action', mode === 'delete');
  $('flow-title').textContent = { create: 'CREATE', update: 'UPDATE', delete: 'DELETE', write: 'WRITE', read: 'READ', history: 'VERSION HISTORY' }[mode];
  const labels = ['create', 'update', 'write'].includes(mode) ? ['Request', 'Authorize', 'Encrypt', 'Commit', 'Respond'] : mode === 'delete' ? ['Request', 'Authorize', 'Tombstone', 'Commit', 'Respond'] : ['Request', 'Authorize', 'Load', mode === 'read' ? 'Decrypt' : 'Collect', 'Respond'];
  document.querySelectorAll('.timeline span').forEach((node, i) => node.textContent = labels[i]);
  $('step-number').textContent = '○'; $('step-title').textContent = 'No operation selected';
  $('step-detail').textContent = '';
  $('animation-state').textContent = 'IDLE'; $('replay').disabled = true;
}
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => selectMode(tab.dataset.mode));
  tab.addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
    event.preventDefault();
    const tabs = [...document.querySelectorAll('.tab')], index = tabs.indexOf(tab);
    const direction = event.key === 'ArrowRight' ? 1 : tabs.length - 1;
    const next = tabs[(index + direction) % tabs.length];
    next.focus(); selectMode(next.dataset.mode);
  });
});
$('add-field').addEventListener('click', () => {
  const row = document.querySelector('.pair').cloneNode(true);
  row.querySelectorAll('input').forEach(input => { input.value = ''; input.removeAttribute('id'); });
  $('pairs').append(row); row.querySelector('input').focus();
});
$('pairs').addEventListener('click', event => {
  if (event.target.closest('.remove-pair') && $('pairs').children.length > 1) event.target.closest('.pair').remove();
});
$('request-form').addEventListener('submit', async event => {
  event.preventDefault(); if (busy) return;
  const path = $('path').value.trim().replace(/^\/+|\/+$/g, '');
  if (!path || path.split('/').some(part => part === '.' || part === '..' || !part)) return message('Enter a path with non-empty segments, such as sandbox/payments.', true);
  if (!$('token').value.trim()) return message('Initialize the vault or enter an access token first.', true);
  let body;
  if (['create', 'update', 'write'].includes(mode)) {
    body = Object.create(null);
    for (const pair of $('pairs').children) {
      const [key, value] = pair.querySelectorAll('input');
      if (!key.value.trim()) return message('Each field needs a key.', true);
      if (Object.hasOwn(body, key.value.trim())) return message('Use a unique name for each key.', true);
      body[key.value.trim()] = value.value;
    }
  }
  let endpoint = `/v1/${mode === 'history' ? 'metadata' : 'secrets'}/${path.split('/').map(encodeURIComponent).join('/')}`;
  if (mode === 'read' && $('version').value) endpoint += `?version=${encodeURIComponent($('version').value)}`;
  const method = ['create', 'update', 'write'].includes(mode) ? 'PUT' : mode === 'delete' ? 'DELETE' : 'GET', operation = mode;
  resetAnimation(); setBusy(true); $('replay').disabled = true; message('Sending request to the service…');
  $('animation-state').textContent = 'AWAITING API RESPONSE';
  $('request-method').textContent = `${method} ${endpoint}`;
  try {
    const result = await api(endpoint, method, body);
    $('response').textContent = result.data === null ? '// 204 No Content — deletion committed' : JSON.stringify(result.data, null, 2);
    $('response-meta').textContent = `HTTP ${result.status} · ${result.duration} MS`;
    $('request-id').textContent = result.id ? `request ${result.id}` : '';
    $('response-description').textContent = result.ok ? (result.node ? `Response from ${result.node}.` : 'Response from the secrets service.') : 'The request failed. No successful flow is shown.';
    if (!result.ok) throw new Error(result.data?.error || `Request failed (HTTP ${result.status})`);
    lastRun = { operation, result };
    message(['create', 'update', 'write'].includes(operation) ? `Version ${result.data.version} saved.` : operation === 'delete' ? 'Delete tombstone committed through Raft.' : 'Request succeeded.');
    if (!clusterMode) await animate(operation, result);
    message(['create', 'update', 'write'].includes(operation) ? `Version ${result.data.version} saved.` : operation === 'delete' ? 'Credential deleted.' : 'Request complete.');
    window.dispatchEvent(new CustomEvent('credential-operation', { detail: { operation, result, path } }));
  } catch (err) {
    message(err.message, true);
    $('animation-state').textContent = 'REQUEST FAILED'; $('step-number').textContent = '!';
    $('step-title').textContent = 'Request could not complete'; $('step-detail').textContent = err.message;
    if (err.name === 'TypeError' || err.name === 'TimeoutError') {
      $('response').textContent = JSON.stringify({ error: err.message }, null, 2); $('response-meta').textContent = 'NETWORK ERROR';
    }
  } finally { setBusy(false); await refreshStatus(); }
});
$('replay').addEventListener('click', async () => { if (!lastRun || busy) return; setBusy(true); await animate(lastRun.operation, lastRun.result); setBusy(false); });
$('initialize').addEventListener('click', async () => {
  if (busy) return; setBusy(true); $('setup-message').textContent = 'Initializing…';
  try {
    const result = await api('/v1/sys/init', 'POST', { shares: 5, threshold: 3 }, false);
    if (!result.ok) throw new Error(result.data?.error || 'Initialization failed');
    recovery = result.data; $('token').value = recovery.root_token;
    $('recovery-data').textContent = JSON.stringify(recovery, null, 2); $('recovery').hidden = false;
    $('setup-message').textContent = 'Vault initialized. Download your recovery kit before leaving this tab.';
    message('Vault ready. Write your first secret.');
  } catch (err) { $('setup-message').textContent = err.message; }
  finally { setBusy(false); await refreshStatus(); }
});
$('download-recovery').addEventListener('click', () => {
  if (!recovery) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(recovery, null, 2)], { type: 'application/json' }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'distributed-secrets-recovery.json'; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$('unseal').addEventListener('click', async () => {
  if (busy || !$('share').value.trim()) return;
  setBusy(true);
  try {
    const result = await api('/v1/sys/unseal', 'POST', { key: $('share').value.trim() }, false);
    if (!result.ok) throw new Error(result.data?.error || 'Unseal failed');
    $('share').value = ''; $('setup-message').textContent = result.data.sealed ? `${result.data.progress} of ${result.data.threshold} shares received.` : 'Vault unsealed.';
  } catch (err) { $('setup-message').textContent = err.message; }
  finally { setBusy(false); await refreshStatus(); }
});
$('clear-response').addEventListener('click', () => { $('response').textContent = '// Response cleared.'; $('response-meta').textContent = 'CLEARED'; $('request-id').textContent = ''; $('request-method').textContent = 'WAITING FOR REQUEST'; $('response-description').textContent = 'The next API response will appear here.'; });
async function initializeSession() {
 try {
  const result = await api('/playground/session', 'GET', undefined, false);
  if (result.ok && result.data.mode === 'cluster') {
   clusterMode = true;
   if (result.data.token) $('token').value = result.data.token;
   window.dispatchEvent(new CustomEvent('cluster-ready', { detail: result.data }));
   return;
  }
 } catch {}
 await refreshStatus();
}
initializeSession();
setInterval(() => { if (!busy) refreshStatus(); }, 15000);
