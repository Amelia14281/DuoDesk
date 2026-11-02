// Security regressions run against real feature classes with native commands isolated.
'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');
const { createRequire } = require('module');
const { EventEmitter, once } = require('events');
const ROOT = path.resolve(__dirname, '../..');
const P = require('../protocol');
function load(file, mocks) {
  const filename = path.join(ROOT, file), mod = { exports: {} };
  const req = createRequire(filename);
  vm.runInThisContext('(function(require,module,exports){' + fs.readFileSync(filename, 'utf8') + '\n})', { filename })(
    (name) => Object.hasOwn(mocks, name) ? mocks[name] : req(name), mod, mod.exports);
  return mod.exports;
}
const tick = () => new Promise((r) => setImmediate(r));
function deferred() { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; }
function link() {
  const l = new EventEmitter();
  l.id = 'peer-a'; l.sent = []; l.send = (m) => l.sent.push(m);
  l.snapshot = () => ({ session: l.id ? { id: l.id } : null, paired: l.id ? { macId: l.id } : null, link: {} });
  return l;
}
function fixture(dir) {
  const l = link(), settings = { files: { acceptFromMac: true, shareOn: true }, terminal: { allowMac: true, installedKey: '' } };
  let fail = false, gate = null;
  const nativeCalls = [];
  const native = async (name, args) => {
    nativeCalls.push({ name, args });
    if (gate) await gate.promise;
    if (fail) throw new Error('administrator prompt cancelled');
    if (args.Result) fs.writeFileSync(args.Result, 'ok');
  };
  const mocks = {
    os: { ...os, homedir: () => dir, tmpdir: () => dir },
    electron: {
      app: { getPath: () => dir },
      safeStorage: { decryptString: (b) => b.toString(), encryptString: (s) => Buffer.from(s), isEncryptionAvailable: () => true },
      shell: { showItemInFolder() {} },
    },
    './fm': { at: async () => ({ folder: dir }) },
    './ps': { script: async () => '', scriptElevated: native },
    child_process: {
      execFile(cmd, args, opts, cb) { native(cmd, args).then(() => cb(null, '', ''), (e) => cb(e, '', e.message)); },
      spawn() { return { unref() {} }; },
    },
  };
  const opts = { link: l, settings, save() {}, onChange() {}, helper: { request: async () => ({ path: dir }) } };
  return { l, settings, mocks, opts, nativeCalls, fail(value) { fail = value; }, gate(value) { gate = value; } };
}
async function files(platform, dir) {
  const { l, mocks, opts } = fixture(dir);
  const Receiver = load(platform + '/filerecv.js', mocks), recv = new Receiver(opts);
  const sentinel = path.join(dir, 'outside.part'); fs.writeFileSync(sentinel, 'untouched');
  for (const id of ['../outside', '..\\outside', '/absolute', 'C:\\outside', 'name:stream', 'x'.repeat(512)]) {
    recv._offer({ id, name: 'hello.txt', size: 0, drop: 'release' });
    const f = recv.files.get(id);
    assert(f, 'opaque IDs remain supported');
    assert.equal(path.dirname(f.tmp), recv.dir, 'remote ID escaped incoming');
    assert.equal(fs.readFileSync(sentinel, 'utf8'), 'untouched');
    const closed = once(f.out, 'close'); recv._drop(id); await closed;
    assert(!fs.existsSync(f.tmp), 'cancel left temporary file');
  }
  // Both normal ordering variants still deliver a checksum-verified file.
  for (const releaseFirst of [true, false]) {
    const id = 'normal-' + releaseFirst, data = Buffer.from('hello');
    recv._offer({ id, name: id + '.txt', size: data.length, drop: 'release' });
    const f = recv.files.get(id), closed = once(f.out, 'close');
    if (releaseFirst) await recv.onRelease();
    recv._chunk({ id, seq: 0, data });
    recv._end({ id, sha256: crypto.createHash('sha256').update(data).digest('hex') });
    await closed;
    if (!releaseFirst) await recv.onRelease();
    assert.equal(fs.readFileSync(path.join(dir, id + '.txt'), 'utf8'), 'hello');
    assert(l.sent.some((m) => m.t === P.T.FILE_DONE && m.id === id && m.ok));
  }
  // Allocation errors refuse the transfer without accepting or truncating an existing file.
  const blocked = path.join(dir, 'not-a-directory'); fs.writeFileSync(blocked, 'keep'); recv.dir = blocked;
  recv._offer({ id: 'no-room', name: 'f', size: 0 });
  assert(l.sent.some((m) => m.t === P.T.FILE_REFUSE && m.id === 'no-room'));
  assert.equal(fs.readFileSync(blocked, 'utf8'), 'keep');
}
async function ssh(platform, dir) {
  const f = fixture(dir), { l, settings, mocks, opts } = f;
  const Sshd = load(platform + '/sshd.js', mocks);
  Sshd.prototype.refresh = async function () { this.service = 'running'; this.isAdmin = false; };
  Sshd.prototype._info = function (enabled, why, id) { if (!id || id === l.id) l.send({ enabled, why }); };
  const sshd = new Sshd(opts), keys = path.join(dir, '.ssh', 'authorized_keys'); fs.mkdirSync(path.dirname(keys));
  const manual = 'ssh-ed25519 MANUAL personal\n';
  const seed = () => fs.writeFileSync(keys, manual + 'ssh-ed25519 AAAA macshare:peer-a\nssh-ed25519 BBBB macshare:peer-b\n');
  seed(); settings.terminal.allowMac = false; await sshd.apply();
  assert.equal(fs.readFileSync(keys, 'utf8'), manual, 'offline Off left keys');
  seed(); settings.terminal.installedKey = ''; l.id = null;
  assert(await sshd.forget('peer-b'));
  assert.equal(fs.readFileSync(keys, 'utf8'), manual + 'ssh-ed25519 AAAA macshare:peer-a\n', 'unselected Forget changed another key');
  settings.terminal.allowMac = true; l.id = 'peer-a';
  await sshd._onKey({ pub: 'ssh-ed25519 CCCC comment' });
  assert(fs.readFileSync(keys, 'utf8').includes('CCCC macshare:peer-a'));
  settings.terminal.allowMac = false; await sshd.apply();
  assert.equal(fs.readFileSync(keys, 'utf8'), manual);
  settings.terminal.allowMac = true; await sshd.apply();
  assert(fs.readFileSync(keys, 'utf8').includes('CCCC macshare:peer-a'), 'local Off/On lost the session key');
  l.emit(P.T.SSH_FORGET); await sshd.keyWork;
  assert.equal(fs.readFileSync(keys, 'utf8'), manual);
  await sshd._onKey({ pub: 'ssh-ed25519 CCCC' });
  assert(fs.readFileSync(keys, 'utf8').includes('CCCC macshare:peer-a'), 'remote Off/On blocked a paired peer');
  // Protocol-valid opaque IDs must not prevent local Forget or revoke unrelated peers.
  fs.appendFileSync(keys, 'ssh-ed25519 LEGACY macshare:' + (platform === 'windows' ? 'peera' : 'peer:a') + '\n');
  l.id = 'peer:a'; l.emit(P.T.SSH_FORGET); await sshd.keyWork;
  assert(!fs.readFileSync(keys, 'utf8').includes('LEGACY'));
  assert(fs.readFileSync(keys, 'utf8').includes('CCCC macshare:peer-a'));
  assert(await sshd.forget('peer:a')); l.id = 'peer-a';
  // A delayed refresh cannot install after Off or bind a key to a newly selected peer.
  const refresh = deferred(); sshd.refresh = () => refresh.promise;
  const installing = sshd._onKey({ pub: 'ssh-ed25519 DDDD' }); await tick();
  settings.terminal.allowMac = false; const off = sshd.apply(); l.id = 'peer-c';
  refresh.resolve(); await Promise.all([installing, off]);
  assert.equal(fs.readFileSync(keys, 'utf8'), manual);
  // Off during a native write is followed by removal before the operation settles.
  settings.terminal.allowMac = true; l.id = 'peer-a'; sshd.refresh = Sshd.prototype.refresh;
  const realChange = sshd._changeKeys.bind(sshd), writing = deferred();
  sshd._changeKeys = async (id, line) => { if (line) await writing.promise; return realChange(id, line); };
  const adding = sshd._onKey({ pub: 'ssh-ed25519 EEEE' }); await tick();
  const forgetting = sshd.forget('peer-a'); writing.resolve(); await Promise.all([adding, forgetting]);
  assert.equal(fs.readFileSync(keys, 'utf8'), manual);
  await sshd._onKey({ pub: 'ssh-ed25519 FFFF' });
  assert.equal(fs.readFileSync(keys, 'utf8'), manual, 'forgotten session restored access');
  // A newly paired session can install again.
  l.emit('welcome'); await sshd._onKey({ pub: 'ssh-ed25519 GGGG' });
  assert(fs.readFileSync(keys, 'utf8').includes('GGGG macshare:peer-a'));
  sshd._changeKeys = async () => { throw new Error('permission denied'); };
  assert.equal(await sshd.forget('peer-a'), false);
  assert.match(sshd.message, /permission denied/);
}
async function smb(platform, dir) {
  const f = fixture(dir), { l, settings, mocks, opts } = f;
  const Smb = load(platform + '/smb.js', mocks); Smb.prototype.checkShare = async function () { this.sharePath = dir; };
  const smb = new Smb(opts); settings.files.shareFolder = dir;
  fs.writeFileSync(smb.credFile, JSON.stringify({ user: 'macshare', password: 'test-only' }));
  f.fail(true);
  assert.equal(await smb.setShareOn(false), false);
  assert(settings.files.shareOn && fs.existsSync(smb.credFile), 'failed cleanup lost retry state');
  assert.match(smb.message, /Could not revoke/);
  f.fail(false); assert(await smb.setShareOn(false));
  assert(!settings.files.shareOn && !fs.existsSync(smb.credFile));
  // Setup/Off are serialized; no credential offer can race a pending revocation.
  const gate = deferred(); f.gate(gate);
  const setup = smb.setShareOn(true); await tick();
  const off = smb.setShareOn(false); gate.resolve(); await Promise.all([setup, off]);
  assert(!settings.files.shareOn && !fs.existsSync(smb.credFile));
  assert(!l.sent.some((m) => m.t === P.T.SMB_OFFER));
  f.gate(null); await smb.setShareOn(true);
  assert(settings.files.shareOn && fs.existsSync(smb.credFile));
  assert(l.sent.some((m) => m.t === P.T.SMB_OFFER), 'ordinary sharing no longer offers credentials');
  // An Off while the share-path check is outstanding wins as well.
  const checking = deferred(); smb.checkShare = () => checking.promise;
  const offers = l.sent.filter((m) => m.t === P.T.SMB_OFFER).length;
  const enable = smb.setShareOn(true); await tick(); const disable = smb.setShareOn(false);
  checking.resolve(); await Promise.all([enable, disable]);
  assert(!settings.files.shareOn);
  assert.equal(l.sent.filter((m) => m.t === P.T.SMB_OFFER).length, offers);
  if (platform === 'linux') {
    const script = f.nativeCalls.find((c) => c.args[2] && c.args[2].includes('close-share')).args[2];
    assert(script.includes('set -e') && script.includes('close-share MacShare'));
    assert(!script.includes('|| true'), 'native failures suppressed');
  }
}
async function savedOff(platform, dir) {
  const f = fixture(dir), { settings, mocks, opts } = f;
  settings.files.shareOn = false;
  const Smb = load(platform + '/smb.js', mocks);
  Smb.prototype.checkShare = async function () { this.sharePath = dir; };
  fs.writeFileSync(path.join(dir, 'smb-share.bin'), '{"user":"macshare","password":"old"}');
  f.fail(true);
  const smb = new Smb(opts); await smb.shareWork;
  assert(settings.files.shareOn, 'legacy native access falsely displayed Off after failed cleanup');
  assert(fs.existsSync(smb.credFile) && /Could not revoke/.test(smb.message));
  f.fail(false); assert(await smb.setShareOn(false));
  assert(!settings.files.shareOn && !fs.existsSync(smb.credFile));
  fs.writeFileSync(smb.credFile, '{"user":"macshare","password":"old"}');
  const restarted = new Smb(opts); await restarted.shareWork;
  assert(!settings.files.shareOn && !fs.existsSync(smb.credFile), 'upgrade did not revoke saved-Off credentials');
}
async function forgetting(platform, dir) {
  for (const mode of ['', '/mesh']) {
    const { mocks } = fixture(dir), prefix = platform + mode;
    const Link = load(prefix + '/link.js', { ...mocks, ws: {} });
    const guest = Object.create(Link.prototype), gate = deferred();
    let removed = false;
    Object.assign(guest, { pairing: { macId: 'offline-peer' }, timers: {}, store: { clear() { removed = true; } },
      _closeSocket() {}, _setStatus() {}, revokeAccess: () => gate.promise });
    const pending = guest.forget(); assert(!removed); gate.resolve(false);
    assert.equal(await pending, false); assert(guest.pairing && !removed);
    guest.revokeAccess = async (id) => { assert.equal(id, 'offline-peer'); return true; };
    assert(await guest.forget()); assert(removed && !guest.pairing);
    const exported = load(prefix + '/hostpair.js', { ...mocks, './store': {} });
    const Pairing = exported.Pairing || exported;
    const host = Object.create(Pairing.prototype);
    Object.assign(host, { paired: [{ id: 'a' }, { id: 'b' }], _save() {}, server: { closeDevice() {} }, emit() {}, revokeAccess: async () => false });
    assert.equal(await host.forget('b'), false); assert.equal(host.paired.length, 2);
    host.revokeAccess = async (id) => { assert.equal(id, 'b'); return true; };
    assert(await host.forget('b')); assert.deepEqual(host.paired, [{ id: 'a' }]);
    // Exercise the actual pairing validation, then the real Sshd revocation callback.
    const ctx = {};
    Object.assign(host, { pending: null, busy: () => false, server: { send() {}, closeDevice() {}, fail() { throw new Error('unexpected pairing rejection'); } } });
    host._onMessage(ctx, { t: P.T.PAIR_START, v: P.PROTOCOL_VERSION, id: 'peer:a', commit: '0'.repeat(64) });
    assert.equal(host.pending.id, 'peer:a'); clearTimeout(host.pending.timer); host.pending = null;
    host.paired.push({ id: 'peer:a' });
    const Sshd = load(platform + '/sshd.js', mocks);
    Sshd.prototype.refresh = async function () { this.isAdmin = false; };
    const sshd = new Sshd(fixture(dir).opts);
    host.revokeAccess = (id) => sshd.forget(id);
    assert(await host.forget('peer:a')); assert.deepEqual(host.paired, [{ id: 'a' }]);
  }
}
(async () => {
  for (const platform of ['windows', 'linux']) {
    for (const test of [files, ssh, smb, savedOff, forgetting]) {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'duodesk-security-'));
      try { await test(platform, dir); console.log('PASS', platform, test.name); }
      finally { await tick(); fs.rmSync(dir, { recursive: true, force: true }); }
    }
  }
})().catch((e) => { console.error(e); process.exitCode = 1; });
