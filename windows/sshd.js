// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// Terminal, the other computer → this PC (it may be a Mac, another PC or Linux): it sends `ssh.key`;
// with "Let {name} open a terminal on {me}" on and Windows' OpenSSH Server running, its key goes
// into authorized_keys (administrators_authorized_keys for admin accounts, written elevated) with
// the marker `macshare:<peer id>`, and we answer `ssh.info` with this PC's host keys.
const { execFile } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const P = require('../shared/protocol.js');
const { script, scriptElevated } = require('./ps');

const T = P.T;
const SSH_DATA = path.join(process.env.ProgramData || 'C:\\ProgramData', 'ssh');
const ADMIN_KEYS = path.join(SSH_DATA, 'administrators_authorized_keys');
const OPTIONS = 'no-agent-forwarding,no-X11-forwarding';

class Sshd {
  // opts: link, settings (shared), save(), onChange()
  constructor(opts) {
    Object.assign(this, opts);
    this.service = 'unknown'; // 'running' | 'stopped' | 'missing' | 'unknown'
    this.isAdmin = null;
    this.pendingKey = null;   // the Mac's last ssh.key line
    this.busy = false;
    this.message = '';
    this.keyWork = Promise.resolve();
    this.keyEpoch = 0;
    this.forgotten = new Set();
    this.link.on(T.SSH_KEY, (m) => this._onKey(m));
    this.link.on(T.SSH_FORGET, () => this._forget());
    this.link.on('closed', () => { this.keyEpoch++; this.pendingKey = null; this.lastInfo = null; this.onChange(); });
    this.link.on('welcome', () => { this.forgotten.delete(this.peerId()); });
    this.refresh().catch((e) => { this.message = e.message; this.onChange(); });
    if (!this.cfg.allowMac) this.apply(); // also clean up keys left by older versions
  }

  get cfg() {
    return this.settings.terminal;
  }

  async refresh() {
    try {
      const out = (await script('sshd-status')).trim();
      this.service = /^(running|stopped|missing)$/.test(out) ? out : 'unknown';
    } catch (_) { this.service = 'unknown'; }
    if (this.isAdmin === null) this.isAdmin = await adminMember();
    this.onChange();
  }

  peerId() {
    const snap = this.link.snapshot();
    const id = snap.session && snap.session.id || snap.paired && snap.paired.macId;
    return typeof id === 'string' && id ? id : null;
  }

  _queue(action) {
    const work = this.keyWork.then(action).catch((e) => {
      this.message = 'SSH access could not be updated: ' + e.message;
      this.onChange();
      return false;
    });
    this.keyWork = work;
    return work;
  }

  async _onKey(m) {
    const pub = typeof m.pub === 'string' ? m.pub.trim().split(/\s+/).slice(0, 2).join(' ') : '';
    const id = this.peerId();
    if (!id || !/^[A-Za-z0-9._-]{1,128}$/.test(id) || this.forgotten.has(id) || !/^(ssh-ed25519|ecdsa-sha2-\S+|ssh-rsa) [A-Za-z0-9+/=]+$/.test(pub)) return;
    this.pendingKey = { id, pub };
    return this.apply();
  }

  apply() {
    if (!this.cfg.allowMac) return this._forget(null, { keepPending: true });
    const key = this.pendingKey, epoch = this.keyEpoch;
    if (!key) return Promise.resolve(true);
    return this._queue(async () => {
      const current = () => this.cfg.allowMac && epoch === this.keyEpoch && !this.forgotten.has(key.id);
      if (!current()) return false;
      await this.refresh();
      if (!current()) return false;
      if (this.service !== 'running') { await this._info(false, 'remote_login_off', key.id); return false; }
      const line = OPTIONS + ' ' + key.pub + ' macshare:' + key.id;
      await this._changeKeys(key.id, line);
      // Off/Forget/disconnect may have arrived while an administrator prompt was open.
      if (!current()) { await this._changeKeys(key.id); return false; }
      this.cfg.installedKey = crypto.createHash('sha256').update(line).digest('hex');
      this.save();
      this.message = '';
      await this._info(true, undefined, key.id);
      return true;
    });
  }

  // null removes every app-owned marker; a device id removes only that device's key.
  _forget(id = this.peerId(), { block = false, keepPending = false } = {}) {
    if (id === null || this.pendingKey && this.pendingKey.id === id) this.keyEpoch++;
    if (block && id !== null) this.forgotten.add(id);
    if (!keepPending && (id === null || this.pendingKey && this.pendingKey.id === id)) this.pendingKey = null;
    return this._queue(async () => {
      await this._changeKeys(id);
      this.cfg.installedKey = '';
      this.save();
      this.message = '';
      await this._info(false, 'not_allowed', id);
      return true;
    });
  }

  forget(id) {
    // Pairing accepts opaque IDs, including old peers that cannot request SSH.
    if (typeof id !== 'string' || !id) return Promise.resolve(false);
    return this._forget(id, { block: true });
  }

  async _changeKeys(id, line = '') {
    if (this.isAdmin === null) this.isAdmin = await adminMember();
    const file = this.isAdmin ? ADMIN_KEYS : path.join(os.homedir(), '.ssh', 'authorized_keys');
    const legacyId = id === null ? null : id.replace(/[^A-Za-z0-9._-]/g, '');
    const remove = (l) => id === null ? / macshare:[^\s]+$/.test(l) : l.endsWith(' macshare:' + id) || !!legacyId && l.endsWith(' macshare:' + legacyId);
    let lines;
    try { lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean); }
    catch (e) { if (e.code === 'ENOENT') lines = []; else if (!this.isAdmin) throw e; }
    if (line && lines && lines.includes(line) && lines.filter(remove).length === 1) return;
    if (!line && lines && !lines.some(remove)) return;
    if (this.isAdmin) {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'macshare-key-'));
      const keyFile = path.join(dir, 'key.txt'), result = path.join(dir, 'result.txt');
      try {
        if (line) fs.writeFileSync(keyFile, line, { mode: 0o600 });
        await scriptElevated('sshd-key', { Path: file, Marker: id === null ? ' macshare:' : ' macshare:' + id, All: id === null ? 'yes' : 'no', LegacyMarker: legacyId && legacyId !== id ? ' macshare:' + legacyId : '', KeyFile: line ? keyFile : '', Result: result });
        const status = fs.existsSync(result) ? fs.readFileSync(result, 'utf8').trim() : 'Key update did not finish';
        if (status !== 'ok') throw new Error(status);
      } finally { fs.rmSync(dir, { recursive: true, force: true }); }
    } else {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, lines.filter((l) => !remove(l)).concat(line ? [line] : []).join('\n') + '\n');
    }
  }

  // One elevated step: OpenSSH Server installed, automatic, running (its installer adds the rule).
  async setup() {
    if (this.busy) return;
    this.busy = true;
    this.onChange();
    try {
      await scriptElevated('sshd-setup', {}, 600000);
      this.message = '';
    } catch (e) {
      this.message = /cancel/i.test(e.message) ? 'The administrator prompt was declined' : 'Setup failed: ' + e.message;
    }
    this.busy = false;
    await this.refresh();
    await this.apply();
  }

  async _info(enabled, why, id = this.peerId()) {
    const msg = { t: T.SSH_INFO, enabled };
    if (enabled) {
      msg.user = os.userInfo().username;
      msg.port = 22;
      msg.hostKeys = await hostKeys();
    } else msg.why = why;
    if (id !== null && this.peerId() !== id) return;
    if (enabled && (!this.cfg.allowMac || this.forgotten.has(id))) return;
    this.link.send(msg);
    this.lastInfo = { enabled, why: why || '' };
    this.onChange();
  }

  view() {
    return { service: this.service, busy: this.busy, message: this.message, macAsked: !!this.pendingKey, info: this.lastInfo || null, admin: this.isAdmin };
  }
}

// The host keys: asked from the running server (the .pub files are admin-only), else the files.
function hostKeys() {
  const keyscan = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'OpenSSH', 'ssh-keyscan.exe');
  return new Promise((resolve) => {
    execFile(keyscan, ['-p', '22', '127.0.0.1'], { windowsHide: true, timeout: 10000 }, (err, out) => {
      const keys = String(out || '').split(/\r?\n/).filter((l) => l && !l.startsWith('#'))
        .map((l) => l.trim().split(/\s+/).slice(1, 3).join(' ')).filter((k) => /^\S+ [A-Za-z0-9+/=]+$/.test(k));
      if (keys.length) return resolve(keys);
      try {
        resolve(fs.readdirSync(SSH_DATA).filter((f) => /^ssh_host_\w+_key\.pub$/.test(f))
          .map((f) => fs.readFileSync(path.join(SSH_DATA, f), 'utf8').trim().split(/\s+/).slice(0, 2).join(' ')));
      } catch (_) { resolve([]); }
    });
  });
}

// Member of Administrators (also when UAC filters the token): sshd then reads administrators_authorized_keys.
function adminMember() {
  return new Promise((resolve, reject) => {
    execFile(path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'whoami.exe'), ['/groups'], { windowsHide: true }, (err, out) => err ? reject(err) : resolve(/S-1-5-32-544/.test(String(out))));
  });
}

module.exports = Sshd;
