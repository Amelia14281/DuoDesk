// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// Terminal, the other computer → this one (Linux version of
// windows/sshd.js): the other side sends `ssh.key`; with "Let {name} open a terminal on {me}" on
// and the OpenSSH server running, its key goes into ~/.ssh/authorized_keys with the marker
// `macshare:<peer id>` (no agent or X11 forwarding), and we answer `ssh.info` with this computer's
// user, port and host keys. Set up installs and starts the server (pkexec, once).
const { execFile } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const P = require('../shared/protocol.js');

const T = P.T;
const OPTIONS = 'no-agent-forwarding,no-X11-forwarding';
const KEYS = path.join(os.homedir(), '.ssh', 'authorized_keys');

function run(cmd, args, timeout = 10000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout }, (err, out, stderr) => resolve({ ok: !err, code: err && typeof err.code === 'number' ? err.code : 0, out: String(out || '').trim(), err: String(stderr || '').trim() }));
  });
}

const which = (cmd) => (process.env.PATH || '/usr/bin:/bin:/usr/sbin:/sbin').split(':').some((d) => d && fs.existsSync(path.join(d, cmd)));

// The port sshd listens on (sshd_config Port, else 22).
function sshPort() {
  try {
    const m = /^\s*Port\s+(\d+)/mi.exec(fs.readFileSync('/etc/ssh/sshd_config', 'utf8'));
    if (m) return Number(m[1]);
  } catch (_) { /* default */ }
  return 22;
}

// Something answers on the port (socket-activated sshd counts as running).
function listening(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port, timeout: 800 });
    const done = (v) => { s.destroy(); resolve(v); };
    s.on('connect', () => done(true));
    s.on('error', () => done(false));
    s.on('timeout', () => done(false));
  });
}

function hostKeys() {
  try {
    return fs.readdirSync('/etc/ssh').filter((f) => /^ssh_host_\w+_key\.pub$/.test(f))
      .map((f) => fs.readFileSync(path.join('/etc/ssh', f), 'utf8').trim().split(/\s+/).slice(0, 2).join(' '))
      .filter((k) => /^\S+ [A-Za-z0-9+/=]+$/.test(k));
  } catch (_) {
    return [];
  }
}

class Sshd {
  // opts: link, settings (shared), save(), onChange()
  constructor(opts) {
    Object.assign(this, opts);
    this.service = 'unknown'; // 'running' | 'stopped' | 'missing' | 'unknown'
    this.pendingKey = null;   // the other side's last ssh.key line
    this.busy = false;
    this.message = '';
    this.keyWork = Promise.resolve();
    this.keyEpoch = 0;
    this.forgotten = new Set();
    this.lastInfo = null;
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
    const port = sshPort();
    if (await listening(port)) this.service = 'running';
    else this.service = (which('sshd') || fs.existsSync('/usr/sbin/sshd')) ? 'stopped' : 'missing';
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
    const remove = (l) => id === null ? / macshare:[^\s]+$/.test(l) : l.endsWith(' macshare:' + id);
    let lines;
    try { lines = fs.readFileSync(KEYS, 'utf8').split(/\r?\n/).filter(Boolean); }
    catch (e) { if (e.code !== 'ENOENT') throw e; lines = []; }
    if (line && lines.includes(line) && lines.filter(remove).length === 1) return;
    if (!line && !lines.some(remove)) return;
    fs.mkdirSync(path.dirname(KEYS), { recursive: true, mode: 0o700 });
    fs.writeFileSync(KEYS, lines.filter((l) => !remove(l)).concat(line ? [line] : []).join('\n') + '\n', { mode: 0o600 });
    fs.chmodSync(KEYS, 0o600);
  }

  // Install (apt, dnf, zypper or pacman), enable and start the OpenSSH server: one password prompt.
  async setup() {
    if (this.busy) return;
    this.busy = true;
    this.message = '';
    this.onChange();
    const script = [
      'if ! command -v sshd >/dev/null 2>&1 && ! [ -x /usr/sbin/sshd ]; then',
      '  if [ -e /etc/NIXOS ]; then echo "On NixOS, enable services.openssh.enable = true; in configuration.nix" >&2; exit 3;',
      '  elif command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server;',
      '  elif command -v dnf >/dev/null; then dnf install -y openssh-server;',
      '  elif command -v zypper >/dev/null; then zypper --non-interactive install openssh-server;',
      '  elif command -v pacman >/dev/null; then pacman -S --noconfirm openssh; fi',
      'fi',
      'systemctl enable --now ssh 2>/dev/null || systemctl enable --now sshd',
    ].join('\n');
    const r = await run('pkexec', ['sh', '-c', script], 600000);
    if (!r.ok) this.message = r.code === 126 ? 'The password prompt was closed' : 'Setup failed: ' + (r.err.split('\n').pop() || 'pkexec failed');
    this.busy = false;
    await this.refresh();
    await this.apply();
  }

  _info(enabled, why, id = this.peerId()) {
    const msg = { t: T.SSH_INFO, enabled };
    if (enabled) {
      msg.user = os.userInfo().username;
      msg.port = sshPort();
      msg.hostKeys = hostKeys();
    } else msg.why = why;
    if (id !== null && this.peerId() !== id) return;
    if (enabled && (!this.cfg.allowMac || this.forgotten.has(id))) return;
    this.link.send(msg);
    this.lastInfo = { enabled, why: why || '' };
    this.onChange();
  }

  view() {
    return { service: this.service, busy: this.busy, message: this.message, macAsked: !!this.pendingKey, info: this.lastInfo || null };
  }
}

module.exports = Sshd;
