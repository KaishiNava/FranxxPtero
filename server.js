const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const path = require("path");
const fs = require("fs");
const fsp = fs.promises;
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { spawn } = require("child_process");
const os = require("os");
const dns = require("dns").promises;
const net = require("net");
const AdmZip = require("adm-zip");

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";
// Persistent Railway Volume. Mount a Railway Volume at /data and keep DATA_DIR=/data.
const DATA = path.resolve(process.env.DATA_DIR || path.join(__dirname, "data"));
const SERVERS_DIR = path.join(DATA, "servers");
// GitHub users.json is root/admin only. Railway volume users.json is non-root only.
const USERS_FILE = path.resolve(process.env.LOCAL_USERS_PATH || path.join(DATA, "database", "users.json"));
const SERVERS_FILE = path.resolve(process.env.LOCAL_SERVERS_PATH || path.join(DATA, "database", "servers.json"));
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 100);

// Account + access-key database. When GitHub is configured, these JSON files
// are the source of truth; local files remain as a safe development fallback.
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "";
const GITHUB_OWNER = process.env.GITHUB_OWNER || "";
const GITHUB_REPO = process.env.GITHUB_REPO || "";
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || "main";
const GITHUB_USERS_PATH = process.env.GITHUB_USERS_PATH || "database/users.json";
const GITHUB_KEYS_PATH = process.env.GITHUB_KEYS_PATH || "database/access-keys.json";
const ROOT_USERNAME = String(process.env.ROOT_USERNAME || "admin").trim().toLowerCase();
const ROOT_PASSWORD = String(process.env.ROOT_PASSWORD || "");
const GITHUB_ENABLED = Boolean(GITHUB_TOKEN && GITHUB_OWNER && GITHUB_REPO);

function githubHeaders() {
  return {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${GITHUB_TOKEN}`,
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json"
  };
}
function githubApiUrl(filePath) {
  return `https://api.github.com/repos/${encodeURIComponent(GITHUB_OWNER)}/${encodeURIComponent(GITHUB_REPO)}/contents/${filePath.split("/").map(encodeURIComponent).join("/")}`;
}
function decodeGithub(content) {
  return JSON.parse(Buffer.from(String(content || "").replace(/\n/g, ""), "base64").toString("utf8"));
}
async function githubReadJson(filePath, fallback = []) {
  if (!GITHUB_ENABLED) return fallback;
  const r = await fetch(`${githubApiUrl(filePath)}?ref=${encodeURIComponent(GITHUB_BRANCH)}`, { headers: githubHeaders() });
  if (r.status === 404) return fallback;
  if (!r.ok) throw new Error(`GitHub database read failed (${r.status})`);
  const d = await r.json();
  return decodeGithub(d.content);
}
async function githubWriteJson(filePath, data, message) {
  if (!GITHUB_ENABLED) return;
  let sha;
  const existing = await fetch(`${githubApiUrl(filePath)}?ref=${encodeURIComponent(GITHUB_BRANCH)}`, { headers: githubHeaders() });
  if (existing.ok) sha = (await existing.json()).sha;
  else if (existing.status !== 404) throw new Error(`GitHub database lookup failed (${existing.status})`);
  const body = {
    message,
    content: Buffer.from(JSON.stringify(data, null, 2) + "\n", "utf8").toString("base64"),
    branch: GITHUB_BRANCH
  };
  if (sha) body.sha = sha;
  const r = await fetch(githubApiUrl(filePath), { method: "PUT", headers: githubHeaders(), body: JSON.stringify(body) });
  if (!r.ok) {
    const d = await r.json().catch(() => ({}));
    throw new Error(d.message || `GitHub database write failed (${r.status})`);
  }
}
function unwrapUsers(data) {
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.users)) return data.users;
  return [];
}
function unwrapKeys(data) {
  if (Array.isArray(data)) return data;
  if (data && Array.isArray(data.keys)) return data.keys;
  return [];
}
async function readRootUsers() {
  if (GITHUB_ENABLED) return unwrapUsers(await githubReadJson(GITHUB_USERS_PATH, { users: [] }));
  return unwrapUsers(await readJson(USERS_FILE));
}
async function writeRootUsers(users, message = "Update root users database") {
  if (GITHUB_ENABLED) return githubWriteJson(GITHUB_USERS_PATH, { users }, message);
  const locals = await readLocalUsers();
  return writeJson(USERS_FILE, { users: [...locals.filter(u => !u.root), ...users.filter(u => Boolean(u.root))] });
}
async function readLocalUsers() {
  return unwrapUsers(await readJson(USERS_FILE));
}
async function writeLocalUsers(users) {
  return writeJson(USERS_FILE, { users });
}
async function readUsers() {
  const [roots, locals] = await Promise.all([readRootUsers(), readLocalUsers()]);
  return [...roots.filter(u => Boolean(u.root)), ...locals.filter(u => !u.root)];
}
async function readAccessKeys() {
  if (GITHUB_ENABLED) return unwrapKeys(await githubReadJson(GITHUB_KEYS_PATH, { keys: [] }));
  const f = path.join(DATA, "access-keys.json");
  if (!fs.existsSync(f)) await writeJson(f, { keys: [] });
  return unwrapKeys(await readJson(f));
}
async function writeAccessKeys(keys, message = "Update access keys database") {
  if (GITHUB_ENABLED) return githubWriteJson(GITHUB_KEYS_PATH, { keys }, message);
  const f = path.join(DATA, "access-keys.json");
  return writeJson(f, { keys });
}
async function findUserById(userId) {
  const users = await readUsers();
  return users.find(u => u.id === userId) || null;
}
async function ensureRootAccount() {
  const roots = (await readRootUsers()).filter(u => Boolean(u.root));
  if (roots.length) return roots;
  if (!ROOT_PASSWORD) {
    if (GITHUB_ENABLED) throw new Error("Database root kosong. Set ROOT_USERNAME dan ROOT_PASSWORD untuk membuat akun root pertama.");
    return roots;
  }
  const root = { id: id("usr"), username: ROOT_USERNAME || "admin", password: await bcrypt.hash(ROOT_PASSWORD, 12), root: true, createdAt: new Date().toISOString() };
  await writeRootUsers([root], "Create initial root account");
  return [root];
}

for (const p of [DATA, SERVERS_DIR, path.dirname(USERS_FILE), path.dirname(SERVERS_FILE)]) fs.mkdirSync(p, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify({ users: [] }, null, 2));
if (!fs.existsSync(SERVERS_FILE)) fs.writeFileSync(SERVERS_FILE, "[]");
const ACCESS_KEYS_FILE = path.join(DATA, "access-keys.json");
if (!fs.existsSync(ACCESS_KEYS_FILE)) fs.writeFileSync(ACCESS_KEYS_FILE, JSON.stringify({ keys: [] }, null, 2));

// One-time migration from the older layout (DATA/servers.json + DATA/servers).
const LEGACY_SERVERS_FILE = path.join(DATA, "servers.json");
const LEGACY_SERVERS_DIR = path.join(DATA, "servers");
try {
  const legacyText = LEGACY_SERVERS_FILE !== SERVERS_FILE && fs.existsSync(LEGACY_SERVERS_FILE) ? fs.readFileSync(LEGACY_SERVERS_FILE, "utf8") : "[]";
  const legacyData = JSON.parse(legacyText || "[]");
  const currentData = JSON.parse(fs.readFileSync(SERVERS_FILE, "utf8") || "[]");
  if (Array.isArray(legacyData) && legacyData.length && Array.isArray(currentData) && !currentData.length) {
    fs.writeFileSync(SERVERS_FILE, JSON.stringify(legacyData, null, 2));
  }
} catch {}
if (LEGACY_SERVERS_DIR !== SERVERS_DIR && fs.existsSync(LEGACY_SERVERS_DIR)) {
  try {
    const currentEntries = fs.readdirSync(SERVERS_DIR);
    const legacyEntries = fs.readdirSync(LEGACY_SERVERS_DIR);
    if (!currentEntries.length && legacyEntries.length) {
      for (const name of legacyEntries) {
        fs.cpSync(path.join(LEGACY_SERVERS_DIR, name), path.join(SERVERS_DIR, name), { recursive: true, force: false });
      }
    }
  } catch {}
}

async function migrateLegacyGithubUsers() {
  if (!GITHUB_ENABLED) return;
  const githubUsers = await readRootUsers();
  const legacyNormal = githubUsers.filter(u => !u.root);
  if (!legacyNormal.length) return;
  const locals = await readLocalUsers();
  const known = new Set(locals.map(u => u.id));
  for (const u of legacyNormal) if (!known.has(u.id)) locals.push({ ...u, root: false });
  await writeLocalUsers(locals);
  await writeRootUsers(githubUsers.filter(u => Boolean(u.root)), "Move non-root users to Railway persistent database");
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: "/ws" });
const processes = new Map();

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const upload = multer({
  storage: multer.diskStorage({
    destination(req, file, cb) {
      getOwnedServer(req.user.id, req.params.id)
        .then(ownerServer => {
          if (!ownerServer) return cb(new Error("Server tidak ditemukan"));
          try {
            const dir = safeServerPath(req.user.id, req.params.id, req.query.path || "");
            fs.mkdirSync(dir, { recursive: true });
            cb(null, dir);
          } catch (e) { cb(e); }
        })
        .catch(e => cb(e));
    },
    filename(req, file, cb) {
      cb(null, path.basename(file.originalname));
    }
  }),
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 }
});

async function readJson(file) {
  try { return JSON.parse(await fsp.readFile(file, "utf8")); }
  catch { return []; }
}
async function writeJson(file, data) {
  const tmp = file + ".tmp";
  await fsp.writeFile(tmp, JSON.stringify(data, null, 2));
  await fsp.rename(tmp, file);
}
function id(prefix) {
  return `${prefix}_${crypto.randomBytes(7).toString("hex")}`;
}
function safeName(v) {
  return String(v || "").replace(/[^a-zA-Z0-9._-]/g, "-").slice(0, 60);
}
function getUser(req) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return null;
  try { return jwt.verify(h.slice(7), JWT_SECRET); } catch { return null; }
}
function auth(req, res, next) {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: "Unauthorized" });
  req.user = user;
  next();
}
function serverRoot(serverId) {
  return path.join(SERVERS_DIR, serverId);
}
function safeServerPath(userId, serverId, relative = "") {
  const root = path.resolve(serverRoot(serverId));
  const target = path.resolve(root, String(relative || ""));
  if (!target.startsWith(root + path.sep) && target !== root) {
    throw new Error("Invalid path");
  }
  return target;
}
async function getOwnedServer(userId, serverId) {
  const servers = await readJson(SERVERS_FILE);
  return servers.find(s => s.id === serverId && s.ownerId === userId);
}
function publicServer(s) {
  return {
    id: s.id, name: s.name, runtime: s.runtime, entry: s.entry,
    command: s.command, memoryLimit: Number(s.memoryLimit || 512),
    createdAt: s.createdAt,
    status: s.suspended ? "suspended" : (processes.has(s.id) ? "online" : "offline"),
    suspended: Boolean(s.suspended),
    web: { url: s.webUrl || null, port: s.webPort || null }
  };
}

function parseMemoryMB(value, fallback = 512) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(64, Math.min(32768, Math.round(n)));
}

async function directorySize(dir) {
  let total = 0;
  const stack = [dir];
  while (stack.length) {
    const current = stack.pop();
    let entries = [];
    try { entries = await fsp.readdir(current, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const p = path.join(current, e.name);
      if (e.isDirectory()) stack.push(p);
      else { try { total += (await fsp.stat(p)).size; } catch {} }
    }
  }
  return total;
}

function readProcessStats(pid) {
  if (!pid || process.platform !== "linux") return null;
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8").trim();
    const endComm = stat.lastIndexOf(")");
    const fields = stat.slice(endComm + 2).split(/\s+/);
    const utime = Number(fields[11] || 0);
    const stime = Number(fields[12] || 0);
    const hz = 100;
    const totalCpu = (utime + stime) / hz;
    const uptime = Number(fs.readFileSync("/proc/uptime", "utf8").split(" ")[0]);
    const startTicks = Number(fields[19] || 0);
    const startSec = startTicks / hz;
    const age = Math.max(0.1, uptime - startSec);
    const cpu = Math.min(100, Math.max(0, (totalCpu / age) * 100));
    const status = fs.readFileSync(`/proc/${pid}/status`, "utf8");
    const match = status.match(/^VmRSS:\s+(\d+)\s+kB$/m);
    const memory = match ? Number(match[1]) * 1024 : 0;
    return { cpu, memory };
  } catch { return null; }
}
function sendWs(ws, payload) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(payload));
}
function broadcastServer(serverId, payload) {
  for (const client of wss.clients) {
    if (client.serverId === serverId) sendWs(client, payload);
  }
}

wss.on("connection", async (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const token = url.searchParams.get("token");
  const serverId = url.searchParams.get("server");
  try {
    const user = jwt.verify(token || "", JWT_SECRET);
    const owned = await getOwnedServer(user.id, serverId);
    if (!owned) {
      ws.close(1008, "Unauthorized");
      return;
    }
    ws.userId = user.id;
    ws.serverId = serverId;
    ws.send(JSON.stringify({ type: "connected", serverId }));
    ws.on("message", raw => {
      try {
        const msg = JSON.parse(String(raw));
        if (msg.type === "stdin") {
          const p = processes.get(serverId);
          if (p && p.child && p.child.stdin && p.child.stdin.writable) {
            p.child.stdin.write(String(msg.data ?? "") + "\n");
          }
        }
      } catch {}
    });
    const p = processes.get(serverId);
    if (p && p.buffer) sendWs(ws, { type: "log", data: p.buffer });
  } catch {
    ws.close(1008, "Unauthorized");
  }
});

function runServer(s) {
  if (processes.has(s.id)) throw new Error("Server already running");
  const cwd = serverRoot(s.id);
  fs.mkdirSync(cwd, { recursive: true });

  // Private-use panel: commands are intentionally configurable per server.
  const child = spawn(s.command, {
    cwd,
    env: { ...process.env, ...(s.env || {}), FX_SERVER_ID: s.id },
    shell: true,
    windowsHide: true,
    detached: process.platform !== "win32"
  });

  const state = {
    child, startedAt: Date.now(), buffer: "",
    cpuStart: process.cpuUsage(), wallStart: Date.now(),
    memoryLimit: Number(s.memoryLimit || 512)
  };
  processes.set(s.id, state);
  broadcastServer(s.id, { type: "status", status: "online" });

  const push = data => {
    const text = String(data);
    state.buffer = (state.buffer + text).slice(-50000);
    broadcastServer(s.id, { type: "log", data: text });
  };
  child.stdout.on("data", push);
  child.stderr.on("data", push);
  child.on("error", e => push(`\n[process error] ${e.message}\n`));
  child.on("close", code => {
    processes.delete(s.id);
    broadcastServer(s.id, { type: "status", status: "offline", code });
    broadcastServer(s.id, { type: "log", data: `\n[process exited: ${code}]\n` });
  });
}

function stopServer(serverId) {
  const p = processes.get(serverId);
  if (!p) return Promise.resolve(false);
  if (p.stopPromise) return p.stopPromise;

  p.stopPromise = new Promise((resolve, reject) => {
    const child = p.child;
    let finished = false;
    let timer;

    const finish = ok => {
      if (finished) return;
      finished = true;
      if (timer) clearTimeout(timer);
      if (processes.get(serverId) === p) processes.delete(serverId);
      ok ? resolve(true) : reject(new Error("Process tidak berhenti dalam waktu yang ditentukan"));
    };

    const forceStop = () => {
      try {
        if (process.platform === "win32") child.kill();
        else process.kill(-child.pid, "SIGKILL");
      } catch {}
    };

    child.once("close", () => finish(true));
    child.once("error", () => finish(true));

    try {
      // The runtime is spawned as a detached process group on Unix. Killing
      // the negative PID terminates the shell and the actual runtime child
      // together, preventing restart from colliding with an old process.
      if (process.platform === "win32") {
        child.kill();
      } else {
        process.kill(-child.pid, "SIGTERM");
      }
    } catch {
      try { child.kill("SIGTERM"); } catch {}
    }

    timer = setTimeout(() => {
      forceStop();
      setTimeout(() => finish(false), 1200);
    }, 5000);
  });

  return p.stopPromise;
}

app.post("/api/auth/register", async (req, res) => {
  return res.status(403).json({ error: "Register publik dinonaktifkan. Hanya akun root/admin yang dapat membuat user baru." });
});

app.post("/api/auth/login", async (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  try {
    const users = await ensureRootAccount();
    const user = users.find(u => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password || user.passwordHash || "")))
      return res.status(401).json({ error: "Username atau password salah" });
    const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: { id: user.id, username, root: Boolean(user.root) } });
  } catch (e) {
    res.status(500).json({ error: e.message || "Database akun tidak tersedia" });
  }
});

app.get("/api/me", auth, async (req, res) => {
  const user = await findUserById(req.user.id);
  if (!user) return res.status(401).json({ error: "Akun tidak ditemukan" });
  res.json({ id: user.id, username: user.username, root: Boolean(user.root), createdAt: user.createdAt });
});

function rootAuth(req, res, next) {
  findUserById(req.user.id).then(user => {
    if (!user) return res.status(401).json({ error: "Akun tidak ditemukan" });
    if (!user.root) return res.status(403).json({ error: "Akses root/admin diperlukan" });
    req.account = user;
    next();
  }).catch(e => res.status(500).json({ error: e.message }));
}

const API_SCOPES = [
  "users:create", "users:read", "users:delete",
  "servers:create", "servers:read", "servers:manage", "servers:delete",
  "stats:read", "web:ping"
];
function normalizeScopes(scopes) {
  const allowed = new Set(API_SCOPES);
  return [...new Set((Array.isArray(scopes) ? scopes : []).map(String).filter(x => allowed.has(x)))];
}
function hashAccessKey(secret) {
  return crypto.createHash("sha256").update(secret).digest("hex");
}
function apiKeyAuth(req, res, next) {
  (async () => {
    const h = req.headers.authorization || "";
    if (!h.startsWith("Bearer ")) return res.status(401).json({ error: "Access key diperlukan" });
    const secret = h.slice(7).trim();
    if (!secret.startsWith("fx_live_")) return res.status(401).json({ error: "Access key tidak valid" });
    const keys = await readAccessKeys();
    const hash = hashAccessKey(secret);
    const key = keys.find(k => {
      if (k.revokedAt || typeof k.keyHash !== "string" || k.keyHash.length !== hash.length) return false;
      return crypto.timingSafeEqual(Buffer.from(k.keyHash), Buffer.from(hash));
    });
    if (!key) return res.status(401).json({ error: "Access key tidak valid atau sudah direvoke" });
    req.apiKey = key;
    next();
  })().catch(e => res.status(500).json({ error: e.message || "Access key database error" }));
}
function requireScope(scope) {
  return (req, res, next) => {
    if (!req.apiKey || !req.apiKey.scopes.includes(scope)) return res.status(403).json({ error: `Scope ${scope} diperlukan` });
    next();
  };
}

app.get("/api/root/profile", auth, rootAuth, async (req, res) => {
  const users = await readUsers();
  res.json({ account: { id: req.account.id, username: req.account.username, root: true, createdAt: req.account.createdAt }, users: users.map(u => ({ id: u.id, username: u.username, root: Boolean(u.root), createdAt: u.createdAt })) });
});

app.post("/api/root/users", auth, rootAuth, async (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const root = Boolean(req.body.root);
  if (!/^[a-z0-9_]{3,24}$/.test(username)) return res.status(400).json({ error: "Username 3-24 chars: a-z, 0-9, _" });
  if (password.length < 6) return res.status(400).json({ error: "Password minimal 6 karakter" });
  const users = await readUsers();
  if (users.some(u => u.username === username)) return res.status(409).json({ error: "Username sudah digunakan" });
  const user = { id: id("usr"), username, password: await bcrypt.hash(password, 12), root, createdAt: new Date().toISOString() };
  if (root) {
    const roots = await readRootUsers();
    roots.push(user);
    await writeRootUsers(roots.filter(u => Boolean(u.root)), `Create root user ${username}`);
  } else {
    const locals = await readLocalUsers();
    locals.push(user);
    await writeLocalUsers(locals);
  }
  res.json({ id: user.id, username: user.username, root: user.root, createdAt: user.createdAt });
});

app.get("/api/root/access-keys", auth, rootAuth, async (req, res) => {
  const keys = await readAccessKeys();
  res.json(keys.map(k => ({ id: k.id, name: k.name, prefix: k.prefix, ownerId: k.ownerId, scopes: k.scopes, createdAt: k.createdAt, lastUsedAt: k.lastUsedAt || null, revokedAt: k.revokedAt || null })));
});

app.post("/api/root/access-keys", auth, rootAuth, async (req, res) => {
  const name = String(req.body.name || "API Key").trim().slice(0, 60) || "API Key";
  const scopes = normalizeScopes(req.body.scopes);
  if (!scopes.length) return res.status(400).json({ error: "Pilih minimal satu permission" });
  const secret = `fx_live_${crypto.randomBytes(32).toString("hex")}`;
  const keys = await readAccessKeys();
  const key = { id: id("key"), name, prefix: secret.slice(0, 16), keyHash: hashAccessKey(secret), ownerId: req.account.id, scopes, createdAt: new Date().toISOString(), revokedAt: null, lastUsedAt: null };
  keys.push(key);
  await writeAccessKeys(keys, `Create access key ${name}`);
  // The raw secret is intentionally returned only once. It is never stored in the database.
  res.json({ id: key.id, name: key.name, secret, prefix: key.prefix, scopes: key.scopes, createdAt: key.createdAt });
});

app.post("/api/root/access-keys/:id/revoke", auth, rootAuth, async (req, res) => {
  const keys = await readAccessKeys();
  const key = keys.find(k => k.id === req.params.id);
  if (!key) return res.status(404).json({ error: "Access key tidak ditemukan" });
  key.revokedAt = new Date().toISOString();
  await writeAccessKeys(keys, `Revoke access key ${key.name}`);
  res.json({ ok: true });
});

app.post("/api/access/users", apiKeyAuth, requireScope("users:create"), async (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const root = Boolean(req.body.root);
  if (!/^[a-z0-9_]{3,24}$/.test(username)) return res.status(400).json({ error: "Username 3-24 chars: a-z, 0-9, _" });
  if (password.length < 6) return res.status(400).json({ error: "Password minimal 6 karakter" });
  // API keys may create normal users only; root elevation remains a root-panel action.
  if (root) return res.status(403).json({ error: "API key tidak boleh membuat akun root" });
  const users = await readUsers();
  if (users.some(u => u.username === username)) return res.status(409).json({ error: "Username sudah digunakan" });
  const user = { id: id("usr"), username, password: await bcrypt.hash(password, 12), root: false, createdAt: new Date().toISOString() };
  const locals = await readLocalUsers();
  locals.push(user);
  await writeLocalUsers(locals);
  res.status(201).json({ id: user.id, username: user.username, root: false, createdAt: user.createdAt });
});


// ---------------------------------------------------------------------------
// FULL ACCESS-KEY API
// Access keys can manage non-root users and servers, inspect runtime stats,
// and perform safe public-web health checks.
// ---------------------------------------------------------------------------
function apiServerView(s) {
  const p = processes.get(s.id);
  return {
    ...publicServer(s),
    ownerId: s.ownerId,
    ownerUsername: null,
    pid: p?.child?.pid || null,
    uptime: p ? Math.floor((Date.now() - p.startedAt) / 1000) : 0
  };
}

async function apiServerViewWithOwner(s) {
  const view = apiServerView(s);
  const owner = await findUserById(s.ownerId);
  view.ownerUsername = owner?.username || null;
  view.ownerRoot = Boolean(owner?.root);
  return view;
}

async function apiAllServers() {
  const servers = await readJson(SERVERS_FILE);
  return Promise.all(servers.map(apiServerViewWithOwner));
}

function isPrivateIp(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const [a,b,c,d] = address.split(".").map(Number);
    return a === 10 ||
      a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a === 0 ||
      a >= 224;
  }
  if (family === 6) {
    const x = address.toLowerCase();
    return x === "::1" || x === "::" || x.startsWith("fc") || x.startsWith("fd") ||
      x.startsWith("fe8") || x.startsWith("fe9") || x.startsWith("fea") || x.startsWith("feb");
  }
  return true;
}

async function assertSafeWebUrl(raw) {
  const u = new URL(String(raw || ""));
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("URL hanya boleh http:// atau https://");
  if (u.username || u.password) throw new Error("URL dengan credential tidak diizinkan");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const addresses = [];
  if (net.isIP(host)) addresses.push(host);
  else {
    const records = await dns.lookup(host, { all: true, verbatim: true });
    addresses.push(...records.map(x => x.address));
  }
  if (!addresses.length || addresses.some(isPrivateIp)) {
    throw new Error("Host tujuan bukan alamat publik yang diizinkan");
  }
  return u;
}

async function pingPublicWeb(rawUrl, timeoutMs = 8000) {
  let current = String(rawUrl || "").trim();
  const started = Date.now();
  let last = null;
  for (let hop = 0; hop < 4; hop++) {
    const u = await assertSafeWebUrl(current);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const r = await fetch(u, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: { "User-Agent": "FRANXX-PTERO-WebMonitor/1.0" }
      });
      const location = r.headers.get("location");
      if (r.status >= 300 && r.status < 400 && location) {
        current = new URL(location, u).toString();
        last = { status: r.status, redirected: true };
        continue;
      }
      const latency = Date.now() - started;
      return {
        ok: r.ok,
        status: r.status,
        statusText: r.statusText,
        latencyMs: latency,
        url: u.toString(),
        checkedAt: new Date().toISOString(),
        contentType: r.headers.get("content-type"),
        server: r.headers.get("server")
      };
    } catch (e) {
      return {
        ok: false,
        status: 0,
        statusText: e.name === "AbortError" ? "TIMEOUT" : (e.message || "FETCH_ERROR"),
        latencyMs: Date.now() - started,
        url: u.toString(),
        checkedAt: new Date().toISOString()
      };
    } finally {
      clearTimeout(timer);
    }
  }
  return {
    ok: false,
    status: last?.status || 0,
    statusText: "TOO_MANY_REDIRECTS",
    latencyMs: Date.now() - started,
    url: current,
    checkedAt: new Date().toISOString()
  };
}

app.get("/api/access/overview", apiKeyAuth, requireScope("servers:read"), async (req, res) => {
  const [users, servers] = await Promise.all([readUsers(), apiAllServers()]);
  res.json({
    ok: true,
    users: { total: users.length, root: users.filter(u => u.root).length, normal: users.filter(u => !u.root).length },
    servers: {
      total: servers.length,
      online: servers.filter(s => s.status === "online").length,
      offline: servers.filter(s => s.status === "offline").length,
      suspended: servers.filter(s => s.status === "suspended").length
    },
    platform: { node: process.version, platform: process.platform, arch: process.arch, uptime: Math.floor(process.uptime()) }
  });
});

app.get("/api/access/users", apiKeyAuth, requireScope("users:read"), async (req, res) => {
  const [users, servers] = await Promise.all([readUsers(), readJson(SERVERS_FILE)]);
  res.json(users.map(u => ({
    id: u.id, username: u.username, root: Boolean(u.root), createdAt: u.createdAt,
    serverCount: servers.filter(s => s.ownerId === u.id).length
  })));
});

app.get("/api/access/users/:id", apiKeyAuth, requireScope("users:read"), async (req, res) => {
  const user = await findUserById(req.params.id);
  if (!user) return res.status(404).json({ error: "User tidak ditemukan" });
  const servers = (await readJson(SERVERS_FILE)).filter(s => s.ownerId === user.id);
  res.json({ id: user.id, username: user.username, root: Boolean(user.root), createdAt: user.createdAt, servers: servers.map(publicServer) });
});

app.delete("/api/access/users/:id", apiKeyAuth, requireScope("users:delete"), async (req, res) => {
  const user = await findUserById(req.params.id);
  if (!user) return res.status(404).json({ error: "User tidak ditemukan" });
  if (user.root) return res.status(403).json({ error: "Akun ROOT/ADMIN dilindungi dan tidak dapat dihapus lewat API" });
  const servers = await readJson(SERVERS_FILE);
  if (servers.some(s => s.ownerId === user.id)) {
    return res.status(409).json({ error: "User masih memiliki server. Hapus server offline terlebih dahulu." });
  }
  const locals = await readLocalUsers();
  await writeLocalUsers(locals.filter(u => u.id !== user.id));
  res.json({ ok: true, deleted: user.id });
});

app.post("/api/access/servers", apiKeyAuth, requireScope("servers:create"), async (req, res) => {
  const ownerId = String(req.body.userId || "").trim();
  if (!ownerId) return res.status(400).json({ error: "userId wajib diisi saat memakai access key" });
  const owner = await findUserById(ownerId);
  if (!owner || owner.root) return res.status(404).json({ error: "User tujuan non-root tidak ditemukan" });

  const name = safeName(req.body.name || "My Server");
  const runtime = ["node", "python", "custom"].includes(req.body.runtime) ? req.body.runtime : "node";
  const entry = safeName(req.body.entry || (runtime === "python" ? "main.py" : "index.js"));
  const command = String(req.body.command || (runtime === "python" ? "python main.py" : "node index.js")).trim();
  if (!command || command.length > 300) return res.status(400).json({ error: "Command tidak valid" });
  const memoryLimit = parseMemoryMB(req.body.memoryLimit, 512);
  const webUrl = String(req.body.webUrl || "").trim().slice(0, 500);
  const webPort = Number(req.body.webPort || 0);
  if (webUrl && !/^https?:\/\//i.test(webUrl)) return res.status(400).json({ error: "webUrl harus http:// atau https://" });
  if (webPort && (!Number.isInteger(webPort) || webPort < 1 || webPort > 65535)) return res.status(400).json({ error: "webPort tidak valid" });

  const servers = await readJson(SERVERS_FILE);
  const serverRecord = {
    id: id("srv"), ownerId, name, runtime, entry, command, memoryLimit,
    env: {}, webUrl: webUrl || null, webPort: webPort || null,
    suspended: false, createdAt: new Date().toISOString()
  };
  servers.push(serverRecord);
  await writeJson(SERVERS_FILE, servers);
  await fsp.mkdir(serverRoot(serverRecord.id), { recursive: true });
  res.status(201).json(await apiServerViewWithOwner(serverRecord));
});

app.get("/api/access/servers", apiKeyAuth, requireScope("servers:read"), async (req, res) => {
  res.json(await apiAllServers());
});

app.get("/api/access/servers/total", apiKeyAuth, requireScope("servers:read"), async (req, res) => {
  const servers = await readJson(SERVERS_FILE);
  res.json({ total: servers.length });
});

app.get("/api/access/servers/:id", apiKeyAuth, requireScope("servers:read"), async (req, res) => {
  const s = (await readJson(SERVERS_FILE)).find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  res.json(await apiServerViewWithOwner(s));
});

app.get("/api/access/servers/:id/stats", apiKeyAuth, requireScope("stats:read"), async (req, res) => {
  const s = (await readJson(SERVERS_FILE)).find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  const p = processes.get(s.id);
  const disk = await directorySize(serverRoot(s.id));
  const proc = p ? readProcessStats(p.child.pid) : null;
  res.json({
    id: s.id, name: s.name, status: s.suspended ? "suspended" : (p ? "online" : "offline"),
    uptime: p ? Math.floor((Date.now() - p.startedAt) / 1000) : 0,
    memory: proc?.memory || 0,
    memoryLimit: Number(s.memoryLimit || 512) * 1024 * 1024,
    cpu: proc ? Number(proc.cpu.toFixed(1)) : 0,
    storage: disk,
    web: { url: s.webUrl || null, port: s.webPort || null },
    platform: process.platform, node: process.version,
    hostMemory: os.totalmem(), hostFreeMemory: os.freemem()
  });
});

async function setServerSuspended(serverId, suspended) {
  const servers = await readJson(SERVERS_FILE);
  const s = servers.find(x => x.id === serverId);
  if (!s) return null;
  if (suspended) await stopServer(s.id);
  s.suspended = suspended;
  await writeJson(SERVERS_FILE, servers);
  return s;
}

app.post("/api/access/servers/:id/start", apiKeyAuth, requireScope("servers:manage"), async (req, res) => {
  const s = (await readJson(SERVERS_FILE)).find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  if (s.suspended) return res.status(423).json({ error: "Server sedang disuspend" });
  try { runServer(s); res.json({ ok: true, server: await apiServerViewWithOwner(s) }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/api/access/servers/:id/stop", apiKeyAuth, requireScope("servers:manage"), async (req, res) => {
  const s = (await readJson(SERVERS_FILE)).find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  await stopServer(s.id);
  res.json({ ok: true });
});

app.post("/api/access/servers/:id/restart", apiKeyAuth, requireScope("servers:manage"), async (req, res) => {
  const s = (await readJson(SERVERS_FILE)).find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  if (s.suspended) return res.status(423).json({ error: "Server sedang disuspend" });
  try { await stopServer(s.id); runServer(s); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/api/access/servers/:id/suspend", apiKeyAuth, requireScope("servers:manage"), async (req, res) => {
  const s = await setServerSuspended(req.params.id, true);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  res.json({ ok: true, suspended: true });
});

app.post("/api/access/servers/:id/unsuspend", apiKeyAuth, requireScope("servers:manage"), async (req, res) => {
  const s = await setServerSuspended(req.params.id, false);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  res.json({ ok: true, suspended: false });
});

app.delete("/api/access/servers/:id", apiKeyAuth, requireScope("servers:delete"), async (req, res) => {
  const servers = await readJson(SERVERS_FILE);
  const s = servers.find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  const owner = await findUserById(s.ownerId);
  if (owner?.root) return res.status(403).json({ error: "Server milik ROOT/ADMIN dilindungi dan tidak dapat dihapus lewat API" });
  if (processes.has(s.id)) return res.status(409).json({ error: "Server harus OFFLINE sebelum dihapus" });
  await writeJson(SERVERS_FILE, servers.filter(x => x.id !== s.id));
  await fsp.rm(serverRoot(s.id), { recursive: true, force: true });
  res.json({ ok: true, deleted: s.id });
});

app.put("/api/access/servers/:id/settings", apiKeyAuth, requireScope("servers:manage"), async (req, res) => {
  const servers = await readJson(SERVERS_FILE);
  const s = servers.find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  const command = String(req.body.command ?? s.command).trim();
  const entry = safeName(req.body.entry || s.entry);
  const memoryLimit = parseMemoryMB(req.body.memoryLimit, s.memoryLimit || 512);
  const webUrl = String(req.body.webUrl ?? s.webUrl ?? "").trim().slice(0, 500);
  const webPort = Number(req.body.webPort ?? s.webPort ?? 0);
  if (!command || command.length > 300) return res.status(400).json({ error: "Command tidak valid" });
  if (webUrl && !/^https?:\/\//i.test(webUrl)) return res.status(400).json({ error: "webUrl harus http:// atau https://" });
  if (webPort && (!Number.isInteger(webPort) || webPort < 1 || webPort > 65535)) return res.status(400).json({ error: "webPort tidak valid" });
  s.command = command;
  s.entry = entry;
  s.memoryLimit = memoryLimit;
  s.webUrl = webUrl || null;
  s.webPort = webPort || null;
  await writeJson(SERVERS_FILE, servers);
  res.json({ ok: true, server: await apiServerViewWithOwner(s) });
});

app.get("/api/access/servers/:id/runtime", apiKeyAuth, requireScope("servers:read"), async (req, res) => {
  const s = (await readJson(SERVERS_FILE)).find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  const p = processes.get(s.id);
  res.json({
    server: await apiServerViewWithOwner(s),
    runtime: {
      running: Boolean(p), pid: p?.child?.pid || null,
      uptime: p ? Math.floor((Date.now() - p.startedAt) / 1000) : 0,
      command: s.command, cwd: serverRoot(s.id),
      webUrl: s.webUrl || null, webPort: s.webPort || null
    }
  });
});

app.post("/api/access/servers/:id/web/ping", apiKeyAuth, requireScope("web:ping"), async (req, res) => {
  const s = (await readJson(SERVERS_FILE)).find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  const url = String(req.body.url || s.webUrl || "").trim();
  if (!url) return res.status(400).json({ error: "Server belum memiliki webUrl dan body.url kosong" });
  try { res.json({ ok: true, serverId: s.id, ping: await pingPublicWeb(url) }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/api/access/web/ping", apiKeyAuth, requireScope("web:ping"), async (req, res) => {
  const url = String(req.body.url || "").trim();
  if (!url) return res.status(400).json({ error: "url wajib diisi" });
  try { res.json(await pingPublicWeb(url)); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

app.get("/api/servers", auth, async (req, res) => {
  const servers = await readJson(SERVERS_FILE);
  res.json(servers.filter(s => s.ownerId === req.user.id).map(publicServer));
});

app.post("/api/servers", async (req, res, next) => {
  const bearer = req.headers.authorization || "";
  try {
    if (bearer.startsWith("Bearer fx_live_")) return apiKeyAuth(req, res, () => requireScope("servers:create")(req, res, next));
    return auth(req, res, next);
  } catch (e) { return res.status(500).json({ error: e.message }); }
}, async (req, res) => {
  let ownerId = req.user?.id;
  if (req.apiKey) {
    ownerId = String(req.body.userId || "").trim();
    if (!ownerId) return res.status(400).json({ error: "userId wajib diisi saat memakai access key" });
    const target = await findUserById(ownerId);
    if (!target) return res.status(404).json({ error: "User tujuan tidak ditemukan" });
  }
  const name = safeName(req.body.name || "My Server");
  const runtime = ["node", "python", "custom"].includes(req.body.runtime) ? req.body.runtime : "node";
  const entry = safeName(req.body.entry || (runtime === "python" ? "main.py" : "index.js"));
  const command = String(req.body.command || (runtime === "python" ? "python main.py" : "node index.js")).trim();
  if (!command || command.length > 300) return res.status(400).json({ error: "Command tidak valid" });
  const memoryLimit = parseMemoryMB(req.body.memoryLimit, 512);
  const webUrl = String(req.body.webUrl || "").trim().slice(0, 500);
  const webPort = Number(req.body.webPort || 0);
  if (webUrl && !/^https?:\/\//i.test(webUrl)) return res.status(400).json({ error: "webUrl harus http:// atau https://" });
  if (webPort && (!Number.isInteger(webPort) || webPort < 1 || webPort > 65535)) return res.status(400).json({ error: "webPort tidak valid" });

  const servers = await readJson(SERVERS_FILE);
  const s = {
    id: id("srv"), ownerId, name, runtime, entry, command,
    memoryLimit, env: {}, webUrl: webUrl || null, webPort: webPort || null,
    suspended: false, createdAt: new Date().toISOString()
  };
  servers.push(s);
  await writeJson(SERVERS_FILE, servers);
  await fsp.mkdir(serverRoot(s.id), { recursive: true });
  res.json(publicServer(s));
});

app.delete("/api/servers/:id", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  await stopServer(s.id);
  const servers = await readJson(SERVERS_FILE);
  await writeJson(SERVERS_FILE, servers.filter(x => x.id !== s.id));
  await fsp.rm(serverRoot(s.id), { recursive: true, force: true });
  res.json({ ok: true });
});

app.post("/api/servers/:id/start", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  if (s.suspended) return res.status(423).json({ error: "Server sedang disuspend" });
  try { runServer(s); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/api/servers/:id/stop", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  try {
    await stopServer(s.id);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/servers/:id/restart", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  try {
    await stopServer(s.id);
    runServer(s);
    res.json({ ok: true });
  } catch (e) {
    broadcastServer(s.id, { type: "log", data: `\n[restart error] ${e.message}\n` });
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/servers/:id/files", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  try {
    const dir = safeServerPath(req.user.id, s.id, req.query.path || "");
    const entries = await fsp.readdir(dir, { withFileTypes: true });
    const result = [];
    for (const e of entries) {
      const p = path.join(dir, e.name);
      const st = await fsp.stat(p);
      result.push({ name: e.name, type: e.isDirectory() ? "dir" : "file", size: st.size, modified: st.mtime });
    }
    result.sort((a,b) => a.type !== b.type ? (a.type === "dir" ? -1 : 1) : a.name.localeCompare(b.name));
    res.json(result);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get("/api/servers/:id/file", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  try {
    const p = safeServerPath(req.user.id, s.id, req.query.path);
    const st = await fsp.stat(p);
    if (!st.isFile()) return res.status(400).json({ error: "Bukan file" });
    if (st.size > 2 * 1024 * 1024) return res.status(413).json({ error: "File terlalu besar untuk editor" });
    res.json({ path: req.query.path, content: await fsp.readFile(p, "utf8") });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.put("/api/servers/:id/file", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  try {
    const p = safeServerPath(req.user.id, s.id, req.body.path);
    await fsp.mkdir(path.dirname(p), { recursive: true });
    await fsp.writeFile(p, String(req.body.content ?? ""), "utf8");
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/api/servers/:id/mkdir", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  try { await fsp.mkdir(safeServerPath(req.user.id, s.id, req.body.path), { recursive: true }); res.json({ok:true}); }
  catch(e) { res.status(400).json({error:e.message}); }
});

app.post("/api/servers/:id/upload", auth, upload.array("files", 30), async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  res.json({ ok: true, files: (req.files || []).map(f => f.filename) });
});

app.delete("/api/servers/:id/file", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  try {
    const p = safeServerPath(req.user.id, s.id, req.body.path);
    await fsp.rm(p, { recursive: true, force: true });
    res.json({ok:true});
  } catch(e) { res.status(400).json({error:e.message}); }
});

app.delete("/api/servers/:id/files/bulk", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  try {
    const paths = Array.isArray(req.body.paths) ? req.body.paths.slice(0, 500) : [];
    if (!paths.length) return res.status(400).json({ error: "Tidak ada file yang dipilih" });
    for (const rel of paths) {
      const clean = String(rel || "").replace(/^\/+/, "");
      if (!clean || clean === ".") continue;
      const target = safeServerPath(req.user.id, s.id, clean);
      const root = path.resolve(serverRoot(s.id));
      const relative = path.relative(root, target);
      if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("Invalid path");
      await fsp.rm(target, { recursive: true, force: true });
    }
    res.json({ ok: true, deleted: paths.length });
  } catch(e) { res.status(400).json({ error: e.message }); }
});

app.put("/api/servers/:id/settings", auth, async (req, res) => {
  const servers = await readJson(SERVERS_FILE);
  const s = servers.find(x => x.id === req.params.id && x.ownerId === req.user.id);
  if (!s) return res.status(404).json({error:"Server tidak ditemukan"});
  const command = String(req.body.command || "").trim();
  const entry = safeName(req.body.entry || s.entry);
  const memoryLimit = parseMemoryMB(req.body.memoryLimit, s.memoryLimit || 512);
  if (!command || command.length > 300) return res.status(400).json({error:"Command tidak valid"});
  s.command = command;
  s.entry = entry;
  s.memoryLimit = memoryLimit;
  await writeJson(SERVERS_FILE, servers);
  res.json({ok:true});
});


function normalizeArchiveEntryName(name) {
  return String(name || "").replace(/\\/g, "/").replace(/^\/+/, "");
}

function safeArchiveTarget(baseDir, entryName) {
  const clean = normalizeArchiveEntryName(entryName);
  if (!clean || clean === ".") return path.resolve(baseDir);
  const base = path.resolve(baseDir);
  const target = path.resolve(base, clean);
  if (!target.startsWith(base + path.sep) && target !== base) {
    throw new Error("ZIP berisi path tidak aman");
  }
  return target;
}

app.post("/api/servers/:id/unzip", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  try {
    const rel = String(req.body.path || "").replace(/^\/+/, "");
    if (!rel.toLowerCase().endsWith(".zip")) return res.status(400).json({ error: "File harus .zip" });
    const zipPath = safeServerPath(req.user.id, s.id, rel);
    const stat = await fsp.stat(zipPath);
    if (!stat.isFile()) return res.status(400).json({ error: "Bukan file" });

    // Extract beside the ZIP, not always into server root. This keeps nested
    // containers such as ptero/public/root intact and immediately navigable.
    const destination = path.dirname(zipPath);
    const zip = new AdmZip(zipPath);
    const entries = zip.getEntries();
    for (const entry of entries) safeArchiveTarget(destination, entry.entryName);
    zip.extractAllTo(destination, true);

    const topLevel = [...new Set(entries.map(e => normalizeArchiveEntryName(e.entryName).split("/")[0]).filter(Boolean))];
    res.json({
      ok: true,
      message: "ZIP berhasil di-extract",
      destination: path.relative(serverRoot(s.id), destination).replace(/\\/g, "/"),
      topLevel
    });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post("/api/servers/:id/move-to-root", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  try {
    const paths = Array.isArray(req.body.paths) ? req.body.paths.slice(0, 100) : [];
    if (!paths.length) return res.status(400).json({ error: "Tidak ada file atau folder yang dipilih" });

    const root = path.resolve(serverRoot(s.id));
    const items = paths.map(raw => {
      const clean = String(raw || "").replace(/^\/+/, "");
      if (!clean || clean === ".") throw new Error("Root folder tidak bisa dipindahkan");
      const source = safeServerPath(req.user.id, s.id, clean);
      const relative = path.relative(root, source);
      if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("Invalid path");
      return { clean, source, name: path.basename(source), relative };
    });

    // Prevent ambiguous operations such as selecting both a folder and one of
    // its children in the same move request.
    for (let i = 0; i < items.length; i++) {
      for (let j = i + 1; j < items.length; j++) {
        const a = path.relative(items[i].source, items[j].source);
        const b = path.relative(items[j].source, items[i].source);
        if ((a && !a.startsWith("..") && !path.isAbsolute(a)) || (b && !b.startsWith("..") && !path.isAbsolute(b))) {
          throw new Error("Jangan pilih folder dan isi di dalamnya sekaligus");
        }
      }
    }

    const destinations = items.map(item => path.join(root, item.name));
    const destinationSet = new Set(destinations.map(p => path.resolve(p)));
    for (const dest of destinations) {
      if (destinationSet.size !== destinations.length || await fsp.access(dest).then(() => true).catch(() => false)) {
        throw new Error(`Item dengan nama "${path.basename(dest)}" sudah ada di root`);
      }
    }

    for (let i = 0; i < items.length; i++) await fsp.rename(items[i].source, destinations[i]);
    res.json({ ok: true, moved: items.map(x => x.name), destination: "/" });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post("/api/servers/:id/archive", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  try {
    const paths = Array.isArray(req.body.paths) ? req.body.paths : [];
    if (!paths.length) return res.status(400).json({ error: "Tidak ada file yang dipilih" });
    const root = path.resolve(serverRoot(s.id));
    const zip = new AdmZip();
    const used = new Set();
    for (const rel of paths.slice(0, 500)) {
      const clean = String(rel || "").replace(/^\/+/, "");
      if (!clean || clean === ".") continue;
      const source = safeServerPath(req.user.id, s.id, clean);
      const relative = path.relative(root, source);
      if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("Invalid path");
      const stat = await fsp.stat(source);
      if (stat.isDirectory()) zip.addLocalFolder(source, relative);
      else zip.addLocalFile(source, undefined, relative);
      used.add(relative);
    }
    if (!used.size) return res.status(400).json({ error: "Tidak ada file yang dipilih" });
    const name = `fx-${safeName(s.name)}-${Date.now()}.zip`;
    const tmpDir = path.join(DATA, "tmp");
    await fsp.mkdir(tmpDir, { recursive: true });
    const out = path.join(tmpDir, `${id("zip")}.zip`);
    zip.writeZip(out);
    res.download(out, name, async () => { try { await fsp.rm(out, { force: true }); } catch {} });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get("/api/servers/:id/stats", auth, async (req,res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({error:"Server tidak ditemukan"});
  const p = processes.get(s.id);
  const disk = await directorySize(serverRoot(s.id));
  const proc = p ? readProcessStats(p.child.pid) : null;
  const memory = proc?.memory || 0;
  res.json({
    status: p ? "online" : "offline",
    uptime: p ? Math.floor((Date.now()-p.startedAt)/1000) : 0,
    memory,
    memoryLimit: Number(s.memoryLimit || 512) * 1024 * 1024,
    cpu: proc ? Number(proc.cpu.toFixed(1)) : 0,
    storage: disk,
    platform: process.platform,
    node: process.version,
    hostMemory: os.totalmem(),
    hostFreeMemory: os.freemem()
  });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message || "Internal server error" });
});

(async () => {
  try {
    await migrateLegacyGithubUsers();
    console.log(`FX PROJECT — storage: ${DATA}`);
  } catch (e) {
    console.error("Database migration warning:", e.message);
  }
  server.listen(PORT, HOST, () => {
    console.log(`FX PROJECT — FRANXX PTERO running on ${HOST}:${PORT}`);
  });
})();
