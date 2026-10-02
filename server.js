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
const net = require("net");
const AdmZip = require("adm-zip");
const { createClient } = require("@supabase/supabase-js");

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

// Railway Persistent Volume. Set DATA_DIR=/data and mount the Railway
// Volume at /data. The old /app/data path is intentionally not used when
// DATA_DIR is configured.
const DATA = path.resolve(process.env.DATA_DIR || "/data");
const SERVERS_DIR = path.resolve(process.env.SERVERS_DIR || path.join(DATA, "servers"));
const LOCAL_USERS_FILE = path.resolve(process.env.LOCAL_USERS_PATH || path.join(DATA, "database", "users.json"));
const SERVERS_FILE = path.resolve(process.env.LOCAL_SERVERS_PATH || path.join(DATA, "database", "servers.json"));
const ACCESS_KEYS_FILE = path.resolve(process.env.LOCAL_KEYS_PATH || path.join(DATA, "database", "access-keys.json"));
const USERS_FILE = LOCAL_USERS_FILE;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 100);
const PANEL_URL = String(process.env.PANEL_URL || process.env.PUBLIC_BASE_URL || "").trim().replace(/\/$/, "");
const RUNTIME_PORT_START = Math.max(1024, Number(process.env.RUNTIME_PORT_START || 10000));
const RUNTIME_PORT_END = Math.max(RUNTIME_PORT_START + 1, Number(process.env.RUNTIME_PORT_END || 20000));

// ============================================================
// SUPABASE DATABASE — runtime source of truth
// GitHub is used ONLY for one-time legacy import when explicitly
// configured. No account/server CRUD writes to GitHub anymore.
// ============================================================
const SUPABASE_URL = String(process.env.SUPABASE_URL || "").trim().replace(/\/$/, "");
const SUPABASE_SERVICE_ROLE_KEY = String(process.env.SUPABASE_SERVICE_ROLE_KEY || "").trim();
const SUPABASE_ENABLED = Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY);
const supabase = SUPABASE_ENABLED
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false }
    })
  : null;

// Optional legacy GitHub source. This is NEVER written by the panel.
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "";
const GITHUB_OWNER = process.env.GITHUB_OWNER || "";
const GITHUB_REPO = process.env.GITHUB_REPO || "";
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || "main";
const GITHUB_USERS_PATH = process.env.GITHUB_USERS_PATH || "database/users.json";
const GITHUB_KEYS_PATH = process.env.GITHUB_KEYS_PATH || "database/access-keys.json";
const GITHUB_ENABLED = Boolean(GITHUB_TOKEN && GITHUB_OWNER && GITHUB_REPO);

const ROOT_USERNAME = String(process.env.ROOT_USERNAME || "admin").trim().toLowerCase();
const ROOT_PASSWORD = String(process.env.ROOT_PASSWORD || "");

if (!SUPABASE_ENABLED) {
  console.warn("[supabase] SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY belum diset. Panel tidak akan memakai GitHub sebagai runtime database.");
}
if (!process.env.JWT_SECRET) console.warn("[security] JWT_SECRET belum diset; set JWT_SECRET di Railway Variables untuk token login yang persisten.");

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
  if (!r.ok) throw new Error(`GitHub legacy read failed (${r.status})`);
  const d = await r.json();
  return decodeGithub(d.content);
}

function normalizeUsersDatabase(value) {
  const list = Array.isArray(value) ? value : (value && Array.isArray(value.users) ? value.users : []);
  return list.filter(Boolean).map(u => {
    const username = String(u.username || "").trim().toLowerCase();
    const stableId = u.id || (username ? `usr_${crypto.createHash("sha256").update(username).digest("hex").slice(0,14)}` : id("usr"));
    return {
      ...u,
      id: stableId,
      username,
      root: Boolean(u.root) || username === ROOT_USERNAME
    };
  }).filter(u => u.username);
}
function normalizeAccessKeysDatabase(value) {
  if (Array.isArray(value)) return value;
  if (value && Array.isArray(value.keys)) return value.keys;
  return [];
}

function userFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: String(row.username || "").toLowerCase(),
    password: row.password_hash,
    root: Boolean(row.root),
    createdAt: row.created_at
  };
}
function userToRow(u) {
  return {
    id: String(u.id),
    username: String(u.username).trim().toLowerCase(),
    password_hash: String(u.password || u.passwordHash || ""),
    root: Boolean(u.root),
    created_at: u.createdAt || new Date().toISOString()
  };
}
function keyFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    prefix: row.prefix,
    keyHash: row.key_hash,
    ownerId: row.created_by,
    scopes: Array.isArray(row.scopes) ? row.scopes : [],
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at || null,
    revokedAt: row.revoked_at || null
  };
}
function keyToRow(k) {
  return {
    id: String(k.id),
    name: String(k.name || "API Key"),
    prefix: String(k.prefix || ""),
    key_hash: String(k.keyHash || ""),
    scopes: Array.isArray(k.scopes) ? k.scopes : [],
    created_by: k.ownerId || null,
    created_at: k.createdAt || new Date().toISOString(),
    last_used_at: k.lastUsedAt || null,
    revoked_at: k.revokedAt || null
  };
}
function serverFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    ownerId: row.owner_id,
    name: row.name,
    runtime: row.runtime,
    entry: row.entry,
    command: row.command,
    memoryLimit: Number(row.memory_limit || 512),
    env: row.env && typeof row.env === "object" ? row.env : {},
    runtimePort: Number(row.runtime_port || 0),
    suspended: Boolean(row.suspended),
    suspendedAt: row.suspended_at || null,
    suspendedReason: row.suspended_reason || null,
    createdAt: row.created_at
  };
}
function serverToRow(s) {
  return {
    id: String(s.id),
    owner_id: String(s.ownerId),
    name: String(s.name || "My Server"),
    runtime: String(s.runtime || "node"),
    entry: String(s.entry || "index.js"),
    command: String(s.command || "node index.js"),
    memory_limit: Number(s.memoryLimit || 512),
    env: s.env && typeof s.env === "object" ? s.env : {},
    runtime_port: Number(s.runtimePort || 0),
    suspended: Boolean(s.suspended),
    suspended_at: s.suspendedAt || null,
    suspended_reason: s.suspendedReason || null,
    created_at: s.createdAt || new Date().toISOString()
  };
}

async function supabaseSelect(table, columns = "*") {
  if (!supabase) throw new Error("Supabase belum dikonfigurasi");
  const { data, error } = await supabase.from(table).select(columns);
  if (error) throw error;
  return data || [];
}
async function supabaseUpsert(table, rows) {
  if (!supabase) throw new Error("Supabase belum dikonfigurasi");
  if (!rows.length) return;
  const { error } = await supabase.from(table).upsert(rows, { onConflict: "id" });
  if (error) throw error;
}
async function supabaseDeleteByIds(table, ids) {
  if (!supabase || !ids.length) return;
  const { error } = await supabase.from(table).delete().in("id", ids);
  if (error) throw error;
}

async function readUsers() {
  const rows = await supabaseSelect("users", "id,username,password_hash,root,created_at");
  return rows.map(userFromRow).filter(Boolean);
}
async function writeUsers(users) {
  const normalized = normalizeUsersDatabase(users);
  const old = await readUsers();
  await supabaseUpsert("users", normalized.map(userToRow));
  const keep = new Set(normalized.map(u => String(u.id)));
  const remove = old.filter(u => !keep.has(String(u.id))).map(u => u.id);
  await supabaseDeleteByIds("users", remove);
}
async function readAccessKeys() {
  const rows = await supabaseSelect("api_keys", "id,name,prefix,key_hash,scopes,created_by,created_at,last_used_at,revoked_at");
  return rows.map(keyFromRow).filter(Boolean);
}
async function writeAccessKeys(keys) {
  const normalized = normalizeAccessKeysDatabase(keys);
  const old = await readAccessKeys();
  await supabaseUpsert("api_keys", normalized.map(keyToRow));
  const keep = new Set(normalized.map(k => String(k.id)));
  const remove = old.filter(k => !keep.has(String(k.id))).map(k => k.id);
  await supabaseDeleteByIds("api_keys", remove);
}
async function readServers() {
  const rows = await supabaseSelect("servers", "id,owner_id,name,runtime,entry,command,memory_limit,env,runtime_port,suspended,suspended_at,suspended_reason,created_at");
  return rows.map(serverFromRow).filter(Boolean);
}
async function writeServers(servers) {
  const normalized = Array.isArray(servers) ? servers : [];
  const old = await readServers();
  await supabaseUpsert("servers", normalized.map(serverToRow));
  const keep = new Set(normalized.map(s => String(s.id)));
  const remove = old.filter(s => !keep.has(String(s.id))).map(s => s.id);
  await supabaseDeleteByIds("servers", remove);
}

async function findUserById(userId) {
  const users = await readUsers();
  return users.find(u => String(u.id) === String(userId)) || null;
}

async function importLegacyIfNeeded() {
  if (!SUPABASE_ENABLED) throw new Error("SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY wajib diisi di Railway Variables");
  const existingUsers = await readUsers();
  const existingServers = await readServers();
  const existingKeys = await readAccessKeys();

  // Import local/legacy JSON first when present on the persistent volume.
  const localUsers = normalizeUsersDatabase(await readJson(LOCAL_USERS_FILE));
  const localServers = normalizeUsersDatabase(await readServers());
  void localServers;

  let legacyUsers = localUsers;
  let legacyServers = [];
  let legacyKeys = normalizeAccessKeysDatabase(await readJson(ACCESS_KEYS_FILE));

  if (GITHUB_ENABLED) {
    try {
      const ghUsers = normalizeUsersDatabase(await githubReadJson(GITHUB_USERS_PATH, { users: [] }));
      const ghKeys = normalizeAccessKeysDatabase(await githubReadJson(GITHUB_KEYS_PATH, { keys: [] }));
      if (ghUsers.length) legacyUsers = [...legacyUsers, ...ghUsers];
      if (ghKeys.length) legacyKeys = [...legacyKeys, ...ghKeys];
      console.log(`[supabase] legacy GitHub import source loaded: users=${ghUsers.length}, keys=${ghKeys.length}`);
    } catch (e) {
      console.warn(`[supabase] legacy GitHub import skipped: ${e.message}`);
    }
  }

  // Old server metadata may already be on the Railway volume.
  legacyServers = await readJson(SERVERS_FILE);

  const usersById = new Map(existingUsers.map(u => [String(u.id), u]));
  const usersByName = new Map(existingUsers.map(u => [u.username, u]));
  const legacyUserIdMap = new Map();
  for (const u of legacyUsers) {
    if (!u.username) continue;
    const oldId = String(u.id);
    const prev = usersById.get(oldId) || usersByName.get(u.username);
    if (prev) {
      legacyUserIdMap.set(oldId, String(prev.id));
      continue;
    }
    usersById.set(oldId, u);
    usersByName.set(u.username, u);
    legacyUserIdMap.set(oldId, oldId);
  }
  if (ROOT_PASSWORD && ![...usersById.values()].some(u => u.username === ROOT_USERNAME)) {
    const root = { id: id("usr"), username: ROOT_USERNAME, password: await bcrypt.hash(ROOT_PASSWORD, 12), root: true, createdAt: new Date().toISOString() };
    usersById.set(root.id, root);
    usersByName.set(root.username, root);
    console.log(`[supabase] root account ${ROOT_USERNAME} dibuat dari ROOT_PASSWORD`);
  }
  const mergedUsers = [...usersById.values()].map(u => ({ ...u, root: Boolean(u.root) || u.username === ROOT_USERNAME }));
  const existingUserIds = new Set(existingUsers.map(u => String(u.id)));
  const usersToImport = mergedUsers.filter(u => !existingUserIds.has(String(u.id)));
  if (usersToImport.length) {
    await supabaseUpsert("users", usersToImport.map(userToRow));
    console.log(`[supabase] imported ${usersToImport.length} user records`);
  }

  // IMPORTANT: servers.owner_id has a foreign-key constraint to users.id.
  // Always ensure the root user exists before importing old server metadata,
  // then repair orphaned legacy owners by assigning those servers to root.
  const usersAfterImport = await readUsers();
  const rootUser = usersAfterImport.find(u => String(u.username).toLowerCase() === ROOT_USERNAME);
  if (!rootUser) {
    throw new Error(`Root user ${ROOT_USERNAME} tidak ditemukan di Supabase. Set ROOT_USERNAME + ROOT_PASSWORD lalu restart.`);
  }

  const existingServerIds = new Set(existingServers.map(s => String(s.id)));
  const knownUserIds = new Set(usersAfterImport.map(u => String(u.id)));
  const serversToImport = (Array.isArray(legacyServers) ? legacyServers : [])
    .filter(s => !existingServerIds.has(String(s.id)))
    .map(s => {
      const oldOwner = String(s.ownerId || s.owner_id || "");
      const mappedOwner = legacyUserIdMap.get(oldOwner) || oldOwner;
      if (!knownUserIds.has(mappedOwner)) {
        console.warn(`[supabase] orphan server ${s.id}: owner ${oldOwner || "unknown"} tidak ditemukan, dipindah ke root ${rootUser.id}`);
        return { ...s, ownerId: rootUser.id, owner_id: rootUser.id };
      }
      return { ...s, ownerId: mappedOwner, owner_id: mappedOwner };
    });
  if (serversToImport.length) {
    await supabaseUpsert("servers", serversToImport.map(serverToRow));
    console.log(`[supabase] imported ${serversToImport.length} server metadata records`);
  }

  const existingKeyIds = new Set(existingKeys.map(k => String(k.id)));
  const keysToImport = legacyKeys.filter(k => !existingKeyIds.has(String(k.id)));
  if (keysToImport.length) {
    await supabaseUpsert("api_keys", keysToImport.map(keyToRow));
    console.log(`[supabase] imported ${keysToImport.length} access keys`);
  }
}

async function ensureRootAccount() {
  let users = await readUsers();
  const rootName = ROOT_USERNAME || "admin";
  let existingRoot = users.find(u => String(u.username || "").toLowerCase() === rootName);
  if (existingRoot) {
    if (!existingRoot.root) {
      existingRoot.root = true;
      await writeUsers(users);
    }
    return users;
  }
  if (!ROOT_PASSWORD) throw new Error(`Akun root ${rootName} belum ada. Set ROOT_USERNAME dan ROOT_PASSWORD di Railway Variables.`);
  const root = { id: id("usr"), username: rootName, password: await bcrypt.hash(ROOT_PASSWORD, 12), root: true, createdAt: new Date().toISOString() };
  users.push(root);
  await writeUsers(users);
  console.log(`[supabase] root account ${rootName} siap`);
  return users;
}

for (const p of [
  DATA,
  SERVERS_DIR,
  path.dirname(LOCAL_USERS_FILE),
  path.dirname(SERVERS_FILE),
  path.dirname(ACCESS_KEYS_FILE)
]) fs.mkdirSync(p, { recursive: true });
if (!fs.existsSync(LOCAL_USERS_FILE)) fs.writeFileSync(LOCAL_USERS_FILE, "[]");
if (!fs.existsSync(SERVERS_FILE)) fs.writeFileSync(SERVERS_FILE, "[]");
if (!fs.existsSync(ACCESS_KEYS_FILE)) fs.writeFileSync(ACCESS_KEYS_FILE, "[]");

// Migrate the previous ephemeral /app/data layout once, if it still exists.
// This is useful when an older Railway deployment used /app/data as its
// volume mount. New writes always go to DATA (/data).
const LEGACY_DATA = path.resolve(__dirname, "data");
if (LEGACY_DATA !== DATA && fs.existsSync(LEGACY_DATA)) {
  try {
    const legacyDb = path.join(LEGACY_DATA, "database");
    const newDb = path.dirname(SERVERS_FILE);
    fs.mkdirSync(newDb, { recursive: true });
    for (const name of ["users.json", "servers.json"]) {
      const from = path.join(legacyDb, name);
      const to = path.join(newDb, name);
      if (fs.existsSync(from) && (!fs.existsSync(to) || fs.statSync(to).size <= 2)) fs.copyFileSync(from, to);
    }
    const legacyServers = path.join(LEGACY_DATA, "servers");
    if (fs.existsSync(legacyServers)) {
      fs.mkdirSync(SERVERS_DIR, { recursive: true });
      for (const name of fs.readdirSync(legacyServers)) {
        const from = path.join(legacyServers, name);
        const to = path.join(SERVERS_DIR, name);
        if (!fs.existsSync(to)) fs.cpSync(from, to, { recursive: true });
      }
    }
    console.log(`[storage] legacy data migration checked: ${LEGACY_DATA} -> ${DATA}`);
  } catch (e) {
    console.warn(`[storage] legacy migration failed: ${e.message}`);
  }
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: "/ws" });
const processes = new Map();

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
// Always serve the panel shell/assets fresh after a Railway deployment.
// This prevents an old cached app.js from hiding the root navigation after
// the backend has already been updated.
app.use((req, res, next) => {
  if (req.path === "/" || req.path === "/index.html" || req.path === "/app.js" || req.path === "/style.css") {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }
  next();
});
app.use(express.static(path.join(__dirname, "public"), { etag: false, lastModified: false }));

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
  const servers = await readServers();
  return servers.find(s => s.id === serverId && s.ownerId === userId);
}
function publicServer(s) {
  return {
    id: s.id, name: s.name, runtime: s.runtime, entry: s.entry,
    command: s.command, memoryLimit: Number(s.memoryLimit || 512),
    createdAt: s.createdAt,
    suspended: Boolean(s.suspended),
    suspendedAt: s.suspendedAt || null,
    suspendedReason: s.suspendedReason || null,
    status: processes.has(s.id) ? "online" : "offline",
    runtimePort: Number(s.runtimePort || runtimePortForServer(s)),
    runtimeOnline: isServerOnline(s.id),
    runtimeWeb: runtimeWebUrl(s),
    runtimeUrl: runtimeWebUrl(s),
    pingUrl: runtimePingUrl(s)
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

function runtimePortForServer(s, servers = []) {
  const existing = Number(s.runtimePort);
  if (existing >= RUNTIME_PORT_START && existing <= RUNTIME_PORT_END) return existing;

  const range = RUNTIME_PORT_END - RUNTIME_PORT_START + 1;
  let port = RUNTIME_PORT_START + (parseInt(crypto.createHash("sha256").update(String(s.id)).digest("hex").slice(0, 8), 16) % range);
  const used = new Set(servers.map(x => Number(x.runtimePort)).filter(Number.isFinite));
  for (let i = 0; i < range; i++) {
    if (!used.has(port)) return port;
    port++;
    if (port > RUNTIME_PORT_END) port = RUNTIME_PORT_START;
  }
  return RUNTIME_PORT_START;
}

function publicBaseUrl() {
  if (PANEL_URL) return PANEL_URL;
  const domain = String(process.env.RAILWAY_PUBLIC_DOMAIN || process.env.RAILWAY_STATIC_URL || "").trim().replace(/\/$/, "");
  if (domain) return domain.startsWith("http://") || domain.startsWith("https://") ? domain : `https://${domain}`;
  return `http://localhost:${PORT}`;
}

function runtimeWebUrl(s) {
  return `${publicBaseUrl()}/runtime/${encodeURIComponent(s.id)}/`;
}

function runtimePingUrl(s) {
  return `${publicBaseUrl()}/api/runtime/${encodeURIComponent(s.id)}/ping`;
}

function runtimeState(s) {
  const p = processes.get(s.id);
  return {
    port: Number(s.runtimePort || runtimePortForServer(s)),
    web: runtimeWebUrl(s),
    url: runtimeWebUrl(s),
    ping: runtimePingUrl(s),
    pingUrl: runtimePingUrl(s),
    online: Boolean(p),
    status: p ? "online" : "offline"
  };
}

function pingLocalRuntime(port, pathname = "/") {
  return new Promise(resolve => {
    const started = Date.now();
    const req = http.request({
      hostname: "127.0.0.1",
      port,
      path: pathname || "/",
      method: "GET",
      timeout: 2500,
      headers: { "User-Agent": "FRANXX-PTERO-Runtime-Ping" }
    }, response => {
      response.resume();
      response.on("end", () => resolve({
        ok: response.statusCode >= 200 && response.statusCode < 500,
        status: response.statusCode || 0,
        responseTimeMs: Date.now() - started
      }));
    });
    req.on("timeout", () => req.destroy());
    req.on("error", error => resolve({
      ok: false,
      status: 0,
      responseTimeMs: Date.now() - started,
      error: error.code || error.message
    }));
    req.end();
  });
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
  if (s.suspended) throw new Error("Server sedang disuspend");
  if (processes.has(s.id)) throw new Error("Server already running");
  const cwd = serverRoot(s.id);
  fs.mkdirSync(cwd, { recursive: true });

  const runtimePort = Number(s.runtimePort || runtimePortForServer(s));
  s.runtimePort = runtimePort;

  // Private-use panel: commands are intentionally configurable per server.
  // PORT/FX_RUNTIME_PORT are injected so web runtimes can bind to the
  // dedicated reverse-proxy port exposed by the panel.
  const child = spawn(s.command, {
    cwd,
    env: { ...process.env, ...(s.env || {}), FX_SERVER_ID: s.id, PORT: String(runtimePort), FX_RUNTIME_PORT: String(runtimePort) },
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
    let settled = false;
    let forceTimer;
    let finalTimer;

    const finish = (ok, error) => {
      if (settled) return;
      settled = true;
      if (forceTimer) clearTimeout(forceTimer);
      if (finalTimer) clearTimeout(finalTimer);
      // Never remove a process from the map until the child actually closes.
      if (ok && processes.get(serverId) === p) processes.delete(serverId);
      if (ok) resolve(true);
      else reject(error || new Error("Process masih berjalan; restart dibatalkan agar tidak membuat proses ganda"));
    };

    child.once("close", () => finish(true));
    child.once("error", () => finish(true));

    const signalGroup = signal => {
      try {
        if (process.platform === "win32") child.kill(signal);
        else process.kill(-child.pid, signal);
        return true;
      } catch {
        try { return child.kill(signal); } catch { return false; }
      }
    };

    signalGroup("SIGTERM");

    forceTimer = setTimeout(() => {
      if (!settled) signalGroup(process.platform === "win32" ? undefined : "SIGKILL");
    }, 5000);

    // If the runtime is still alive, keep it registered and refuse restart.
    finalTimer = setTimeout(() => {
      finish(false, new Error("Runtime belum benar-benar berhenti. Coba STOP lagi sebelum RESTART."));
    }, 8000);
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
    let valid = false;
    const stored = String(user?.password || user?.passwordHash || "");
    if (user && stored) {
      // Accept legacy plaintext entries only long enough to migrate them to
      // bcrypt after a successful login. New accounts are always hashed.
      if (stored.startsWith("$2")) valid = await bcrypt.compare(password, stored);
      else valid = stored === password;
    }
    if (!user || !valid) return res.status(401).json({ error: "Username atau password salah" });

    if (!stored.startsWith("$2")) {
      user.password = await bcrypt.hash(password, 12);
      delete user.passwordHash;
      await writeUsers(users, `Migrate password for ${username}`);
    }

    const root = Boolean(user.root) || username === ROOT_USERNAME;
    if (root && !user.root) { user.root = true; await writeUsers(users, `Repair root flag for ${username}`); }
    const token = jwt.sign({ id: user.id, username, root }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: { id: user.id, username, root } });
  } catch (e) {
    res.status(500).json({ error: e.message || "Database akun tidak tersedia" });
  }
});

app.get("/api/me", auth, async (req, res) => {
  const users = await readUsers();
  const user = users.find(u => String(u.id) === String(req.user.id));
  if (!user) return res.status(401).json({ error: "Akun tidak ditemukan" });

  const root = Boolean(user.root) || String(user.username).toLowerCase() === ROOT_USERNAME;
  if (root && !user.root) {
    user.root = true;
    try { await writeUsers(users, `Repair root flag for ${user.username}`); } catch (e) {
      console.warn("[root] gagal menyimpan root flag:", e.message);
    }
  }
  res.setHeader("Cache-Control", "no-store");
  res.json({ id: user.id, username: user.username, root, createdAt: user.createdAt });
});

function rootAuth(req, res, next) {
  findUserById(req.user.id).then(async user => {
    if (!user) return res.status(401).json({ error: "Akun tidak ditemukan" });
    // The configured ROOT_USERNAME is authoritative. This makes admin access
    // survive older database records that have root:false or lack the flag.
    const configuredRoot = String(user.username || "").toLowerCase() === ROOT_USERNAME;
    if (!user.root && !configuredRoot) return res.status(403).json({ error: "Akses root/admin diperlukan" });
    if (configuredRoot && !user.root) {
      user.root = true;
      try {
        const users = await readUsers();
        const found = users.find(u => u.id === user.id || u.username === user.username);
        if (found) found.root = true;
        await writeUsers(users, `Repair root flag for ${user.username}`);
      } catch (e) {
        // Do not block the configured root account just because a database write
        // is temporarily unavailable; access is still authorized by username.
        console.warn("[root] gagal menyimpan root flag:", e.message);
      }
    }
    req.account = user;
    next();
  }).catch(e => res.status(500).json({ error: e.message }));
}

// ============================================================
// FRANXX PTERO — FULL ACCESS-KEY API
// API keys can provision users/servers and manage all servers.
// The first/root admin server is protected from deletion.
// ============================================================
const API_SCOPES = [
  "users:create",
  "users:read",
  "users:delete",
  "servers:create",
  "servers:read",
  "servers:start",
  "servers:stop",
  "servers:restart",
  "servers:suspend",
  "servers:unsuspend",
  "servers:delete",
  "servers:stats"
];

function normalizeScopes(scopes) {
  const incoming = Array.isArray(scopes) ? scopes.map(String) : [];
  const valid = incoming.filter(x => API_SCOPES.includes(x));

  // Backward compatibility: the old API-key screen only created
  // users:create + servers:create. Treat that legacy pair as a full
  // management key so existing tokens keep working after this update.
  if (valid.includes("users:create") && valid.includes("servers:create")) {
    return [...API_SCOPES];
  }

  return [...new Set(valid)];
}

function effectiveApiKeyScopes(key) {
  const scopes = normalizeScopes(key?.scopes);
  return scopes;
}

function hashAccessKey(secret) {
  return crypto.createHash("sha256").update(secret).digest("hex");
}

function apiKeyAuth(req, res, next) {
  (async () => {
    const h = req.headers.authorization || "";
    if (!h.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Access key diperlukan" });
    }

    const secret = h.slice(7).trim();
    if (!secret.startsWith("fx_live_")) {
      return res.status(401).json({ error: "Access key tidak valid" });
    }

    const keys = await readAccessKeys();
    const hash = hashAccessKey(secret);
    const key = keys.find(k => {
      if (k.revokedAt || typeof k.keyHash !== "string" || k.keyHash.length !== hash.length) return false;
      try {
        return crypto.timingSafeEqual(Buffer.from(k.keyHash), Buffer.from(hash));
      } catch {
        return false;
      }
    });

    if (!key) {
      return res.status(401).json({ error: "Access key tidak valid atau sudah direvoke" });
    }

    // Do not expose the raw key or hash to route handlers.
    req.apiKey = {
      id: key.id,
      name: key.name,
      ownerId: key.ownerId,
      scopes: effectiveApiKeyScopes(key)
    };

    next();
  })().catch(e => res.status(500).json({ error: e.message || "Access key database error" }));
}

function requireScope(scope) {
  return (req, res, next) => {
    if (!req.apiKey || !req.apiKey.scopes.includes(scope)) {
      return res.status(403).json({ error: `Scope ${scope} diperlukan` });
    }
    next();
  };
}

async function getAllServers() {
  return readServers();
}

async function getAllUsersForApi() {
  return readUsers();
}

function isServerOnline(serverId) {
  return processes.has(serverId);
}

function rootAccountForProtection(users) {
  const rootName = ROOT_USERNAME.toLowerCase();
  return users.find(u => String(u.username || "").toLowerCase() === rootName)
    || users.find(u => u.root === true)
    || null;
}

function protectedRootServerId(servers, users) {
  const root = rootAccountForProtection(users);
  if (!root) return null;

  const owned = servers
    .filter(s => String(s.ownerId) === String(root.id))
    .sort((a, b) => {
      const aa = new Date(a.createdAt || 0).getTime();
      const bb = new Date(b.createdAt || 0).getTime();
      return aa - bb || String(a.id).localeCompare(String(b.id));
    });

  return owned[0]?.id || null;
}

function apiServerView(server, users, protectedId) {
  const owner = users.find(u => String(u.id) === String(server.ownerId));
  return {
    id: server.id,
    name: server.name,
    ownerId: server.ownerId,
    owner: owner ? {
      id: owner.id,
      username: owner.username,
      root: Boolean(owner.root) || String(owner.username).toLowerCase() === ROOT_USERNAME.toLowerCase()
    } : null,
    runtime: server.runtime,
    entry: server.entry,
    command: server.command,
    memoryLimit: Number(server.memoryLimit || 512),
    status: isServerOnline(server.id) ? "online" : "offline",
    suspended: Boolean(server.suspended),
    suspendedAt: server.suspendedAt || null,
    suspendedReason: server.suspendedReason || null,
    protected: server.id === protectedId,
    createdAt: server.createdAt,
    runtimePort: Number(server.runtimePort || runtimePortForServer(server, users ? [] : [])),
    runtimeWeb: runtimeWebUrl(server),
    runtimeUrl: runtimeWebUrl(server),
    pingUrl: runtimePingUrl(server)
  };
}

app.get("/api/root/profile", auth, rootAuth, async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
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
  users.push(user);
  await writeUsers(users, `Create user ${username}`);
  res.json({ id: user.id, username: user.username, root: user.root, createdAt: user.createdAt });
});

app.get("/api/root/access-keys", auth, rootAuth, async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
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
  if (!/^[a-z0-9_]{3,24}$/.test(username)) {
    return res.status(400).json({ error: "Username 3-24 chars: a-z, 0-9, _" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password minimal 6 karakter" });
  }

  // Access keys can NEVER create/elevate a root account.
  const users = await readUsers();
  if (users.some(u => u.username === username)) {
    return res.status(409).json({ error: "Username sudah digunakan" });
  }

  const user = {
    id: id("usr"),
    username,
    password: await bcrypt.hash(password, 12),
    root: false,
    createdAt: new Date().toISOString()
  };

  users.push(user);
  await writeUsers(users, `API create user ${username}`);

  res.json({
    ok: true,
    id: user.id,
    username: user.username,
    root: false,
    createdAt: user.createdAt
  });
});

app.get("/api/access/users", apiKeyAuth, requireScope("users:read"), async (req, res) => {
  const users = await getAllUsersForApi();
  res.json({
    total: users.length,
    users: users.map(u => ({
      id: u.id,
      username: u.username,
      root: Boolean(u.root) || String(u.username).toLowerCase() === ROOT_USERNAME.toLowerCase(),
      createdAt: u.createdAt
    }))
  });
});

app.get("/api/access/users/:id", apiKeyAuth, requireScope("users:read"), async (req, res) => {
  const users = await getAllUsersForApi();
  const user = users.find(u => String(u.id) === String(req.params.id));
  if (!user) return res.status(404).json({ error: "User tidak ditemukan" });

  const servers = await getAllServers();
  res.json({
    id: user.id,
    username: user.username,
    root: Boolean(user.root) || String(user.username).toLowerCase() === ROOT_USERNAME.toLowerCase(),
    createdAt: user.createdAt,
    servers: servers.filter(s => String(s.ownerId) === String(user.id)).map(s => s.id)
  });
});

app.delete("/api/access/users/:id", apiKeyAuth, requireScope("users:delete"), async (req, res) => {
  const users = await getAllUsersForApi();
  const user = users.find(u => String(u.id) === String(req.params.id));
  if (!user) return res.status(404).json({ error: "User tidak ditemukan" });

  const isRoot = Boolean(user.root) || String(user.username).toLowerCase() === ROOT_USERNAME.toLowerCase();
  if (isRoot) {
    return res.status(403).json({ error: "Akun ROOT/ADMIN tidak boleh dihapus melalui API key" });
  }

  const servers = await getAllServers();
  const owned = servers.filter(s => String(s.ownerId) === String(user.id));
  const online = owned.filter(s => isServerOnline(s.id));
  if (online.length) {
    return res.status(409).json({
      error: "User masih memiliki server yang online. Stop server terlebih dahulu.",
      onlineServers: online.map(s => s.id)
    });
  }

  const nextServers = servers.filter(s => String(s.ownerId) !== String(user.id));
  await writeServers( nextServers);
  for (const s of owned) {
    await fsp.rm(serverRoot(s.id), { recursive: true, force: true });
  }

  const nextUsers = users.filter(u => String(u.id) !== String(user.id));
  await writeUsers(nextUsers, `API delete user ${user.username}`);

  res.json({
    ok: true,
    deletedUser: user.id,
    deletedServers: owned.map(s => s.id)
  });
});

// Create server through an access key. The owner must already exist and
// is always used as a normal account; the API key itself never becomes root.
app.post("/api/access/servers", apiKeyAuth, requireScope("servers:create"), async (req, res) => {
  const ownerId = String(req.body.userId || "").trim();
  if (!ownerId) return res.status(400).json({ error: "userId wajib diisi" });

  const users = await getAllUsersForApi();
  const owner = users.find(u => String(u.id) === ownerId);
  if (!owner) return res.status(404).json({ error: "User tujuan tidak ditemukan" });

  const name = safeName(req.body.name || "My Server");
  const runtime = ["node", "python", "custom"].includes(req.body.runtime) ? req.body.runtime : "node";
  const entry = safeName(req.body.entry || (runtime === "python" ? "main.py" : "index.js"));
  const command = String(req.body.command || (runtime === "python" ? "python main.py" : "node index.js")).trim();
  if (!command || command.length > 300) return res.status(400).json({ error: "Command tidak valid" });
  const memoryLimit = parseMemoryMB(req.body.memoryLimit, 512);

  const servers = await getAllServers();
  const s = {
    id: id("srv"),
    ownerId,
    name,
    runtime,
    entry,
    command,
    memoryLimit,
    env: {},
    runtimePort: runtimePortForServer({ id: "pending_" + crypto.randomBytes(4).toString("hex") }, servers),
    suspended: false,
    createdAt: new Date().toISOString()
  };
  s.runtimePort = runtimePortForServer(s, servers);

  servers.push(s);
  await writeServers( servers);
  await fsp.mkdir(serverRoot(s.id), { recursive: true });

  const protectedId = protectedRootServerId(servers, users);
  res.json({ ok: true, server: apiServerView(s, users, protectedId) });
});

app.get("/api/access/servers", apiKeyAuth, requireScope("servers:read"), async (req, res) => {
  const [servers, users] = await Promise.all([getAllServers(), getAllUsersForApi()]);
  const protectedId = protectedRootServerId(servers, users);
  const list = servers.map(s => apiServerView(s, users, protectedId));
  res.json({ total: list.length, servers: list });
});

app.get("/api/access/servers/total", apiKeyAuth, requireScope("servers:read"), async (req, res) => {
  const servers = await getAllServers();
  res.json({ total: servers.length });
});

app.get("/api/access/servers/:id", apiKeyAuth, requireScope("servers:read"), async (req, res) => {
  const [servers, users] = await Promise.all([getAllServers(), getAllUsersForApi()]);
  const s = servers.find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  const protectedId = protectedRootServerId(servers, users);
  res.json(apiServerView(s, users, protectedId));
});

async function getApiServerOr404(req, res) {
  const servers = await getAllServers();
  const s = servers.find(x => x.id === req.params.id);
  if (!s) {
    res.status(404).json({ error: "Server tidak ditemukan" });
    return null;
  }
  return { servers, server: s };
}

app.post("/api/access/servers/:id/start", apiKeyAuth, requireScope("servers:start"), async (req, res) => {
  const found = await getApiServerOr404(req, res);
  if (!found) return;
  const { server: s, servers } = found;
  if (s.suspended) return res.status(423).json({ error: "Server sedang disuspend", suspended: true });
  if (isServerOnline(s.id)) return res.json({ ok: true, status: "online", alreadyRunning: true });
  try {
    runServer(s);
    res.json({ ok: true, status: "online" });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post("/api/access/servers/:id/stop", apiKeyAuth, requireScope("servers:stop"), async (req, res) => {
  const found = await getApiServerOr404(req, res);
  if (!found) return;
  try {
    await stopServer(found.server.id);
    res.json({ ok: true, status: "offline" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/access/servers/:id/restart", apiKeyAuth, requireScope("servers:restart"), async (req, res) => {
  const found = await getApiServerOr404(req, res);
  if (!found) return;
  const s = found.server;
  if (s.suspended) return res.status(423).json({ error: "Server sedang disuspend", suspended: true });
  try {
    if (isServerOnline(s.id)) await stopServer(s.id);
    runServer(s);
    res.json({ ok: true, status: "online" });
  } catch (e) {
    broadcastServer(s.id, { type: "log", data: `\n[api restart error] ${e.message}\n` });
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/access/servers/:id/suspend", apiKeyAuth, requireScope("servers:suspend"), async (req, res) => {
  const found = await getApiServerOr404(req, res);
  if (!found) return;
  const s = found.server;
  try {
    if (isServerOnline(s.id)) await stopServer(s.id);
    s.suspended = true;
    s.suspendedAt = new Date().toISOString();
    s.suspendedReason = String(req.body.reason || "Suspended by API").slice(0, 200);
    await writeServers( found.servers);
    res.json({ ok: true, status: "offline", suspended: true, reason: s.suspendedReason });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/access/servers/:id/unsuspend", apiKeyAuth, requireScope("servers:unsuspend"), async (req, res) => {
  const found = await getApiServerOr404(req, res);
  if (!found) return;
  const s = found.server;
  s.suspended = false;
  s.suspendedAt = null;
  s.suspendedReason = null;
  await writeServers( found.servers);
  res.json({ ok: true, status: isServerOnline(s.id) ? "online" : "offline", suspended: false });
});

app.get("/api/access/servers/:id/stats", apiKeyAuth, requireScope("servers:stats"), async (req, res) => {
  const found = await getApiServerOr404(req, res);
  if (!found) return;
  const s = found.server;
  const p = processes.get(s.id);
  const disk = await directorySize(serverRoot(s.id));
  const proc = p ? readProcessStats(p.child.pid) : null;
  res.json({
    id: s.id,
    status: p ? "online" : "offline",
    suspended: Boolean(s.suspended),
    uptime: p ? Math.floor((Date.now() - p.startedAt) / 1000) : 0,
    memory: proc?.memory || 0,
    memoryLimit: Number(s.memoryLimit || 512) * 1024 * 1024,
    cpu: proc ? Number(proc.cpu.toFixed(1)) : 0,
    storage: disk,
    runtimeWeb: runtimeWebUrl(s),
    runtimeUrl: runtimeWebUrl(s),
    pingUrl: runtimePingUrl(s),
    runtimePort: Number(s.runtimePort || runtimePortForServer(s))
  });
});

app.delete("/api/access/servers/:id", apiKeyAuth, requireScope("servers:delete"), async (req, res) => {
  const found = await getApiServerOr404(req, res);
  if (!found) return;
  const { servers, server: s } = found;
  const users = await getAllUsersForApi();
  const protectedId = protectedRootServerId(servers, users);

  if (s.id === protectedId) {
    return res.status(403).json({
      error: "Server ROOT/ADMIN pertama dilindungi dan tidak boleh dihapus melalui API"
    });
  }

  // API deletion is intentionally offline-only.
  if (isServerOnline(s.id)) {
    return res.status(409).json({
      error: "Server masih online. Stop server terlebih dahulu sebelum delete."
    });
  }

  await writeServers( servers.filter(x => x.id !== s.id));
  await fsp.rm(serverRoot(s.id), { recursive: true, force: true });

  res.json({ ok: true, deleted: s.id });
});

app.get("/api/access/overview", apiKeyAuth, requireScope("servers:read"), async (req, res) => {
  const [servers, users] = await Promise.all([getAllServers(), getAllUsersForApi()]);
  const protectedId = protectedRootServerId(servers, users);
  const online = servers.filter(s => isServerOnline(s.id)).length;
  const suspended = servers.filter(s => Boolean(s.suspended)).length;

  res.json({
    users: users.length,
    servers: servers.length,
    onlineServers: online,
    offlineServers: servers.length - online,
    suspendedServers: suspended,
    protectedRootServerId: protectedId
  });
});

// ---------------------------------------------------------------------------
// Runtime Web / Ping
// ---------------------------------------------------------------------------
app.get("/runtime/:id", async (req, res) => {
  res.redirect(302, `/runtime/${encodeURIComponent(req.params.id)}/`);
});

app.use("/runtime/:id", async (req, res, next) => {
  try {
    const servers = await getAllServers();
    const s = servers.find(x => String(x.id) === String(req.params.id));
    if (!s) return res.status(404).send("Runtime tidak ditemukan");
    if (!isServerOnline(s.id)) return res.status(503).send("Runtime sedang offline");

    const port = Number(s.runtimePort || runtimePortForServer(s, servers));
    const targetPath = req.path || "/";
    const headers = { ...req.headers, host: `127.0.0.1:${port}`, "x-forwarded-host": req.headers.host || "", "x-forwarded-proto": req.protocol };
    delete headers.connection;
    delete headers["content-length"];

    const proxy = http.request({
      hostname: "127.0.0.1",
      port,
      method: req.method,
      path: targetPath + (req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : ""),
      headers
    }, upstream => {
      res.status(upstream.statusCode || 502);
      for (const [key, value] of Object.entries(upstream.headers)) {
        if (value !== undefined && key.toLowerCase() !== "connection") res.setHeader(key, value);
      }
      upstream.pipe(res);
    });

    proxy.on("error", err => {
      if (!res.headersSent) res.status(502).send(`Runtime proxy error: ${err.message}`);
      else res.end();
    });
    req.pipe(proxy);
  } catch (e) {
    next(e);
  }
});

app.get("/api/runtime/:id/ping", auth, async (req, res) => {
  const servers = await getAllServers();
  const s = servers.find(x => String(x.id) === String(req.params.id) && String(x.ownerId) === String(req.user.id));
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  const runtime = runtimeState(s);
  const ping = runtime.online ? await pingLocalRuntime(runtime.port, "/") : { ok: false, status: 0, responseTimeMs: 0, error: "RUNTIME_OFFLINE" };
  res.json({ ok: ping.ok, serverId: s.id, status: runtime.status, runtimeWeb: runtime.web, pingUrl: runtime.pingUrl, port: runtime.port, ...ping });
});

app.get("/api/access/servers/:id/runtime", apiKeyAuth, requireScope("servers:read"), async (req, res) => {
  const servers = await getAllServers();
  const s = servers.find(x => String(x.id) === String(req.params.id));
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  const runtime = runtimeState(s);
  const ping = runtime.online ? await pingLocalRuntime(runtime.port, "/") : { ok: false, status: 0, responseTimeMs: 0, error: "RUNTIME_OFFLINE" };
  res.json({ ok: true, serverId: s.id, name: s.name, runtime, ping });
});

app.get("/api/access/servers/:id/ping", apiKeyAuth, requireScope("servers:stats"), async (req, res) => {
  const servers = await getAllServers();
  const s = servers.find(x => String(x.id) === String(req.params.id));
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  const runtime = runtimeState(s);
  const ping = runtime.online ? await pingLocalRuntime(runtime.port, String(req.query.path || "/")) : { ok: false, status: 0, responseTimeMs: 0, error: "RUNTIME_OFFLINE" };
  res.status(ping.ok ? 200 : 503).json({ ...ping, serverId: s.id, runtimeWeb: runtime.web, pingUrl: runtime.pingUrl, port: runtime.port });
});

app.get("/api/servers", auth, async (req, res) => {
  const servers = await readServers();
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

  const servers = await readServers();
  const s = {
    id: id("srv"), ownerId, name, runtime, entry, command,
    memoryLimit, env: {}, runtimePort: 0, createdAt: new Date().toISOString()
  };
  s.runtimePort = runtimePortForServer(s, servers);
  servers.push(s);
  await writeServers( servers);
  await fsp.mkdir(serverRoot(s.id), { recursive: true });
  res.json(publicServer(s));
});

app.delete("/api/servers/:id", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  await stopServer(s.id);
  const servers = await readServers();
  await writeServers( servers.filter(x => x.id !== s.id));
  await fsp.rm(serverRoot(s.id), { recursive: true, force: true });
  res.json({ ok: true });
});

app.post("/api/servers/:id/start", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  if (s.suspended) return res.status(423).json({ error: "Server sedang disuspend", suspended: true });
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
  if (s.suspended) return res.status(423).json({ error: "Server sedang disuspend", suspended: true });
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
  const servers = await readServers();
  const s = servers.find(x => x.id === req.params.id && x.ownerId === req.user.id);
  if (!s) return res.status(404).json({error:"Server tidak ditemukan"});
  const command = String(req.body.command || "").trim();
  const entry = safeName(req.body.entry || s.entry);
  const memoryLimit = parseMemoryMB(req.body.memoryLimit, s.memoryLimit || 512);
  if (!command || command.length > 300) return res.status(400).json({error:"Command tidak valid"});
  s.command = command;
  s.entry = entry;
  s.memoryLimit = memoryLimit;
  await writeServers( servers);
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

async function bootstrap() {
  try {
    await importLegacyIfNeeded();
    await ensureRootAccount();
    server.listen(PORT, HOST, () => {
      console.log(`FX PROJECT — FRANXX PTERO running on ${HOST}:${PORT}`);
      console.log(`[storage] Supabase metadata DB + Railway Volume files: ${DATA}`);
    });
  } catch (e) {
    console.error(`[startup] gagal menyiapkan database: ${e.message}`);
    process.exit(1);
  }
}
bootstrap();
