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
const AdmZip = require("adm-zip");

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";
const DATA = path.join(__dirname, "data");
const SERVERS_DIR = path.join(DATA, "servers");
const USERS_FILE = path.join(DATA, "users.json");
const SERVERS_FILE = path.join(DATA, "servers.json");
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 100);

for (const p of [DATA, SERVERS_DIR]) fs.mkdirSync(p, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]");
if (!fs.existsSync(SERVERS_FILE)) fs.writeFileSync(SERVERS_FILE, "[]");

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
    status: processes.has(s.id) ? "online" : "offline"
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
    windowsHide: true
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
  if (!p) return false;
  try {
    if (process.platform === "win32") p.child.kill();
    else {
      p.child.kill("SIGTERM");
      setTimeout(() => {
        if (!p.child.killed) try { p.child.kill("SIGKILL"); } catch {}
      }, 5000);
    }
  } catch {}
  return true;
}

app.post("/api/auth/register", async (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!/^[a-z0-9_]{3,24}$/.test(username))
    return res.status(400).json({ error: "Username 3-24 chars: a-z, 0-9, _" });
  if (password.length < 6) return res.status(400).json({ error: "Password minimal 6 karakter" });

  const users = await readJson(USERS_FILE);
  if (users.some(u => u.username === username))
    return res.status(409).json({ error: "Username sudah digunakan" });

  const user = {
    id: id("usr"),
    username,
    passwordHash: await bcrypt.hash(password, 12),
    createdAt: new Date().toISOString()
  };
  users.push(user);
  await writeJson(USERS_FILE, users);
  const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: { id: user.id, username } });
});

app.post("/api/auth/login", async (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const users = await readJson(USERS_FILE);
  const user = users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: "Username atau password salah" });
  const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: "30d" });
  res.json({ token, user: { id: user.id, username } });
});

app.get("/api/me", auth, (req, res) => res.json({ id: req.user.id, username: req.user.username }));

app.get("/api/servers", auth, async (req, res) => {
  const servers = await readJson(SERVERS_FILE);
  res.json(servers.filter(s => s.ownerId === req.user.id).map(publicServer));
});

app.post("/api/servers", auth, async (req, res) => {
  const name = safeName(req.body.name || "My Server");
  const runtime = ["node", "python", "custom"].includes(req.body.runtime) ? req.body.runtime : "node";
  const entry = safeName(req.body.entry || (runtime === "python" ? "main.py" : "index.js"));
  const command = String(req.body.command || (runtime === "python" ? "python main.py" : "node index.js")).trim();
  if (!command || command.length > 300) return res.status(400).json({ error: "Command tidak valid" });
  const memoryLimit = parseMemoryMB(req.body.memoryLimit, 512);

  const servers = await readJson(SERVERS_FILE);
  const s = {
    id: id("srv"), ownerId: req.user.id, name, runtime, entry, command,
    memoryLimit, env: {}, createdAt: new Date().toISOString()
  };
  servers.push(s);
  await writeJson(SERVERS_FILE, servers);
  await fsp.mkdir(serverRoot(s.id), { recursive: true });
  res.json(publicServer(s));
});

app.delete("/api/servers/:id", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  stopServer(s.id);
  const servers = await readJson(SERVERS_FILE);
  await writeJson(SERVERS_FILE, servers.filter(x => x.id !== s.id));
  await fsp.rm(serverRoot(s.id), { recursive: true, force: true });
  res.json({ ok: true });
});

app.post("/api/servers/:id/start", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  try { runServer(s); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/api/servers/:id/stop", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  stopServer(s.id);
  res.json({ ok: true });
});

app.post("/api/servers/:id/restart", auth, async (req, res) => {
  const s = await getOwnedServer(req.user.id, req.params.id);
  if (!s) return res.status(404).json({ error: "Server tidak ditemukan" });
  stopServer(s.id);
  setTimeout(() => { try { runServer(s); } catch (e) { broadcastServer(s.id, { type: "log", data: `\n[restart error] ${e.message}\n` }); } }, 700);
  res.json({ ok: true });
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

server.listen(PORT, HOST, () => {
  console.log(`FX PROJECT — FRANXX PTERO running on ${HOST}:${PORT}`);
});
