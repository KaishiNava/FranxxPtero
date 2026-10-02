# FRANXX PTERO — FX PROJECT

Private-use lightweight server and bot control panel.

## Included

- Login authentication with JWT
- Public registration disabled
- Root/Admin-only Profile page
- Root/Admin-only API / Access Keys page
- Root/Admin can create normal users or root/admin users
- Access keys with `users:create` and `servers:create` scopes
- Access-key secrets are shown once and only SHA-256 hashes are stored
- Account database stored as JSON in GitHub when GitHub variables are configured
- Access-key database stored as JSON in GitHub when GitHub variables are configured
- Node.js / Python / Custom runtime commands
- Start / stop / restart server runtime
- Live WebSocket console + stdin
- Live RAM, CPU, storage and uptime monitor
- Configurable RAM allocation per server
- Multi-file upload
- ZIP upload + manual UNZIP
- Multi-select files
- Bulk delete
- Make/download selected files as ZIP
- File editor
- Server settings
- Responsive mobile UI
- FRANXX PTERO logo, banner and favicon branding
- Footer: `© 2025 - 2026 KYZX FRANXX DEV`

## Account JSON format

The GitHub user database uses the requested shape. The `password` field contains a bcrypt hash, never the plaintext password:

```json
[
  {
    "id": "usr_xxx",
    "username": "admin",
    "password": "$2b$12$...",
    "root": true,
    "createdAt": "2026-10-02T00:00:00.000Z"
  }
]
```

Normal users use `root: false`.

Access keys are stored separately in `database/access-keys.json`; only the SHA-256 hash of the secret is stored.

## GitHub configuration

Copy `.env.example` to your deployment environment and set:

- `GITHUB_TOKEN` — GitHub token with Contents read/write access to the repository.
- `GITHUB_OWNER` — repository owner.
- `GITHUB_REPO` — repository name. A private repository is recommended.
- `GITHUB_BRANCH` — branch, normally `main`.
- `GITHUB_USERS_PATH` — default `database/users.json`.
- `GITHUB_KEYS_PATH` — default `database/access-keys.json`.
- `ROOT_USERNAME` — username for the first root account.
- `ROOT_PASSWORD` — password for the first root account.

On first login, if the GitHub user JSON is empty/missing and `ROOT_PASSWORD` is set, the panel creates the initial root account automatically.

Server files and server metadata remain on the panel host as before; the GitHub JSON database is for accounts and access keys.

## Access-key API

Use:

```http
Authorization: Bearer fx_live_xxxxxxxxx
```

Create a normal user:

```http
POST /api/access/users
Content-Type: application/json

{
  "username": "botuser",
  "password": "strong-password"
}
```

Create a server for an existing user:

```http
POST /api/servers
Authorization: Bearer fx_live_xxxxxxxxx
Content-Type: application/json

{
  "userId": "usr_xxx",
  "name": "My Bot",
  "runtime": "node",
  "entry": "index.js",
  "command": "node index.js",
  "memoryLimit": 512
}
```

An access key cannot create a root account. Root elevation is only available from the root/admin panel.

## Run

```bash
npm install
npm start
```

Set `JWT_SECRET` in production. Optional upload limit can be changed with `MAX_UPLOAD_MB`.

## Branding

Logo:
`https://zfile.web.id/PBe7sdw.png`

Banner:
`https://zfile.web.id/ptVnzVN.png`

## V2 UI / account isolation

- Create Server is accessed from the ☰ sidebar.
- Dashboard no longer shows a Create Server button.
- Header branding stays left-aligned on Android/mobile.
- Every server has an ownerId and all server/file/runtime APIs verify ownership.
- Upload storage also verifies server ownership before writing files.
