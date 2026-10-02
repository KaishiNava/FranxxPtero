# FX PROJECT — FRANXX PTERO

Private lightweight Pterodactyl-style panel for Railway.

## Features
- Register / login
- JSON users + server metadata
- JWT session stored in LocalStorage
- Multiple servers per user
- Start / stop / restart process
- Live WebSocket console
- Runtime status + uptime + RAM display
- Console stdin
- Upload files
- ZIP upload + one-click UNZIP
- ZIP path traversal protection
- File browser
- Create folder
- Delete file/folder
- Built-in file editor
- Configurable startup command
- Responsive mobile UI
- Animated dark FRANXX interface
- Railway PORT support

## Run
```bash
npm install
npm start
```

## Railway
Set:
- `JWT_SECRET` = long random secret
- `MAX_UPLOAD_MB` = optional, default 100

The app uses Railway's `PORT` automatically.

## Important
This is intentionally a private-use process runner. Uploaded/user-provided commands execute in the panel's runtime environment. Do not expose this publicly without proper authentication hardening, rate limits, resource limits, sandbox/container isolation, and persistent storage.

For persistence across Railway container recreation/redeploy, use a Railway Volume or external database/object storage. JSON/filesystem storage is suitable for private testing only.
