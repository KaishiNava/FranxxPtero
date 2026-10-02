# FX PROJECT — FRANXX PTERO

Lightweight private-use panel untuk Railway / Node.js.

## Fitur
- Register / login
- JSON user + server storage
- JWT session 30 hari di LocalStorage
- Multi-server per user
- Start / stop / restart process
- Realtime console via WebSocket
- Upload file
- File browser
- Create folder
- Delete file/folder
- Edit/save file
- Configurable startup command
- Responsive mobile UI
- Railway PORT support

## Local
```bash
npm install
npm start
```

Buka `http://localhost:3000`.

## Railway
1. Upload project ke GitHub.
2. Buat Railway service dari repository.
3. Railway akan menjalankan `npm start`.
4. Set variable:
   - `JWT_SECRET` = random secret panjang
   - `MAX_UPLOAD_MB` = misalnya `100`
5. Generate domain Railway.

## Catatan persistence
Folder `data/` berisi users, server metadata, dan file server. Railway container filesystem bukan tempat ideal untuk persistence jangka panjang. Untuk private testing, ini cukup. Untuk deployment yang harus survive redeploy/recreate, gunakan Railway Volume atau object/database storage.

## Keamanan
Panel ini dibuat untuk private use. Jangan membuka endpoint ini ke publik tanpa menambahkan rate limit, HTTPS, admin controls, resource limits, dan sandbox/container isolation.
