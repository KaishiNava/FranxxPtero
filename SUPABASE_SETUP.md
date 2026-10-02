# FRANXX PTERO — Supabase + Railway

## 1. Supabase

Buka Supabase → SQL Editor, lalu jalankan seluruh isi `supabase.sql`.

Tabel yang dibuat:

- `users` — akun panel + root/admin
- `api_keys` — access key, hanya hash key yang disimpan
- `servers` — metadata server/runtime

Node backend memakai `SUPABASE_SERVICE_ROLE_KEY`. Key ini hanya boleh berada di Railway Variables dan **jangan** dimasukkan ke `public/app.js`.

## 2. Railway Variables

Minimal:

```env
PORT=3000
DATA_DIR=/data
SERVERS_DIR=/data/servers
JWT_SECRET=isi-random-panjang
SUPABASE_URL=https://PROJECT_REF.supabase.co
SUPABASE_SERVICE_ROLE_KEY=isi_service_role_key
ROOT_USERNAME=admin
ROOT_PASSWORD=password_admin_kamu
PANEL_URL=https://nel.elaina-cloud.my.id
RUNTIME_PORT_START=10000
RUNTIME_PORT_END=20000
MAX_UPLOAD_MB=100
```

Mount Railway Volume ke `/data`.

## 3. GitHub

GitHub **tidak lagi dipakai untuk menyimpan perubahan runtime**.

Kalau `GITHUB_TOKEN`, `GITHUB_OWNER`, dan `GITHUB_REPO` masih diisi, backend hanya membacanya untuk **one-time legacy import** saat Supabase masih belum memiliki record tersebut. Setelah data masuk ke Supabase, variabel GitHub boleh dihapus.

Membuat user, API key, server, suspend, unsuspend, atau settings server tidak melakukan commit ke GitHub sehingga tidak memicu redeploy GitHub → Railway.

## 4. Penyimpanan server

Supabase menyimpan metadata/config server.

File asli server tetap di Railway Volume:

```text
/data/servers/srv_xxxxx/
```

Jadi ZIP, `index.js`, `package.json`, upload, extract, dan file runtime tidak disimpan di Supabase.

## 5. Root/Admin

Saat backend boot:

1. record root lama dari legacy source diimpor bila ada;
2. `ROOT_USERNAME` selalu diperlakukan sebagai root;
3. bila username root belum ada dan `ROOT_PASSWORD` diisi, akun root dibuat di Supabase;
4. `/api/me` membaca status root langsung dari Supabase;
5. menu `Profile` dan `API / Access Keys` hanya muncul untuk root.

Jika login sudah pernah dilakukan sebelum migrasi, hapus token lama dari browser/localStorage dengan logout lalu login lagi setelah deployment baru aktif.
