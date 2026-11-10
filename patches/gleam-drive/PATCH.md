# gleam-drive — patch guide

**Challenge:** gleam-drive (2024, Web)
**Primary source:** `gemastik-xvii-final/gleam-drive/src/app/service.gleam & crypto_ffi.erl`
**Audit status:** 3 finding(s) — VALID (High), VALID (High), VALID (Medium)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Celah 1: Path Traversal pada Upload & Urutan Insert DB Sebelum Simpan File
- **Status:** VALID / High / confidence High / CWE-22
- **Root cause:** Attacker meng-upload file dengan nama `../../../../flag.txt`. Ketika `util.upload_file` mencoba menulis ke `/flag.txt`, operasi tulis gagal (karena `/flag.txt` sudah ada/read-only), TAPI `repository.create_upload` sudah terlanjur menyimpan `../../../../flag.txt` ke database! Selanjutnya attacker tinggal membuat link share untuk file tersebut dan mendownloadnya untuk mendapatkan isi `/flag.txt`.
- **Exploit page:** `exploits/gleam-drive/exploit.py --vuln traversal`

**Vulnerable pattern**
```text
let user_dir = filepath.join(config.upload_dir, session.email)
let filepath = filepath.join(user_dir, file.file_name)
case repository.create_upload(db, session.email, file.file_name, filesize) {
  Ok(_) -> util.upload_file(file.path, filepath)
  Error(_) -> Error("Failed to upload file")
}
```

**Patched pattern**
```text
// 1. Bersihkan nama file dengan mengambil basename-nya saja (membuang ../ dan /)
let clean_name = filepath.base_name(file.file_name)
let user_dir = filepath.join(config.upload_dir, filepath.base_name(session.email))
let dest_path = filepath.join(user_dir, clean_name)

// 2. Simpan file ke disk DULU, jika berhasil baru masukkan ke database!
case util.upload_file(file.path, dest_path) {
  Ok(_) -> repository.create_upload(db, session.email, clean_name, filesize)
  Error(_) -> Error("Failed to upload file")
}
```

**Verification**
- Use `filepath.base_name(file.file_name)` and reject `..`/absolute names.
- Write the file before inserting the DB row; only insert on success.
- Validate the resolved path is inside the user's upload directory at download time.


### 2. AES-128-ECB session/share tokens without integrity (key readable via traversal)
- **Status:** VALID / High / confidence Medium / CWE-347
- **Root cause:** Tokens have no MAC and the AES key is recoverable via the upload traversal. An attacker can forge a session for any known email or a share token pointing at `/flag.txt`; the download handler trusts the token's `filepath`.
- **Exploit page:** `exploits/gleam-drive/exploit.py --vuln key`

**Vulnerable pattern**
```text
encrypt(Key, Data) -> crypto:crypto_one_time(aes_128_ecb, Key, Data, true).
% no HMAC, no expiry binding in the share token
```

**Patched pattern**
```text
% Use AES-GCM or AES-CBC + HMAC-SHA256; keep the key outside the web root and never derive trust from the token alone.
% Validate shared.filepath against the user's upload directory and the database record.
```

**Verification**
- Use AES-GCM or encrypt-then-MAC; reject tampered tokens.
- Store the key outside the upload/web-readable tree.
- Validate `shared.filepath` against the DB record and the user's directory.
- A forged token must be rejected; a legitimate share must still work.


### 3. Reflected/stored XSS via unescaped error and filename rendering
- **Status:** VALID / Medium / confidence High / CWE-79
- **Root cause:** `GET /error?message=<script>alert(1)</script>` reflects the payload unescaped. A filename containing HTML is also rendered unescaped on the details page, giving stored XSS against the file owner.
- **Exploit page:** `exploits/gleam-drive/exploit.py --vuln xss`

**Vulnerable pattern**
```text
pub fn render_error_html(message: String) -> String {
  string.replace(error_html, "ERROR_MESSAGE", message)
}
```

**Patched pattern**
```text
// HTML-escape message/filename before substitution, or use a templating engine with autoescaping.
pub fn render_error_html(message: String) -> String {
  string.replace(error_html, "ERROR_MESSAGE", html_escape(message))
}
```

**Verification**
- HTML-escape all interpolated values; the payload must appear as text.
- Normal error messages and filenames must still display.

## Reference diffs
No applyable diff is shipped for this challenge. The before/after patterns above are the reference implementation; the change spans protocol/state design or lacks a locally runnable target.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
