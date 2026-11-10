# blogpost — patch guide

**Challenge:** blogpost (2025, Web)
**Primary source:** `gemastik18-final/services/blogpost/chall/app.py`
**Audit status:** 3 finding(s) — VALID (Critical), VALID (High), INVALID (Info)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Celah 1: Command Injection & Path Traversal pada Upload Gambar
- **Status:** VALID / Critical / confidence High / CWE-78
- **Root cause:** Fungsi allowed_file() hanya mengecek akhiran ekstensi (.jpg/.png). Attacker bisa memberi nama file 'tes.jpg; cat /flag.txt > static/out.txt; #.jpg'. Saat masuk ke os.system(), perintah cat /flag.txt ikut dieksekusi oleh server.
- **Exploit page:** `exploits/blogpost/exploit.py --vuln cmdi`

**Vulnerable pattern**
```text
original_filename = file.filename
save_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
file.save(save_path)

cmd = f"exiftool {save_path}"
meta_file = save_path + ".meta"
full_cmd = f"{cmd} > {meta_file} 2>&1"
os_status = os.system(full_cmd)
```

**Patched pattern**
```text
from werkzeug.utils import secure_filename
import uuid, subprocess

original_filename = secure_filename(file.filename or "")
if not original_filename or not allowed_file(original_filename):
    return redirect(url_for("create_post"))

# Ganti nama file dengan UUID acak agar 100% bersih dari karakter shell
ext = original_filename.rsplit(".", 1)[1].lower()
stored_name = f"{uuid.uuid4().hex}.{ext}"
save_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
file.save(save_path)

# Panggil exiftool TANPA shell menggunakan argumen list dan pemisah '--'
proc = subprocess.run(
    ["exiftool", "--", save_path],
    capture_output=True, text=True, timeout=10
)
metadata_text = proc.stdout if proc.stdout else "no-metadata"
```

**Verification**
- Upload the same filename; `secure_filename()`/UUID storage must remove `;`, spaces and `#`.
- The injected command must not run (no `static/leak.txt`, no callback).
- Upload a normal PNG/JPEG and confirm metadata extraction still works.


### 2. Celah 2: Stacked SQL Injection lewat Metadata Gambar
- **Status:** VALID / High / confidence High / CWE-89
- **Root cause:** Walaupun metadata_text keluar dari exiftool, isi metadata EXIF di dalam gambar dikendalikan oleh attacker sebelum di-upload. Attacker bisa mengisi metadata Comment gambar dengan: a'; UPDATE users SET role='admin' WHERE username='attacker';-- sehingga akunnya berubah menjadi admin dan bisa membuka /profile untuk melihat flag.
- **Exploit page:** `exploits/blogpost/exploit.py --vuln sqli`

**Vulnerable pattern**
```text
metadata_insert = f"UPDATE posts SET metadata = '{metadata_text}' WHERE id = {post_id};"
db.executescript(metadata_insert)
```

**Patched pattern**
```text
db.execute(
    "UPDATE posts SET metadata = ? WHERE id = ?",
    (metadata_text, post_id)
)
db.commit()
```

**Verification**
- Upload the same metadata; the metadata must be stored literally and the role must remain `user`.
- `/profile` must not show the flag.
- Normal image metadata must still be displayed.


### 3. Celah 3: Server-Side Template Injection (SSTI) di Halaman /profile
- **Status:** INVALID / Info / confidence High / N/A
- **Root cause:** Claim not supported: the `.replace()` target uses `{{ user.username }}`, but `templates/profile.html` contains `{{ user['username'] }}`, so the substitution never occurs and the username never becomes template source.
- **Exploit page:** none (no confirmed exploit for this claim)

No patch is applicable: the claim is not supported by the source. Do not add a workaround for this item; keep the existing safe behavior.

**Why the claim fails:** `templates/profile.html` uses `{{ user['username'] }}` (bracket notation), while `app.py` calls `profile_template.replace("{{ user.username }}", username)` (dot notation). The replace is a no-op, so the username is never inserted into the template source. Jinja2 renders the database value as an autoescaped variable; `{{7*7}}` is displayed literally, not evaluated.
## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik18-final/services/blogpost
patch -p1 --dry-run < ../../../patches/fix-upload-and-metadata.diff
patch -p1 < ../../../patches/fix-upload-and-metadata.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
