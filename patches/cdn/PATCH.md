# cdn — patch guide

**Challenge:** cdn (2025, Web)
**Primary source:** `gemastik18-final/services/cdn/chall/app.py`
**Audit status:** 2 finding(s) — VALID (Critical), VALID (Medium)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Celah 1: SSTI lewat Metadata EXIF Gambar (File Name / Date Created)
- **Status:** VALID / Critical / confidence High / CWE-1336
- **Root cause:** Pemanggilan exiftool di challenge ini sudah aman (pakai subprocess list). Namun, attacker bisa memodifikasi tag EXIF 'Date Created' pada gambarnya menjadi '{{ lipsum.__globals__["os"].popen("cat /flag.txt").read() }}'. Saat halaman /post/<id> dibuka, string itu ditempel ke template source dan dieksekusi oleh render_template_string().
- **Exploit page:** `exploits/cdn/exploit.py --vuln ssti`

**Vulnerable pattern**
```text
metadata_snippet_html = f"<pre>File Name: {file_name_val}\nDate Created: {date_created_val}</pre>"
page_src = tpl_src.replace(placeholder, metadata_snippet_html)
return render_template_string(page_src, post=post)
```

**Patched pattern**
```text
# Kirim file_name dan date_created sebagai variabel ke render_template (otomatis di-autoescape)
return render_template(
    "view_post.html",
    post=post,
    file_name=file_name_val,
    date_created=date_created_val
)
# Lalu di dalam templates/view_post.html tulis:
# <pre>File Name: {{ file_name }}
Date Created: {{ date_created }}</pre>
```

**Verification**
- Upload the same image; the `Date Created` value must be escaped/displayed literally.
- No Jinja evaluation may occur (`{{7*7}}` must stay `{{7*7}}`).
- Normal metadata display and image serving must still work.


### 2. Celah 2: Open Redirect pada Parameter next
- **Status:** VALID / Medium / confidence High / CWE-601
- **Root cause:** URL '//evil.com' diawali dengan karakter '/', sehingga lolos dari pengecekan startswith('/'), tetapi browser mengartikan '//' sebagai protokol relatif menuju domain eksternal evil.com.
- **Exploit page:** `exploits/cdn/exploit.py --vuln redirect`

**Vulnerable pattern**
```text
next_url = request.args.get("next") or request.form.get("next")
if next_url and next_url.startswith("/"):
    return redirect(next_url)
```

**Patched pattern**
```text
from urllib.parse import urlparse
next_url = request.args.get("next") or request.form.get("next") or ""
parsed = urlparse(next_url)
if next_url.startswith("/") and not next_url.startswith("//") and not parsed.netloc:
    return redirect(next_url)
return redirect(url_for("gallery"))
```

**Verification**
- `next=//evil.example` must redirect to the gallery, not an external host.
- `next=/gallery` must still work.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik18-final/services/cdn
patch -p1 --dry-run < ../../../patches/fix-redirect-validation.diff
patch -p1 < ../../../patches/fix-redirect-validation.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
