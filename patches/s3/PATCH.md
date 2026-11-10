# s3 — patch guide

**Challenge:** s3 (2023, Web)
**Primary source:** `gemastik-xvi-final/services/s3/src/main.py`
**Audit status:** 1 finding(s) — VALID (High)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Absolute Path Behavior pada os.path.join() -> Arbitrary File Read (/flag.txt)
- **Status:** VALID / High / confidence High / CWE-22
- **Root cause:** Developer sudah memblokir `'..'` tetapi lupa bahwa di Python, `os.path.join('uploads/', '/flag.txt')` menghasilkan `'/flag.txt'`. Attacker cukup mengakses `/download?filename=/flag.txt` (tanpa memakai `..` sama sekali) untuk membaca flag!
- **Exploit page:** `exploits/s3/exploit.py`

**Vulnerable pattern**
```text
@app.route("/download", methods=["GET"])
def donlot():
    filename = request.args.get("filename")
    assert filename and ".." not in filename
    return open(os.path.join("uploads/", filename)).read()
```

**Patched pattern**
```text
from werkzeug.utils import secure_filename

@app.route("/download", methods=["GET"])
def donlot():
    filename = secure_filename(request.args.get("filename") or "")
    assert filename and ".." not in filename and not os.path.isabs(filename)
    base = os.path.realpath("uploads")
    target = os.path.realpath(os.path.join(base, filename))
    assert os.path.commonpath([base, target]) == base
    return open(target).read()
```

**Verification**
- Reject absolute paths and use `secure_filename`/`realpath` with a base-directory prefix check.
- `/flag.txt` and `../` must both be rejected; a normal uploaded file must still download.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvi-final/services/s3
patch -p1 --dry-run < ../../../patches/fix-download-confinement.diff
patch -p1 < ../../../patches/fix-download-confinement.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
