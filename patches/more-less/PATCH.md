# more-less — patch guide

**Challenge:** more-less (2024, Web)
**Primary source:** `gemastik-xvii-final/more-less/src/main.py`
**Audit status:** 1 finding(s) — VALID (Critical)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Unsafe YAML Deserialization -> Remote Code Execution (RCE)
- **Status:** VALID / Critical / confidence High / CWE-502
- **Root cause:** Attacker cukup meng-upload file YAML berisi `!!python/object/apply:subprocess.check_output [['cat', '/flag.txt']]`. Saat `yaml.load(..., Loader=Loader)` membaca file tersebut, PyYAML langsung menjalankan perintah itu dan mengembalikan isi `/flag.txt` di response HTTP!
- **Exploit page:** `exploits/more-less/exploit.py`

**Vulnerable pattern**
```text
from yaml import load, Loader

@app.post("/")
def upload_file(file: UploadFile = File(...)):
    return load(file.file, Loader=Loader)
```

**Patched pattern**
```text
from yaml import safe_load

@app.post("/")
def upload_file(file: UploadFile = File(...)):
    return safe_load(file.file)
```

**Verification**
- Use `yaml.safe_load()` and reject custom tags.
- The malicious YAML must return a parse error or plain data, never command output.
- Normal YAML documents must still parse.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvii-final/more-less
patch -p1 --dry-run < ../../patches/fix-safe-yaml.diff
patch -p1 < ../../patches/fix-safe-yaml.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
