# warmup — patch guide

**Challenge:** warmup (2025, Web)
**Primary source:** `gemastik18-final/services/warmup/src/main.go`
**Audit status:** 1 finding(s) — VALID (High)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Path Traversal / Arbitrary File Read (LFI)
- **Status:** VALID / High / confidence High / CWE-22
- **Root cause:** Developer mengira filepath.Join otomatis mengurung akses di dalam /opt/files/. Padahal jika user mengirim ?file=../../flag.txt, hasil filepath.Join adalah /flag.txt dan langsung dibaca oleh ioutil.ReadFile.
- **Exploit page:** `exploits/warmup/exploit.py`

**Vulnerable pattern**
```text
filename := r.URL.Query().Get("file")
if filename == "" {
    filename = "welcome.txt"
}
filePath := filepath.Join("/opt/files/", filename)
content, err := ioutil.ReadFile(filePath)
```

**Patched pattern**
```text
filename := r.URL.Query().Get("file")
if filename == "" {
    filename = "welcome.txt"
}
base := "/opt/files"
cleanPath := filepath.Clean(filepath.Join(base, filename))

// Pastikan path akhir masih berada di dalam folder /opt/files/
if !strings.HasPrefix(cleanPath, base + "/") {
    http.Error(w, "Invalid file path", http.StatusBadRequest)
    return
}
content, err := ioutil.ReadFile(cleanPath)
```

**Verification**
- `../../flag.txt` must return 400/404.
- `?file=welcome.txt` must still return the normal file.
- A symlink inside the upload directory must not escape the base directory.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik18-final/services/warmup
patch -p1 --dry-run < ../../../patches/fix-path-confinement.diff
patch -p1 < ../../../patches/fix-path-confinement.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
