# gemas-fetcher — patch guide

**Challenge:** gemas-fetcher (2023, Web)
**Primary source:** `gemastik-xvi-final/services/gemas-fetcher/src/controllers/dashboard.py`
**Audit status:** 1 finding(s) — VALID (High)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. URL Parser Bypass (Leading Whitespace CVE-2023-24329) -> Arbitrary File Read
- **Status:** VALID / High / confidence High / CWE-20
- **Root cause:** Adanya perbedaan perilaku antara `urlparse` dan `urlopen` terhadap spasi di awal string memungkinkan attacker mengirim `{"provider": "python", "url": " file:///flag.txt"}` untuk melewati filter dan membaca `/flag.txt`. Selain itu, pengecekan hostname hanya memblokir `localhost` dan `127.0.0.1` (bisa ditembus dengan `0.0.0.0` atau `127.0.0.2`).
- **Exploit page:** `exploits/gemas-fetcher/exploit.py`

**Vulnerable pattern**
```text
if urlparse(data["url"]).scheme in ["file", "ftp"]:
    return "You cannot use this scheme!!"
if urlparse(data["url"]).hostname in ["localhost", "127.0.0.1"]:
    return "Cannot fetch localhost / 127.0.0.1"
if data["provider"] == "python":
    return urllib.request.urlopen(data["url"]).read()
```

**Patched pattern**
```text
import ipaddress, socket

raw_url = (data.get("url") or "").strip()
parsed = urlparse(raw_url)

# Gunakan Allowlist: HANYA izinkan http dan https!
if parsed.scheme not in ("http", "https") or not parsed.hostname:
    return "You cannot use this scheme!!"

# Resolusi DNS dan blokir semua IP private/loopback/internal
try:
    for info in socket.getaddrinfo(parsed.hostname, None):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
            return "Cannot fetch localhost / 127.0.0.1"
except Exception:
    return "Invalid host"

# Gunakan raw_url yang sudah di-strip dan tambahkan '--' pada subprocess curl/wget
```

**Verification**
- Strip the URL and allow only `http`/`https`.
- Resolve DNS and block private/loopback addresses (including numeric variants).
- The leading-space file URL must be rejected; a normal URL fetch must work.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvi-final/services/gemas-fetcher
patch --binary -p1 --dry-run < ../../../patches/fix-url-validation.diff
patch --binary -p1 < ../../../patches/fix-url-validation.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

**CRLF source:** this diff contains CRLF lines, so the `--binary` flag is required. Without it GNU patch strips the CRs and the hunks fail with `different line endings`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
