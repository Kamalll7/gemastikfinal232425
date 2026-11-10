# Gemastik 2023–2025 Attack & Defense Playbook — Source Audit Report

**Audit date:** 10 November 2026  
**Scope:** 28 challenges from Gemastik XVI (2023), XVII (2024), and XVIII (2025)  
**Primary evidence:** the challenge source trees in `gemastik-xvi-final/`, `gemastik-xvii-final/`, and `gemastik18-final/services/`  
**Deliverables:** audited playbook `index.html`, per-challenge exploits in `exploits/`, patch guides and diffs in `patches/`, this report

---

## 1. Executive summary

The original playbook was treated as a set of claims to verify, not as evidence. Every claim was re-derived from source, and where possible from a local copy of the service. The audit records **44 findings across 28 challenges**:

| Status | Count | Meaning |
|---|---:|---|
| VALID | 38 | Confirmed by source and/or local execution as described |
| PARTIALLY VALID | 1 | A real primitive exists, but the claimed scope or impact is overstated |
| INVALID | 3 | Source or testing contradicts the claim |
| UNVERIFIED | 2 | Plausible, but no working proof was produced; not counted as a confirmed vulnerability |

Severity distribution: **Critical 13, High 21, Medium 4, Low 3, Info 3**.

Key outcomes:

- **39 of 44 findings** have a dedicated exploit reference. Every VALID and PARTIALLY VALID finding has a configurable script or a concrete manual artifact; the 5 INVALID/UNVERIFIED claims intentionally have none.
- **3 claims are INVALID** and were corrected in the HTML: the blogpost `/profile` SSTI, the asmr negative-index claim, and the bit-canvas `resize=50` flag leak.
- **2 claims remain UNVERIFIED**: raw-RSA voucher malleability (the Base64 replay is proven) and kode-viewer `isAdmin` privilege escalation (the display override is real but not authentication).
- **1 claim is PARTIALLY VALID**: tempest-poc `scan_id` traversal exists, but the fixed `.json` suffix limits it to readable JSON files.
- **1 new confirmed finding was added**: reflected/stored XSS in gleam-drive. Several other claims were newly separated or narrowed (tempest-poc SSRF, gemas-notes IDOR, carbeat's partial free-pointer overwrite, bit-canvas's debug flag leak).
- **11 scripts were verified end-to-end locally** (some partially, with the exact scope noted in §7). The rest are source-verified only because the Docker daemon, seed data, or an external component was unavailable.

The original challenge source was **not modified**. All dynamic tests used copies under `/tmp` or scratch directories. The pre-audit HTML is preserved at `audit_work/playbook_original.html`.

---

## 2. Methodology and evidence standard

1. **Source first.** Each finding was traced from attacker-controlled input to the dangerous sink. The HTML's `badCode`/`goodCode` snippets were checked against the actual repository.
2. **Official material as supporting evidence.** Repository writeups and official exploits were used to confirm exploitability and constants, but never as the sole proof. Where the official PoC was empty or absent, the finding was downgraded or marked UNVERIFIED.
3. **Local execution where possible.** A copy of the service was run in a scratch environment, the documented script was executed, and success was read from the response (normally a test flag or a concrete primitive confirmation). The original challenge directories were left untouched.
4. **Conservative status.** A claim is VALID only when the source supports the stated primitive and impact. A theoretical weakness with no working path is UNVERIFIED. A claim that contradicts the source is INVALID.
5. **Honest limitations.** The report distinguishes “source-verified” from “executed locally”. It does not describe a source review as a successful exploit run.

Status definitions are in §1. Severity is the audit's judgment of impact in the challenge context (typically RCE or full flag read = Critical/High; limited read or logic abuse = Medium; display-only or informational = Low/Info).

---

## 3. Validation matrix

Each finding title links to its anchor in the audited playbook. `vulnId` values are stable and are also used by the HTML index. The exploit column is the exact command artifact; the patch column links to the per-challenge guide. Detailed root cause, validity evidence, attack steps, and before/after code are in the playbook entries.

### 2025 — Gemastik XVIII

| Challenge | # | Finding | Status | Severity | Confidence | CWE | Exploit | Patch |
|---|---:|---|---|---|---|---|---|---|
| blogpost | 1 | [Celah 1: Command Injection & Path Traversal pada Upload Gambar](index.html#2025-blogpost-v0) | **VALID** | Critical | High | CWE-78 | `exploits/blogpost/exploit.py --vuln cmdi` | [PATCH](patches/blogpost/PATCH.md) |
| blogpost | 2 | [Celah 2: Stacked SQL Injection lewat Metadata Gambar](index.html#2025-blogpost-v1) | **VALID** | High | High | CWE-89 | `exploits/blogpost/exploit.py --vuln sqli` | [PATCH](patches/blogpost/PATCH.md) |
| blogpost | 3 | [Celah 3: Server-Side Template Injection (SSTI) di Halaman /profile](index.html#2025-blogpost-v2) | **INVALID** | Info | High | N/A | `—` | [PATCH](patches/blogpost/PATCH.md) |
| cdn | 1 | [Celah 1: SSTI lewat Metadata EXIF Gambar (File Name / Date Created)](index.html#2025-cdn-v0) | **VALID** | Critical | High | CWE-1336 | `exploits/cdn/exploit.py --vuln ssti` | [PATCH](patches/cdn/PATCH.md) |
| cdn | 2 | [Celah 2: Open Redirect pada Parameter next](index.html#2025-cdn-v1) | **VALID** | Medium | High | CWE-601 | `exploits/cdn/exploit.py --vuln redirect` | [PATCH](patches/cdn/PATCH.md) |
| phew | 1 | [Decryption Oracle + Affine Obfuscation pada Paillier](index.html#2025-phew-v0) | **VALID** | High | High | CWE-330 | `exploits/phew/exploit.py` | [PATCH](patches/phew/PATCH.md) |
| sheesh | 1 | [Celah 1 & 2: AES Encryption Oracle (K1 Reuse) + CBC Padding Oracle (K0)](index.html#2025-sheesh-v0) | **VALID** | High | High | CWE-649 | `exploits/sheesh/exploit.py` | [PATCH](patches/sheesh/PATCH.md) |
| carbeat | 1 | [Partial free-pointer overwrite in edit_karbit() -> heap corruption -> RCE](index.html#2025-carbeat-v0) | **VALID** | Critical | High | CWE-121 | `exploits/carbeat/exploit.py` | [PATCH](patches/carbeat/PATCH.md) |
| warmup | 1 | [Path Traversal / Arbitrary File Read (LFI)](index.html#2025-warmup-v0) | **VALID** | High | High | CWE-22 | `exploits/warmup/exploit.py` | [PATCH](patches/warmup/PATCH.md) |

### 2024 — Gemastik XVII

| Challenge | # | Finding | Status | Severity | Confidence | CWE | Exploit | Patch |
|---|---:|---|---|---|---|---|---|---|
| anti-alchemy | 1 | [Type Confusion pada JSON Nested Object -> SQL Injection](index.html#2024-anti-alchemy-v0) | **VALID** | Critical | High | CWE-89 | `exploits/anti-alchemy/exploit.py` | [PATCH](patches/anti-alchemy/PATCH.md) |
| asmr | 1 | [Unchecked allocation/copy size -> host heap OOB read/write (RCE primitive)](index.html#2024-asmr-v0) | **VALID** | High | Medium | CWE-787 | `exploits/asmr/exploit.py --vuln read` | [PATCH](patches/asmr/PATCH.md) |
| asmr | 2 | [Negative array index via signed rdi (claimed)](index.html#2024-asmr-v1) | **INVALID** | Info | High | N/A | `—` | [PATCH](patches/asmr/PATCH.md) |
| bit-canvas | 1 | [Unchecked canvas index -> debug toggle + stack flag leak](index.html#2024-bit-canvas-v0) | **VALID** | High | High | CWE-125 | `exploits/bit-canvas/exploit.py --vuln leak` | [PATCH](patches/bit-canvas/PATCH.md) |
| bit-canvas | 2 | [Stack buffer overflow via scanf("%s", buffer)](index.html#2024-bit-canvas-v1) | **VALID** | High | High | CWE-121 | `exploits/bit-canvas/exploit.py --vuln overflow` | [PATCH](patches/bit-canvas/PATCH.md) |
| bit-canvas | 3 | [resize=50 leaks the flag (claimed)](index.html#2024-bit-canvas-v2) | **INVALID** | Info | High | N/A | `—` | [PATCH](patches/bit-canvas/PATCH.md) |
| fjb | 1 | [Celah 1: Struct Buffer Overflow di Modul C kauth.c (Forging User ID)](index.html#2024-fjb-v0) | **VALID** | Critical | High | CWE-121 | `exploits/fjb/exploit.py --vuln overflow` | [PATCH](patches/fjb/PATCH.md) |
| fjb | 2 | [Celah 2: Integer Overflow pada Perhitungan Total Harga Checkout](index.html#2024-fjb-v1) | **VALID** | High | Medium | CWE-190 | `exploits/fjb/exploit.py --vuln intoverflow` | [PATCH](patches/fjb/PATCH.md) |
| gift-card | 1 | [Stateless Checksum-Only Giftcard (Tanpa Secret / Tanpa MAC)](index.html#2024-gift-card-v0) | **VALID** | High | High | CWE-345 | `exploits/gift-card/exploit.py` | [PATCH](patches/gift-card/PATCH.md) |
| gift-voucher | 1 | [Base64 Non-Canonical Replay Attack](index.html#2024-gift-voucher-v0) | **VALID** | Medium | High | CWE-345 | `exploits/gift-voucher/exploit.py` | [PATCH](patches/gift-voucher/PATCH.md) |
| gift-voucher | 2 | [Raw RSA malleability forgery (claimed)](index.html#2024-gift-voucher-v1) | **UNVERIFIED** | Low | Low | N/A | `—` | [PATCH](patches/gift-voucher/PATCH.md) |
| gleam-drive | 1 | [Celah 1: Path Traversal pada Upload & Urutan Insert DB Sebelum Simpan File](index.html#2024-gleam-drive-v0) | **VALID** | High | High | CWE-22 | `exploits/gleam-drive/exploit.py --vuln traversal` | [PATCH](patches/gleam-drive/PATCH.md) |
| gleam-drive | 2 | [AES-128-ECB session/share tokens without integrity (key readable via traversal)](index.html#2024-gleam-drive-v1) | **VALID** | High | Medium | CWE-347 | `exploits/gleam-drive/exploit.py --vuln key` | [PATCH](patches/gleam-drive/PATCH.md) |
| gleam-drive | 3 | [Reflected/stored XSS via unescaped error and filename rendering](index.html#2024-gleam-drive-v2) | **VALID** | Medium | High | CWE-79 | `exploits/gleam-drive/exploit.py --vuln xss` | [PATCH](patches/gleam-drive/PATCH.md) |
| go-green | 1 | [Missing Negative Number Validation (Donasi Negatif Menambah Uang)](index.html#2024-go-green-v0) | **VALID** | Medium | High | CWE-20 | `exploits/go-green/exploit.py` | [PATCH](patches/go-green/PATCH.md) |
| kode-viewer | 1 | [Redis glob injection via wildcard email -> list all snippets](index.html#2024-kode-viewer-v0) | **VALID** | High | High | CWE-1333 | `exploits/kode-viewer/exploit.py --vuln enum` | [PATCH](patches/kode-viewer/PATCH.md) |
| kode-viewer | 2 | [Payload email/isAdmin overwrite in create() (claimed)](index.html#2024-kode-viewer-v1) | **UNVERIFIED** | Low | Low | N/A | `—` | [PATCH](patches/kode-viewer/PATCH.md) |
| kode-viewer | 3 | [IDOR: GET /kode/:id reads any snippet key without ownership/private check](index.html#2024-kode-viewer-v2) | **VALID** | High | High | CWE-639 | `exploits/kode-viewer/exploit.py --vuln idor` | [PATCH](patches/kode-viewer/PATCH.md) |
| more-less | 1 | [Unsafe YAML Deserialization -> Remote Code Execution (RCE)](index.html#2024-more-less-v0) | **VALID** | Critical | High | CWE-502 | `exploits/more-less/exploit.py` | [PATCH](patches/more-less/PATCH.md) |
| tempest-poc | 1 | [WebSocket smuggling through /api/public -> /api/private/report](index.html#2024-tempest-poc-v0) | **VALID** | High | Medium | CWE-444 | `exploits/tempest-poc/exploit.py --vuln smuggle` | [PATCH](patches/tempest-poc/PATCH.md) |
| tempest-poc | 2 | [Tornado SSTI via report_name](index.html#2024-tempest-poc-v1) | **VALID** | Critical | High | CWE-1336 | `exploits/tempest-poc/exploit.py --vuln smuggle` | [PATCH](patches/tempest-poc/PATCH.md) |
| tempest-poc | 3 | [SSRF in /api/public/test via numeric-IP validation bypass](index.html#2024-tempest-poc-v2) | **VALID** | High | High | CWE-918 | `exploits/tempest-poc/exploit.py --vuln ssrf` | [PATCH](patches/tempest-poc/PATCH.md) |
| tempest-poc | 4 | [Path traversal in scan_id (limited to .json files)](index.html#2024-tempest-poc-v3) | **PARTIALLY VALID** | Low | Medium | CWE-22 | `exploits/tempest-poc/exploit.py --vuln traversal` | [PATCH](patches/tempest-poc/PATCH.md) |
| ticketer | 1 | [Deterministic Private Key dari Username Publik + Ticket Refund Replay](index.html#2024-ticketer-v0) | **VALID** | Critical | High | CWE-321 | `exploits/ticketer/exploit.py` | [PATCH](patches/ticketer/PATCH.md) |

### 2023 — Gemastik XVI

| Challenge | # | Finding | Status | Severity | Confidence | CWE | Exploit | Patch |
|---|---:|---|---|---|---|---|---|---|
| art | 1 | [Server-Side Template Injection (SSTI) pada Slim::Template](index.html#2023-art-v0) | **VALID** | Critical | High | CWE-1336 | `exploits/art/exploit.py` | [PATCH](patches/art/PATCH.md) |
| back-to-basic | 1 | [Classic Stack Buffer Overflow (ret2libc / ROP)](index.html#2023-back-to-basic-v0) | **VALID** | Critical | High | CWE-121 | `exploits/back-to-basic/exploit.py` | [PATCH](patches/back-to-basic/PATCH.md) |
| burvesigner | 1 | [Time-Based & Biased ECDSA Nonce k -> Private Key Recovery](index.html#2023-burvesigner-v0) | **VALID** | Critical | High | CWE-338 | `exploits/burvesigner/exploit.py` | [PATCH](patches/burvesigner/PATCH.md) |
| crawlback | 1 | [Unrestricted SSRF / Arbitrary File Read via file:// Protocol di cURL](index.html#2023-crawlback-v0) | **VALID** | High | High | CWE-918 | `exploits/crawlback/exploit.py` | [PATCH](patches/crawlback/PATCH.md) |
| gemas-fetcher | 1 | [URL Parser Bypass (Leading Whitespace CVE-2023-24329) -> Arbitrary File Read](index.html#2023-gemas-fetcher-v0) | **VALID** | High | High | CWE-20 | `exploits/gemas-fetcher/exploit.py` | [PATCH](patches/gemas-fetcher/PATCH.md) |
| gemas-notes | 1 | [JSON Parser Differential Bypass + SQL Injection pada GetNotesCount](index.html#2023-gemas-notes-v0) | **VALID** | Critical | High | CWE-89 | `exploits/gemas-notes/exploit.py --vuln sqli` | [PATCH](patches/gemas-notes/PATCH.md) |
| gemas-notes | 2 | [IDOR: GET /api/notes/:id has no authentication or ownership check](index.html#2023-gemas-notes-v1) | **VALID** | High | High | CWE-639 | `exploits/gemas-notes/exploit.py --vuln idor` | [PATCH](patches/gemas-notes/PATCH.md) |
| hirnfick | 1 | [Out-of-Bounds Pointer (`>` / `<`) & Unbounded Code Read pada Interpreter Brainfuck](index.html#2023-hirnfick-v0) | **VALID** | Critical | High | CWE-787 | `exploits/hirnfick/exploit.py` | [PATCH](patches/hirnfick/PATCH.md) |
| pasta | 1 | [Biased ECDSA Nonce pada Kurva NIST P-521 (Hidden Number Problem / Lattice Attack)](index.html#2023-pasta-v0) | **VALID** | High | High | CWE-330 | `exploits/pasta/exploit.py` | [PATCH](patches/pasta/PATCH.md) |
| s3 | 1 | [Absolute Path Behavior pada os.path.join() -> Arbitrary File Read (/flag.txt)](index.html#2023-s3-v0) | **VALID** | High | High | CWE-22 | `exploits/s3/exploit.py` | [PATCH](patches/s3/PATCH.md) |
| xl | 1 | [Arbitrary File Read (LFI) lewat Injeksi Opsi Query ?type=file pada xlsx.read()](index.html#2023-xl-v0) | **VALID** | High | High | CWE-73 | `exploits/xl/exploit.py` | [PATCH](patches/xl/PATCH.md) |

### Per-challenge summary

| Year | Challenge | Category | Findings | Status breakdown |
|---|---|---|---:|---|
| 2025 | blogpost | Web | 3 | VALID 2, INVALID 1 |
| 2025 | cdn | Web | 2 | VALID 2 |
| 2025 | phew | Crypto | 1 | VALID 1 |
| 2025 | sheesh | Crypto | 1 | VALID 1 |
| 2025 | carbeat | Pwn | 1 | VALID 1 |
| 2025 | warmup | Web | 1 | VALID 1 |
| 2024 | anti-alchemy | Web | 1 | VALID 1 |
| 2024 | asmr | Pwn | 2 | VALID 1, INVALID 1 |
| 2024 | bit-canvas | Pwn | 3 | VALID 2, INVALID 1 |
| 2024 | fjb | Web | 2 | VALID 2 |
| 2024 | gift-card | Crypto | 1 | VALID 1 |
| 2024 | gift-voucher | Crypto | 2 | VALID 1, UNVERIFIED 1 |
| 2024 | gleam-drive | Web | 3 | VALID 3 |
| 2024 | go-green | Logic | 1 | VALID 1 |
| 2024 | kode-viewer | Web | 3 | VALID 2, UNVERIFIED 1 |
| 2024 | more-less | Web | 1 | VALID 1 |
| 2024 | tempest-poc | Web | 4 | VALID 3, PARTIALLY VALID 1 |
| 2024 | ticketer | Crypto | 1 | VALID 1 |
| 2023 | art | Web | 1 | VALID 1 |
| 2023 | back-to-basic | Pwn | 1 | VALID 1 |
| 2023 | burvesigner | Crypto | 1 | VALID 1 |
| 2023 | crawlback | Web | 1 | VALID 1 |
| 2023 | gemas-fetcher | Web | 1 | VALID 1 |
| 2023 | gemas-notes | Web | 2 | VALID 2 |
| 2023 | hirnfick | Pwn | 1 | VALID 1 |
| 2023 | pasta | Crypto | 1 | VALID 1 |
| 2023 | s3 | Web | 1 | VALID 1 |
| 2023 | xl | Web | 1 | VALID 1 |

---

## 4. Corrected claims

### 4.1 blogpost `/profile` SSTI — INVALID

**Original claim:** the username is inserted into the profile template source with `.replace()` before `render_template_string()`, so a username such as `{{7*7}}` executes.

**Source evidence:** `gemastik18-final/services/blogpost/chall/templates/profile.html` contains `{{ user['username'] }}`, while `app.py` calls:

```python
profile_source = profile_template.replace("{{ user.username }}", username)
return render_template_string(profile_source, user=user, flag=flag_content)
```

The replacement target is dot notation; the template uses bracket notation. The `.replace()` is a no-op. The username is rendered as an autoescaped Jinja variable, so `{{7*7}}` is displayed literally. The two other blogpost findings (command injection and stacked SQLi) remain VALID.

### 4.2 asmr negative array index — INVALID

**Original claim:** a guest can pass a negative index through `rdi` and reach a negative Python list index.

**Source evidence:** `uc.reg_read(x86_const.UC_X86_REG_RDI)` returns an unsigned 64-bit value and the code does not convert it to a signed integer. A negative Python index is not reachable from the guest. The actionable bug is the missing per-note size tracking, which is documented as VALID under finding `2024-asmr-v0`; the local OOB read/write and host crash are real.

### 4.3 bit-canvas `resize=50` flag leak — INVALID

**Original claim:** setting `size=50` in the resize menu prints the flag.

**Source evidence and test:** the resize path prints `canvas[i]`, not the separate `flag[43]` stack buffer. A local `resize=50` run printed additional stack words but no flag bytes. The actual leak uses the admin menu to read `/flag.txt`, then negative `canvas[x]` indices and the debug print; that chain is VALID and implemented in `exploits/bit-canvas/exploit.py --vuln leak`.

### 4.4 Other corrections and narrowings

- **carbeat:** the old title bundled “non-NUL-terminated strncpy”, “out-of-bounds index”, and “UAF”. The confirmed primitive is a **partial free-pointer overwrite** in `edit_karbit()`: `getline(karbit, 0x20)` writes 0x20 bytes into `char karbit[20]`, and the trailing NUL clears the low byte of the adjacent `free` pointer. The full chain is implemented and was verified locally.
- **gift-voucher:** the old finding combined a proven Base64 replay with an unproven raw-RSA malleability claim. The replay is VALID (`2024-gift-voucher-v0`); raw-RSA malleability is UNVERIFIED (`v1`).
- **kode-viewer:** the confirmed issues are the Redis glob injection and the IDOR. The claimed `isAdmin` overwrite is UNVERIFIED; the `--vuln spoof` probe only demonstrates an author/email display override and is excluded from `--vuln all`.
- **tempest-poc:** the `scan_id` traversal is PARTIALLY VALID. The `.json` suffix is always appended and `json.load()` must succeed, so it is a limited JSON-file read, not a direct `/flag.txt` read.
- **gleam-drive:** reflected/stored XSS was added as a separate VALID finding after source review of `render_error_html`/`render_detail_html`.

---

## 5. Partial and unverified findings

### PARTIALLY VALID — tempest-poc `scan_id` traversal (`2024-tempest-poc-v3`)

`report_file = f"report/{scan_id}.json"` can escape `report/`, but the attacker cannot remove the `.json` suffix and the response requires `json.load()` to succeed. This is a real limited file-read primitive. The old claim that it reads the flag is not supported unless the flag happens to be in a readable `.json` path. The playbook and `patches/tempest-poc/PATCH.md` document the narrowed scope; the exploit's `traversal` mode only probes candidate `.json` files.

### UNVERIFIED — gift-voucher raw-RSA malleability (`2024-gift-voucher-v1`)

The code uses textbook RSA, so it is theoretically malleable. However, the verifier requires the decrypted message to start with `00 02` and end with `00 || SHA256(name)`. No practical forgery preserving both was demonstrated, and no published exploit was found. The exploit artifact implements the proven Base64 replay, not this claim. Do not treat raw-RSA malleability as confirmed.

### UNVERIFIED — kode-viewer `isAdmin` overwrite (`2024-kode-viewer-v1`)

The create path spreads a client-controlled `email` into the stored object, which is a real display/author override. Source review shows the object is not used by `AuthGuard` or the session, and the Redis key is built from the session email. No privilege escalation was demonstrated; the admin/flag seed is also absent from the workspace. The confirmed wildcard listing and IDOR are separately VALID.

---

## 6. New or newly separated confirmed findings

These were added or made explicit during the audit rather than inherited unchanged from the pre-audit HTML:

- **gleam-drive XSS** (`2024-gleam-drive-v2`, new): `/error?message=...` reflects HTML unescaped, and uploaded filenames are inserted into the details page without escaping.
- **tempest-poc SSRF** (`2024-tempest-poc-v2`, newly separated): `/api/public/test` validates the host with a numeric-IP check that accepts decimal/octal forms such as `2130706433`, allowing requests to localhost. This was bundled into the old WebSocket-smuggling narrative; it is now a distinct finding and exploit mode.
- **gemas-notes IDOR** (`2023-gemas-notes-v1`, newly separated): `GET /api/notes/:id` has no authentication or ownership check. The old entry combined it with the JSON-parser SQLi.
- **bit-canvas debug leak** (`2024-bit-canvas-v0`, newly characterized): the confirmed primitive is an unchecked `canvas[x]` index that toggles the `debug` flag and reads the stack `flag[43]` buffer through the debug print. The old resize claim is INVALID.
- **carbeat free-pointer overwrite** (`2025-carbeat-v0`, corrected): the confirmed primitive is a partial overwrite of the adjacent `free` pointer, not a generic “buffer overflow/UAF” bundle.

---

## 7. Local verification results

The following were executed against copies of the challenge services. “Flag” means a test flag placed in the local lab, never a real event flag.

| Challenge | Command (local) | Result |
|---|---|---|
| sheesh | `python3 exploits/sheesh/exploit.py --host 127.0.0.1 --port 13000 --verbose` | Full flag recovered; 32,183 oracle queries, ~5 minutes, 8% noise handled |
| ticketer | `python3 exploits/ticketer/exploit.py --host 127.0.0.1 --port 14000 --refunds 20` | Full flag recovered through key recovery + refund replay |
| gift-card | `python3 exploits/gift-card/exploit.py --host 127.0.0.1 --port 21000` | Full flag recovered with forged checksum-only cards |
| gift-voucher | `python3 exploits/gift-voucher/exploit.py --host 127.0.0.1 --port 16000` | Full flag recovered via non-canonical Base64 replay; raw-RSA malleability not tested |
| go-green | `python3 exploits/go-green/exploit.py --host 127.0.0.1 --port 20000` | Full flag recovered with a negative donation |
| carbeat | `python3 exploits/carbeat/exploit.py --host 127.0.0.1 --port 14000 --command 'cat /flag.txt'` | Full chain against the supplied `mybini` binary; test flag returned |
| back-to-basic | `python3 exploits/back-to-basic/exploit.py --process ./back-to-basic --elf ./back-to-basic --libc /lib/x86_64-linux-gnu/libc.so.6` | Full ret2libc chain on a GCC 13 rebuild + glibc 2.39; 10/10 runs returned the test flag via a test `cat` shim. The local build needed an added `pop rdi; ret` gadget. |
| phew | `python3 exploits/phew/exploit.py --host 127.0.0.1 --port 15000 --verbose` | Full flag recovered; affine oracle + Paillier factorization + CRT key recovery |
| pasta | `PYTHONPATH=/tmp/opencode/fpylll audit_work/venv/bin/python exploits/pasta/exploit.py --host 127.0.0.1 --port 13002 --samples 110` | P-521 key recovered at lattice row 1 (~15 s LLL); admin token accepted, flag returned |
| bit-canvas (leak) | `python3 exploits/bit-canvas/exploit.py --host 127.0.0.1 --port 11000 --vuln leak` | Flag leak verified on the GCC 11 default layout and a stack-protector layout (`debug` at -8 and -11; `--debug-index` auto-detect) |
| bit-canvas (overflow) | `python3 exploits/bit-canvas/exploit.py --host 127.0.0.1 --port 11000 --vuln overflow --overflow-length 512` | Direct local run (512-byte password) exited 134 with `*** stack smashing detected ***: terminated`; remote success requires stderr/crash marker, otherwise the script reports it as unconfirmed |
| asmr (read) | `python3 exploits/asmr/exploit.py --host 127.0.0.1 --port 17000 --vuln read` | Host heap OOB read/write confirmed; 256 bytes returned past a 0x10-byte allocation |
| asmr (write) | `python3 exploits/asmr/exploit.py --host 127.0.0.1 --port 17000 --vuln write` | Host allocator corruption / crash confirmed; full RCE not reproduced |

**Source-verified but not executed end-to-end:** art, burvesigner, crawlback, gemas-fetcher, gemas-notes, hirnfick, s3, xl, anti-alchemy, fjb, gleam-drive, kode-viewer, more-less, tempest-poc, blogpost, cdn, warmup. Reasons are listed in §8.

**Patch verification:** all **19 applyable diffs** were generated against the unmodified source and passed `patch -p1 --dry-run` on a throwaway copy. The carbeat and gemas-fetcher diffs contain CRLF lines and require `patch --binary`; the generator and their `PATCH.md` commands include that flag. The other 9 challenges have guidance-only patches because the fix spans protocol/state design or there is no locally runnable target.

---

## 8. Blockers, caveats, and unverified areas

- **Docker daemon unavailable.** The Docker CLI exists, but `/var/run/docker.sock` is missing. Most multi-service labs could not be started. This is the main reason many HTTP findings are source-verified only.
- **fjb:** the workspace `fjb.db` is empty; the seeded admin/flag catalog item and the full checkout chain were not reproduced. Both bugs are source-confirmed.
- **kode-viewer:** no local admin/flag seed exists. The wildcard and IDOR primitives are source-confirmed; full flag retrieval was not reproduced.
- **tempest-poc:** the full chain needs nginx, a `tempest-poc:5000` backend host, and an attacker-controlled callback that returns HTTP 101. The script implements the logic, but the complete environment was not built.
- **gift-voucher:** RSA malleability remains UNVERIFIED (see §5).
- **asmr:** the host heap OOB primitive is proven, but a full RCE chain was not reproduced. The official PoC gist was empty.
- **back-to-basic:** the repository ships source only. The chain was verified on a local GCC 13 rebuild with host glibc 2.39 and a test `cat` shim, not against the original Ubuntu 20.04 GCC 9 binary. The local build lacked a `pop rdi; ret` gadget, so one was linked into the test binary; the built-in offsets remain official-reference values.
- **pasta:** `fpylll`/`cysignals` are not in the system Python. The verified run used `PYTHONPATH=/tmp/opencode/fpylll` with the audit venv.
- **Severity and confidence are audit judgments.** They reflect the challenge context, not a formal CVSS score.
- **Local test flags are not event flags.** No public or third-party target was contacted, and no destructive action was performed outside disposable local labs.
- **Patches are reference fixes.** They were dry-run tested but not regression-tested against every challenge flow; each `PATCH.md` includes a regression checklist.

---

## 9. Artifact inventory

| Artifact | Count | Location |
|---|---:|---|
| Audited playbook | 1 | `index.html` |
| Challenges | 28 | 2023: 10, 2024: 12, 2025: 6 |
| Findings | 44 | 38 VALID, 1 PARTIALLY VALID, 3 INVALID, 2 UNVERIFIED |
| Exploit references | 39 | linked from the playbook and `exploits/README.md` |
| Challenge exploit directories | 28 | `exploits/<challenge>/` |
| Exploit scripts | 28 | `exploits/<challenge>/exploit.py` |
| Exploit READMEs | 29 | 28 per-challenge + `exploits/README.md` |
| Patch guides | 28 | `patches/<challenge>/PATCH.md` |
| Applyable diffs | 19 | `patches/<challenge>/*.diff` |
| Patch index | 1 | `patches/README.md` |
| Pre-audit HTML backup | 1 | `audit_work/playbook_original.html` |

The HTML keeps the original visual identity and Indonesian narrative where it was accurate. It now includes an audit snapshot, the validation matrix, an artifact index, per-finding exploit/patch references, and the corrected data. The client-side storage key was bumped to `gemastik_ad_playbook_audited_v2`.

---

## 10. Reproduction and responsible use

Open the playbook directly in a browser:

```bash
xdg-open index.html
```

Run a script only against a local or explicitly authorized lab:

```bash
python3 exploits/sheesh/exploit.py --host 127.0.0.1 --port 13000
python3 exploits/tempest-poc/exploit.py --host 127.0.0.1 --port 80 --vuln smuggle
```

Every network script defaults to `127.0.0.1`, accepts `--host`/`--port`, and exits non-zero when its success condition is not observed. Some scripts need extra dependencies: `pasta` needs `fpylll` + `cysignals`; the pwn scripts (`asmr`, `back-to-basic`, `carbeat`, `hirnfick`) need `pwntools`.

Apply a patch only to a copy or lab deployment:

```bash
cd gemastik18-final/services/blogpost
patch -p1 --dry-run < ../../../patches/blogpost/fix-upload-and-metadata.diff
patch -p1 < ../../../patches/blogpost/fix-upload-and-metadata.diff
```

For carbeat, add `--binary`:

```bash
cd gemastik18-final/services/carbeat
patch --binary -p1 --dry-run < ../../../patches/carbeat/fix-getline-width.diff
```

**Do not run these challenges or exploits against public systems.** They contain intentional RCE, file-read, and authentication-bypass primitives. The audit was scoped to local copies and challenge labs.

---

## 11. Final assessment

The audited playbook is now a source-backed reference rather than an unverified summary. The three false claims are explicitly marked INVALID and explained, the two unproven claims are marked UNVERIFIED, the one overstated traversal is scoped to its real impact, and every confirmed finding has a configurable artifact and a patch reference. The main remaining gap is dynamic coverage: 11 scripts were run end-to-end (some partially), while the rest are source-verified. That distinction is stated in the playbook, every challenge README, and this report.

*End of report.*
