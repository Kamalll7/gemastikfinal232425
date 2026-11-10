# bit-canvas — patch guide

**Challenge:** bit-canvas (2024, Pwn)
**Primary source:** `gemastik-xvii-final/bit-canvas/src/main.c`
**Audit status:** 3 finding(s) — VALID (High), VALID (High), INVALID (Info)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Unchecked canvas index -> debug toggle + stack flag leak
- **Status:** VALID / High / confidence High / CWE-125
- **Root cause:** `canvas[x] ^= 1 << y` and the print loops use `x`, `y`, and `size` without bounds checks. `canvas` is a 16-element stack array; negative `x` addresses stack slots before it, including the `debug` flag and the `flag[43]` buffer left by the admin menu.
- **Exploit page:** `exploits/bit-canvas/exploit.py --vuln leak`

**Vulnerable pattern**
```text
case 1: // draw
    scanf("%d %d", &x, &y);
    canvas[x] ^= 1 << y;
case 3: // resize
    scanf("%d", &size);
case 4: // admin
    char buffer[43];
    scanf("%s", buffer);
```

**Patched pattern**
```text
case 1: // Validasi koordinat x (0..15) dan bit y (0..31)
    if (scanf("%d %d", &x, &y) != 2 || x < 0 || x >= 16 || y < 0 || y >= 32) {
        puts("invalid coordinate");
        break;
    }
    canvas[x] ^= (1u << y);
case 3: // Batasi ukuran resize maksimal 16
    if (scanf("%d", &size) != 1 || size < 1 || size > 16) {
        size = 16;
    }
    break;
case 4: // Batasi panjang pembacaan string maksimal 42 karakter + NUL
    char buffer[43];
    scanf("%42s", buffer);
```

**Verification**
- Reject `x` outside `[0,15]`, `y` outside `[0,31]`, and `size` outside `[1,16]`.
- Remove the debug print or keep the flag out of the stack.
- The exploit must no longer produce flag bytes; normal drawing must still work.


### 2. Stack buffer overflow via scanf("%s", buffer)
- **Status:** VALID / High / confidence High / CWE-121
- **Root cause:** The admin branch reads a password with an unbounded `%s` into a 43-byte stack buffer. This is a separate memory-corruption bug from the canvas OOB leak; it can crash or redirect control flow, although the flag leak above does not need it.
- **Exploit page:** `exploits/bit-canvas/exploit.py --vuln overflow`

**Vulnerable pattern**
```text
char buffer[43];
scanf("%s", buffer);
```

**Patched pattern**
```text
char buffer[43];
if (scanf("%42s", buffer) != 1) { /* handle error */ }
```

**Verification**
- Use `scanf("%42s", buffer)` or `fgets(buffer, sizeof(buffer), stdin)`.
- Compile with stack protector/PIE/RELRO.
- A long password must be rejected or truncated without crashing.


### 3. resize=50 leaks the flag (claimed)
- **Status:** INVALID / Info / confidence High / N/A
- **Root cause:** Claim not supported: the resize print loop reads `canvas[i]`, not the separate `flag[43]` stack buffer; `size=50` prints adjacent stack words but not the flag. The real leak uses the debug print and negative indices.
- **Exploit page:** none (no confirmed exploit for this claim)

No patch is applicable: the claim is not supported by the source. Do not add a workaround for this item; keep the existing safe behavior.

**Why the claim fails:** Local test: `resize=50` prints additional canvas words but not the flag bytes. The flag leak was reproduced with the negative-index/debug technique documented above.
## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvii-final/bit-canvas
patch -p1 --dry-run < ../../patches/fix-bounds-and-scanf.diff
patch -p1 < ../../patches/fix-bounds-and-scanf.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
