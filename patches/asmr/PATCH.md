# asmr — patch guide

**Challenge:** asmr (2024, Pwn)
**Primary source:** `gemastik-xvii-final/asmr/src/asmr.py`
**Audit status:** 2 finding(s) — VALID (High), INVALID (Info)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Unchecked allocation/copy size -> host heap OOB read/write (RCE primitive)
- **Status:** VALID / High / confidence Medium / CWE-787
- **Root cause:** `create(size)` stores only the `malloc` pointer; `edit(idx, buf, size)` copies `size` bytes into that allocation and `view(idx, buf, size)` reads `size` bytes back. There is no per-note size tracking and no check that `size <= allocated_size`. The guest controls `rdi/rsi/rdx`, so a small `create(16)` followed by `edit(..., 0x1000)` corrupts the host Python/libc heap.
- **Exploit page:** `exploits/asmr/exploit.py --vuln read`

**Vulnerable pattern**
```text
notes = [0 for _ in range(MAX_NOTES)]

def create(size):
    idx = find_empty()
    notes[idx] = libc.malloc(size)

def edit(idx, buf, size):
    if notes[idx] == 0: return
    ubuf = uc.mem_read(buf, size)
    ctypes.memmove(notes[idx], ctypes.create_string_buffer(bytes(ubuf)), size)
```

**Patched pattern**
```text
notes = [0 for _ in range(MAX_NOTES)]
sizes = [0 for _ in range(MAX_NOTES)]

def valid_idx(idx):
    return isinstance(idx, int) and 0 <= idx < MAX_NOTES

def create(size):
    if size <= 0 or size > 0x1000:
        uc.reg_write(RAX, -1); return
    idx = find_empty()
    if idx == -1:
        uc.reg_write(RAX, -1); return
    notes[idx] = libc.malloc(size)
    sizes[idx] = size
    uc.reg_write(RAX, idx)

def edit(idx, buf, size):
    if not valid_idx(idx) or notes[idx] == 0 or size < 0 or size > sizes[idx]:
        uc.reg_write(RAX, -1); return
    ubuf = uc.mem_read(buf, size)
    ctypes.memmove(notes[idx], ctypes.create_string_buffer(bytes(ubuf)), size)

def view(idx, buf, size):
    if not valid_idx(idx) or notes[idx] == 0 or size < 0 or size > sizes[idx]:
        uc.reg_write(RAX, -1); return
    kbuf = ctypes.string_at(notes[idx], size)
    uc.mem_write(buf, kbuf)
```

**Verification**
- Track `sizes[idx]` and reject `size > sizes[idx]`.
- Validate `idx` in `[0, MAX_NOTES)`.
- Use `memmove(..., min(size, sizes[idx]))` and never pass guest-controlled sizes to `string_at`/`puts`.
- ASan must report no OOB access; the official PoC must fail.


### 2. Negative array index via signed rdi (claimed)
- **Status:** INVALID / Info / confidence High / N/A
- **Root cause:** Claim not supported: `uc.reg_read()` returns an unsigned 64-bit value, so the guest cannot express a negative Python list index; the real bug is the missing size check.
- **Exploit page:** none (no confirmed exploit for this claim)

No patch is applicable: the claim is not supported by the source. Do not add a workaround for this item; keep the existing safe behavior.

**Why the claim fails:** `uc.reg_read()` returns an unsigned value; `notes[idx]` with a negative Python index is not reachable from the guest. The claim is not supported by the source or by local tests.
## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvii-final/asmr
patch -p1 --dry-run < ../../patches/fix-size-tracking.diff
patch -p1 < ../../patches/fix-size-tracking.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
