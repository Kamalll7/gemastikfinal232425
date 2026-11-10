# carbeat — patch guide

**Challenge:** carbeat (2025, Pwn)
**Primary source:** `gemastik18-final/services/carbeat/chall/mybini.cpp`
**Audit status:** 1 finding(s) — VALID (Critical)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Partial free-pointer overwrite in edit_karbit() -> heap corruption -> RCE
- **Status:** VALID / Critical / confidence High / CWE-121
- **Root cause:** `Karbit::karbit` is only 20 bytes, but `edit_karbit()` calls `std::cin.getline(karbit, 0x20)` and writes up to 31 characters plus NUL. `MyKisah` stores its `free` pointer immediately after the 20-byte buffer (with 4 bytes of padding), so a 20-byte name + 4 bytes + 7 bytes of the pointer + NUL partially overwrites `free`. The custom allocator then returns an attacker-chosen pointer; the official exploit grooms the heap and redirects execution to shellcode.
- **Exploit page:** `exploits/carbeat/exploit.py`

**Vulnerable pattern**
```text
class Karbit {
protected:
    size_t karbit_level;
public:
    char karbit[20];
    void edit_karbit() {
        std::cin.getline(karbit, 0x20); // OVERFLOW: 32 byte ke buffer 20 byte!
    }
};
// Di MyKisah::add():
strncpy(used->curr, bini, 0x20); // Tidak menjamin NUL-terminated!
```

**Patched pattern**
```text
class Karbit {
protected:
    size_t karbit_level;
public:
    char karbit[32]; // Perbesar ukuran buffer atau batasi getline sesuai sizeof(karbit)
    void edit_karbit() {
        std::cin.getline(karbit, sizeof(karbit));
    }
};

// Di MyKisah::add(): pastikan selalu NUL-terminated
strncpy(used->curr, bini, 0x1f);
used->curr[0x1f] = '\0';

// Di MyKisah::view(int id) dan del(unsigned int id):
if (id < 0 || id >= 9) {
    std::cout << "Invalid index\n";
    return;
}
```

**Verification**
- `getline(karbit, sizeof(karbit))` or `std::string` must prevent writes past 20 bytes.
- `strncpy` must NUL-terminate and respect the destination size.
- Delete must clear the freed pointer; indices must be bounds-checked.
- Re-run the exploit: it must crash safely or fail, never return a shell; ASan should report no OOB write.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik18-final/services/carbeat
patch --binary -p1 --dry-run < ../../../patches/fix-getline-width.diff
patch --binary -p1 < ../../../patches/fix-getline-width.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

**CRLF source:** this diff contains CRLF lines, so the `--binary` flag is required. Without it GNU patch strips the CRs and the hunks fail with `different line endings`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
