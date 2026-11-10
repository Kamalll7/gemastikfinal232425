# back-to-basic — patch guide

**Challenge:** back-to-basic (2023, Pwn)
**Primary source:** `gemastik-xvi-final/services/back-to-basic/src/main.c`
**Audit status:** 1 finding(s) — VALID (Critical)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Classic Stack Buffer Overflow (ret2libc / ROP)
- **Status:** VALID / Critical / confidence High / CWE-121
- **Root cause:** Binary di-compile dengan `-no-pie` dan `-fno-stack-protector` (tanpa canary). Attacker cukup mengirim 72 byte sampah diikuti rangkaian alamat ROP (Return-Oriented Programming) untuk membocorkan alamat libc lewat `puts` lalu memanggil `system('/bin/sh')`.
- **Exploit page:** `exploits/back-to-basic/exploit.py`

**Vulnerable pattern**
```text
void give_me_idea() {
  char buf[64];
  puts("Do you have a good idea?");
  fgets(buf, 200, stdin);
}
```

**Patched pattern**
```text
void give_me_idea() {
  char buf[64];
  puts("Do you have a good idea?");
  fgets(buf, sizeof(buf), stdin);
}
```

**Verification**
- `fgets(buf, sizeof(buf), stdin)` must prevent the overflow.
- Compile with `-fstack-protector-strong`, PIE, and full RELRO.
- The exploit must fail; normal input must still work.

## Reference diffs
No applyable diff is shipped for this challenge. The before/after patterns above are the reference implementation; the change spans protocol/state design or lacks a locally runnable target.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
