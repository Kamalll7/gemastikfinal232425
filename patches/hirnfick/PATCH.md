# hirnfick — patch guide

**Challenge:** hirnfick (2023, Pwn)
**Primary source:** `gemastik-xvi-final/services/hirnfick/src/hirnfick.c`
**Audit status:** 1 finding(s) — VALID (Critical)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Out-of-Bounds Pointer (`>` / `<`) & Unbounded Code Read pada Interpreter Brainfuck
- **Status:** VALID / Critical / confidence High / CWE-787
- **Root cause:** Attacker menulis program Brainfuck yang menggeser pointer `p` mundur ke arah tabel GOT, mengubah alamat `puts@GOT` menjadi `system`, mengubah variabel `debug` menjadi 1, dan menulis perintah `/bin/sh` atau `cat /flag.txt` di awal `data`. Saat program selesai dan memanggil `if (debug) puts(data)`, yang terpanggil justru `system(data)`!
- **Exploit page:** `exploits/hirnfick/exploit.py`

**Vulnerable pattern**
```text
while ((ch = fgetc(fp)) != EOF) {
    if (ch == '>' || ch == '<' || ch == '+' || ch == '-' || ch == ',' || ch == '.' || ch == '[' || ch == ']') {
        *(pc++) = ch; // Tidak dicek apakah sudah melebihi 1024 byte!
    }
}
// Saat eksekusi:
case '>': ++p; break; // Bisa keluar dari batas atas data[1024]!
case '<': --p; break; // Bisa mundur keluar dari batas bawah data[0]!
```

**Patched pattern**
```text
size_t code_len = 0;
while ((ch = fgetc(fp)) != EOF && code_len < sizeof(code) - 1) {
    if (ch == '>' || ch == '<' || ch == '+' || ch == '-' || ch == ',' || ch == '.' || ch == '[' || ch == ']') {
        code[code_len++] = (char)ch;
    }
}
code[code_len] = '\0';

// Saat eksekusi: kunci pointer p agar tidak pernah keluar dari data[0..1023]
case '>':
    if (p < data + sizeof(data) - 1) ++p;
    break;
case '<':
    if (p > data) --p;
    break;
```

**Verification**
- Bound `p` to `data[0..1023]` and the code length to `sizeof(code)-1`.
- Compile with PIE and full RELRO so the GOT is read-only.
- The payload must not overwrite the GOT; normal Brainfuck programs must still run.

## Reference diffs
No applyable diff is shipped for this challenge. The before/after patterns above are the reference implementation; the change spans protocol/state design or lacks a locally runnable target.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
