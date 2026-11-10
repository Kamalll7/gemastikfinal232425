# go-green — patch guide

**Challenge:** go-green (2024, Logic)
**Primary source:** `gemastik-xvii-final/go-green/src/main.go`
**Audit status:** 1 finding(s) — VALID (Medium)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Missing Negative Number Validation (Donasi Negatif Menambah Uang)
- **Status:** VALID / Medium / confidence High / CWE-20
- **Root cause:** Karena tidak ada pengecekan `donate <= 0`, attacker pertama-tama memasukkan donasi `-2000`. Karena `-2000 > 420` bernilai salah, donasi diterima dan uang attacker bertambah menjadi `420 - (-2000) = 2420`. Selanjutnya attacker berdonasi `1337` dan langsung mendapatkan flag.
- **Exploit page:** `exploits/go-green/exploit.py`

**Vulnerable pattern**
```text
var donate int
fmt.Print("how much money? ")
fmt.Scanln(&donate)

if donate > money {
    fmt.Println("not enough money")
    return
}
if donate >= 1337 {
    fmt.Println(flag)
}
money -= donate
```

**Patched pattern**
```text
var donate int
fmt.Print("how much money? ")
fmt.Scanln(&donate)

// Tolak angka negatif atau nol!
if donate <= 0 || donate > money {
    fmt.Println("invalid amount or not enough money")
    return
}
if donate >= 1337 {
    fmt.Println(flag)
}
money -= donate
```

**Verification**
- Reject `donate <= 0`.
- Negative input must not change the balance; the flag must not print.
- A normal donation within the balance must still work.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvii-final/go-green
patch -p1 --dry-run < ../../patches/fix-negative-donation.diff
patch -p1 < ../../patches/fix-negative-donation.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
