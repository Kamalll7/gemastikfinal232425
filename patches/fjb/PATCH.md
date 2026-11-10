# fjb — patch guide

**Challenge:** fjb (2024, Web)
**Primary source:** `gemastik-xvii-final/fjb/kauth/kauth.c & src/handler/cart.lua`
**Audit status:** 2 finding(s) — VALID (Critical), VALID (High)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Celah 1: Struct Buffer Overflow di Modul C kauth.c (Forging User ID)
- **Status:** VALID / Critical / confidence High / CWE-121
- **Root cause:** Attacker mendaftar dengan username sepanjang 128 huruf diikuti byte '\x01\x00...'. Saat fungsi kauth.encode() menyalin username dengan strcpy, byte ke-129 menimpa claim.id menjadi 1 (ID milik admin). Token yang dihasilkan tetap ditandatangani secara sah oleh server sehingga attacker mendapatkan akses sebagai user ID 1 (admin).
- **Exploit page:** `exploits/fjb/exploit.py --vuln overflow`

**Vulnerable pattern**
```text
struct kauth_user {
  const char name[128];
  unsigned long long id;
  unsigned long long exp;
};
// Di dalam fungsi encode():
const char *name = lua_tostring(L, -1);
strcpy((char *)claim.name, name);
```

**Patched pattern**
```text
const char *name = lua_tostring(L, -1);
if (!name || strlen(name) >= sizeof(claim.name)) {
    lua_pushstring(L, "username too long");
    return lua_error(L);
}
strncpy((char *)claim.name, name, sizeof(claim.name) - 1);
((char *)claim.name)[sizeof(claim.name) - 1] = '\0';
```

**Verification**
- Reject usernames with `strlen(name) >= sizeof(claim.name)`.
- Use `strncpy` + explicit NUL, or a length-prefixed struct.
- The forged token must decode with the real user id, not 1.
- Normal registration/login and catalog access must still work.


### 2. Celah 2: Integer Overflow pada Perhitungan Total Harga Checkout
- **Status:** VALID / High / confidence Medium / CWE-190
- **Root cause:** Attacker memasukkan item mahal berisi flag ke keranjang, lalu membuat item palsu sendiri dengan harga mendekati maksimum 64-bit (0x7fffffffffffffff) dan memasukkannya ke keranjang yang sama. Saat dijumlahkan di checkout, variabel 'cost' mengalami overflow menjadi negatif, sehingga pengecekan 'wallet < cost' bernilai False (lolos!) dan flag berhasil dibeli.
- **Exploit page:** `exploits/fjb/exploit.py --vuln intoverflow`

**Vulnerable pattern**
```text
local cost = 0x0
for i = 1, #items do
    cost = cost + items[i].price
end
if wallet < cost then
    return error_insufficient_funds()
end
```

**Patched pattern**
```text
-- 1. Saat membuat item & saat menjumlahkan di checkout, batasi harga wajar:
local cost = 0
for i = 1, #items do
    local p = tonumber(items[i].price) or 0
    if p < 0 or p > 1000000000 then
        return error_invalid_price()
    end
    cost = cost + p
    if cost < 0 or cost > 1000000000 then
        return error_invalid_price()
    end
end
```

**Verification**
- Reject negative/absurd prices and use checked addition.
- Reject checkout if any item price is outside a sane range.
- The wrapped total must be detected and rejected; normal checkout must still work.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvii-final/fjb
patch -p1 --dry-run < ../../patches/fix-bounded-name-copy.diff
patch -p1 < ../../patches/fix-bounded-name-copy.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
