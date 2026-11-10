# sheesh — patch guide

**Challenge:** sheesh (2025, Crypto)
**Primary source:** `gemastik18-final/services/sheesh/src/chall.py`
**Audit status:** 1 finding(s) — VALID (High)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Celah 1 & 2: AES Encryption Oracle (K1 Reuse) + CBC Padding Oracle (K0)
- **Status:** VALID / High / confidence High / CWE-649
- **Root cause:** Pertama, karena enc1 memakai kunci K1 yang sama dengan pembuat MK (enc3), attacker bisa menghitung MK sendiri dari IV yang dicetak di awal. Kedua, fungsi C membocorkan apakah padding AES-CBC valid atau tidak ('ok' vs 'no'), sehingga attacker bisa mendekripsi ciphertext flag byte demi byte menggunakan teknik CBC Padding Oracle Attack (meskipun ada noise 8% random).
- **Exploit page:** `exploits/sheesh/exploit.py`

**Vulnerable pattern**
```text
def enc1(b16):
    x = AES.new(K1, AES.MODE_ECB).encrypt(b16)
    return bytes(a ^ b for a, b in zip(x, b16))

def C(iv, ct):
    z = T(iv, ct)
    if z is None: ok = False
    else:
        try:
            x = AES.new(K0, AES.MODE_CBC, iv=iv).decrypt(z)
            unpad(x, 16)
            ok = True
        except: ok = False
    if random.random() < 0.08:
        ok = not ok
    return ok
```

**Patched pattern**
```text
# 1. Pisahkan kunci K1 untuk enc1 dengan kunci pembuat MK (misal gunakan K2 = os.urandom(16))
K2 = os.urandom(16)
def enc3(m):
    return AES.new(K2, AES.MODE_CBC, iv=b"\x00"*16).encrypt(pad(m, 16))[-16:]

# 2. Tutup Padding Oracle di fungsi C: jangan bocorkan hasil unpad(x, 16) pada ciphertext arbitrer
def C(iv, ct):
    z = T(iv, ct)
    if z is None:
        return False
    # Hanya izinkan ciphertext yang memang sah atau jangan bedakan error unpad
    return False
```

**Verification**
- The oracle must return a generic error for all invalid paddings (no `ok`/`no` distinction).
- The enc1 key must be independent from the MK key (or remove the enc1 oracle).
- The flag ciphertext must use an authenticated mode (AES-GCM/ChaCha20-Poly1305).

## Reference diffs
No applyable diff is shipped for this challenge. The before/after patterns above are the reference implementation; the change spans protocol/state design or lacks a locally runnable target.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
