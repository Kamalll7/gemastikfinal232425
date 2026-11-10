# burvesigner — patch guide

**Challenge:** burvesigner (2023, Crypto)
**Primary source:** `gemastik-xvi-final/services/burvesigner/src/burvesigner.py`
**Audit status:** 1 finding(s) — VALID (Critical)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Time-Based & Biased ECDSA Nonce k -> Private Key Recovery
- **Status:** VALID / Critical / confidence High / CWE-338
- **Root cause:** Dalam ECDSA, jika selisih antara dua nonce `k1 - k2` diketahui atau bisa ditebak, maka kunci privat `self.x` bisa dihitung langsung dengan persamaan linear sederhana! Karena `self.v` tetap sama, maka `k2 - k1 = (t2 - t1) << u`. Attacker cukup meminta 2 token dalam waktu berdekatan, menebak selisih waktu `t2 - t1`, menghitung kunci privat `self.x`, lalu menandatangani token baru dengan `role: admin`.
- **Exploit page:** `exploits/burvesigner/exploit.py`

**Vulnerable pattern**
```text
def sign(self, msg):
    self.set_keys()
    k = (int(time() * 1337) << self.u) + self.v
    R = k * self.C.G
    s = (self.hash(msg) - self.x * R.x) * pow(k, -1, self.C.q) % self.C.q
```

**Patched pattern**
```text
import secrets

def sign(self, msg):
    self.set_keys()
    # Gunakan CSPRNG penuh dari 1 sampai q-1 untuk setiap penandatanganan!
    k = secrets.randbelow(self.C.q - 1) + 1
    R = k * self.C.G
    s = (self.hash(msg) - self.x * R.x) * pow(k, -1, self.C.q) % self.C.q
```

**Verification**
- Use a CSPRNG nonce (`secrets.randbelow(q-1)+1`) or RFC 6979.
- Two signatures must not have a recoverable linear nonce relation.
- The forged admin token must be rejected.

## Reference diffs
No applyable diff is shipped for this challenge. The before/after patterns above are the reference implementation; the change spans protocol/state design or lacks a locally runnable target.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
