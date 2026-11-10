# pasta — patch guide

**Challenge:** pasta (2023, Crypto)
**Primary source:** `gemastik-xvi-final/services/pasta/src/pasta.py`
**Audit status:** 1 finding(s) — VALID (High)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Biased ECDSA Nonce pada Kurva NIST P-521 (Hidden Number Problem / Lattice Attack)
- **Status:** VALID / High / confidence High / CWE-330
- **Root cause:** Dalam kriptografi ECDSA, jika beberapa bit teratas dari nonce `k` selalu bernilai 0 (nonce bias), attacker cukup mengumpulkan sekitar 60–100 token dengan pesan berbeda lalu menjalankan algoritma reduksi basis kisi (LLL / Hidden Number Problem) untuk menghitung kunci privat server! Setelah kunci privat didapat, attacker membuat token admin palsu.
- **Exploit page:** `exploits/pasta/exploit.py`

**Vulnerable pattern**
```text
def sign(self, data: str):
    data = data.encode()
    pub = self.priv.get_verifying_key().to_string()
    h = self.hashfunc(data + pub).digest()
    nonce = hmac.new(self.priv.to_string(), data, self.hashfunc).hexdigest()
    sig = self.priv.sign_digest(h, k=int(nonce, 16))
    return self.serialize(data + pub, sig)
```

**Patched pattern**
```text
import secrets

def sign(self, data: str):
    data = data.encode()
    pub = self.priv.get_verifying_key().to_string()
    h = self.hashfunc(data + pub).digest()
    # Gunakan RFC 6979 bawaan library ecdsa atau CSPRNG dengan rentang penuh order kurva!
    order = self.priv.curve.order
    k = secrets.randbelow(order - 1) + 1
    sig = self.priv.sign_digest(h, k=k)
    return self.serialize(data + pub, sig)
```

**Verification**
- Use a full-range CSPRNG nonce or RFC 6979 (521-bit range).
- The nonce distribution must have no fixed top bits.
- The forged admin token must be rejected; normal v1-v4 tokens must still verify.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvi-final/services/pasta
patch -p1 --dry-run < ../../../patches/fix-full-range-nonce.diff
patch -p1 < ../../../patches/fix-full-range-nonce.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
