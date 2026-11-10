# gift-voucher — patch guide

**Challenge:** gift-voucher (2024, Crypto)
**Primary source:** `gemastik-xvii-final/gift-voucher/src/main.py`
**Audit status:** 2 finding(s) — VALID (Medium), UNVERIFIED (Low)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Base64 Non-Canonical Replay Attack
- **Status:** VALID / Medium / confidence High / CWE-345
- **Root cause:** Attacker cukup membeli 1 voucher asli (misal 'ABCD...'), lalu me-redeem-nya berkali-kali dengan menambahkan spasi atau karakter non-base64 (' ABCD...', '  ABCD...', dst). Karena string-nya terlihat berbeda, pengecekan `voucher in self.redeemed_voucher` selalu lolos, padahal hasil decode RSA-nya tetap voucher yang sama!
- **Exploit page:** `exploits/gift-voucher/exploit.py`

**Vulnerable pattern**
```text
# Mengecek string mentah dari user, bukan hasil decode kanoniknya
if voucher not in self.redeemed_voucher and self.validate_voucher(voucher):
    self.redeemed_voucher.add(voucher)
    self.balance += random.randint(30, 60)
```

**Patched pattern**
```text
# 1. Simpan voucher yang resmi diterbitkan oleh generate_voucher()
# 2. Normalisasi (canonicalize) Base64 menjadi bytes sebelum dicek di redeemed_voucher
raw_bytes = base64.b64decode(voucher.encode(), validate=True)
if (raw_bytes in self.issued_vouchers 
    and raw_bytes not in self.redeemed_voucher 
    and self.validate_voucher(voucher)):
    self.redeemed_voucher.add(raw_bytes)
    self.balance += random.randint(30, 60)
```

**Verification**
- Decode with `base64.b64decode(..., validate=True)` and store the canonical bytes/hash.
- Reject any non-canonical encoding.
- The same voucher must be redeemable only once; a mutated encoding must be rejected.


### 2. Raw RSA malleability forgery (claimed)
- **Status:** UNVERIFIED / Low / confidence Low / N/A
- **Root cause:** The code uses raw RSA without a proper signature padding scheme, so it is theoretically malleable. No practical forgery that preserves the fixed prefix/suffix was demonstrated; the exploitable issue is the Base64 replay above.
- **Exploit page:** none (no confirmed exploit for this claim)

No confirmed patch is provided. First reproduce the claim; if it is confirmed, apply the hardening below and add a regression test.

**Vulnerable pattern**
```text
message = int.to_bytes(pow(voucher, self.key.e, self.key.n), 128, "big")
return message.startswith(b"\x00\x02") and message.endswith(b"\x00" + self.Hm)
```

**Patched pattern**
```text
Use RSA-PSS or RSA-OAEP with a random salt; never accept raw RSA signatures.
```

**Verification**
- Replace raw RSA with RSA-PSS/OAEP and verify the signature over a canonical message.
- The replay exploit must fail; a legitimate voucher must still redeem.
- Reproduce the claim first; the current source does not prove it.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvii-final/gift-voucher
patch -p1 --dry-run < ../../patches/fix-canonical-base64.diff
patch -p1 < ../../patches/fix-canonical-base64.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
