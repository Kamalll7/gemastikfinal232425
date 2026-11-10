# gift-card — patch guide

**Challenge:** gift-card (2024, Crypto)
**Primary source:** `gemastik-xvii-final/gift-card/src/main.py`
**Audit status:** 1 finding(s) — VALID (High)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Stateless Checksum-Only Giftcard (Tanpa Secret / Tanpa MAC)
- **Status:** VALID / High / confidence High / CWE-345
- **Root cause:** Karena validasi giftcard hanya mengecek apakah jumlah 16 byte modulo 256 sama dengan jumlah byte nama user, attacker tidak perlu membeli giftcard! Attacker cukup membuat sendiri ribuan kode 16 byte yang jumlahnya cocok, lalu me-redeem semuanya sampai saldonya cukup untuk membeli flag.
- **Exploit page:** `exploits/gift-card/exploit.py`

**Vulnerable pattern**
```text
def generate_giftcard(self) -> str:
    r = random.randbytes(15)
    s = int.to_bytes(self.mod(self.Hm - self.mod(sum(r))))
    return (r + s).hex()

def validate_giftcard(self, giftcard: str) -> bool:
    signature = bytes.fromhex(giftcard)
    return len(signature) == 16 and self.mod(sum(signature)) == self.Hm
```

**Patched pattern**
```text
# Simpan daftar giftcard yang benar-benar diterbitkan oleh server di memori objek
def __init__(self, name: str) -> None:
    self.issued_cards = set()
    self.redeemed_giftcard = set()

def generate_giftcard(self) -> str:
    card = secrets.token_hex(16)
    self.issued_cards.add(card)
    return card

def validate_giftcard(self, giftcard: str) -> bool:
    return giftcard in self.issued_cards and giftcard not in self.redeemed_giftcard
```

**Verification**
- Issue cards server-side with a random ID and store them in an issued set.
- Use an HMAC over the card ID/name, not a checksum.
- A forged card must be rejected; a legitimate card must redeem exactly once.

## Reference diffs
No applyable diff is shipped for this challenge. The before/after patterns above are the reference implementation; the change spans protocol/state design or lacks a locally runnable target.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
