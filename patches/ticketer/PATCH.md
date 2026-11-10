# ticketer — patch guide

**Challenge:** ticketer (2024, Crypto)
**Primary source:** `gemastik-xvii-final/ticketer/src/main.py & pok.py`
**Audit status:** 1 finding(s) — VALID (Critical)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Deterministic Private Key dari Username Publik + Ticket Refund Replay
- **Status:** VALID / Critical / confidence High / CWE-321
- **Root cause:** Attacker membeli 1 tiket VIP. Karena attacker tahu nilai private key `pk = H(username)`, attacker bisa membuat tanda tangan (proof) baru yang valid untuk `ticket_id` yang sama berkali-kali. Karena string `ticket` (ID + proof baru) berubah setiap kali ditandatangani ulang, pengecekan `ticket not in self.used_tickets` selalu lolos dan attacker bisa me-refund 1 tiket yang sama terus-menerus hingga saldonya cukup untuk membeli FLAG!
- **Exploit page:** `exploits/ticketer/exploit.py`

**Vulnerable pattern**
```text
# Di pok.py:
def keygen(seed):
    pk = H(seed) # Attacker bisa menghitung sendiri pk ini!
    vk = pk * curve.secp256k1.G
    return pk, vk

# Di main.py (refund):
if ticket_id in self.issued_tickets and ticket not in self.used_tickets:
    self.used_tickets.append(ticket)
```

**Patched pattern**
```text
# 1. Di pok.py: Tambahkan secret acak server saat menurunkan private key
import os
SERVER_SECRET = os.urandom(32)
def keygen(seed):
    pk = H(SERVER_SECRET + seed)
    vk = pk * curve.secp256k1.G
    return pk, vk

# 2. Di main.py (refund): Simpan dan cek ticket_id di used_tickets, BUKAN string ticket lengkapnya!
if ticket_id in self.issued_tickets and ticket_id not in self.used_tickets:
    self.used_tickets.append(ticket_id)
```

**Verification**
- Derive the key with a server-side secret: `pk = H(SERVER_SECRET + username)`.
- Track used refunds by `ticket_id`, not by the full signed string.
- Re-signing the same ID must be rejected; a normal refund must still work once.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvii-final/ticketer
patch -p1 --dry-run < ../../patches/fix-ticket-id-replay.diff
patch -p1 < ../../patches/fix-ticket-id-replay.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
