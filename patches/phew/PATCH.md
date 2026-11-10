# phew — patch guide

**Challenge:** phew (2025, Crypto)
**Primary source:** `gemastik18-final/services/phew/src/Pailier.py & chall.py`
**Audit status:** 1 finding(s) — VALID (High)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Decryption Oracle + Affine Obfuscation pada Paillier
- **Status:** VALID / High / confidence High / CWE-330
- **Root cause:** Attacker punya akses ke Encryption Oracle (Menu 1), Decryption Oracle (Menu 3), sekaligus Ciphertext dari Secret Key (Menu 4). Dengan mengenkripsi angka x = 0, 1, 2 lalu mendekripsinya di Menu 3, attacker dapat menemukan nilai alpha dan beta. Setelah itu, attacker mengambil ciphertext secret_key dari Menu 4, mendekripsinya di Menu 3, dan membalik rumus (y - beta) * alpha^-1 mod n untuk mendapatkan secret_key lalu menukarkannya dengan flag di Menu 2.
- **Exploit page:** `exploits/phew/exploit.py`

**Vulnerable pattern**
```text
# Di chall.py: mengizinkan decrypt sembarang ciphertext (termasuk ciphertext key dari menu 4)
elif choice == "3":
    ct = int(input("ciphertext (hex): "), 16)
    print(hex(cipher.decrypt(ct))[2:])
elif choice == "4":
    print(hex(cipher.encrypt(int.from_bytes(key, 'big')))[2:])
```

**Patched pattern**
```text
# 1. Simpan daftar ciphertext yang berasal dari menu 4 (encrypted secret key) dan tolak di menu 3
forbid_cts = set()

elif choice == "3":
    ct = int(input("ciphertext (hex): "), 16)
    if ct <= 0 or ct >= cipher.n2 or ct in forbid_cts:
        print("invalid ciphertext")
        continue
    # Atau matikan transformasi linear yang membocorkan relasi langsung ke key
elif choice == "4":
    enc_k = cipher.encrypt(int.from_bytes(key, 'big'))
    forbid_cts.add(enc_k)
    print(hex(enc_k)[2:])
# Catatan: Lebih baik lagi jika alpha/beta diacak per sesi atau menu 3 dibatasi agar tidak bisa mendekripsi komponen homomorfik dari enc_k.
```

**Verification**
- Menu 3 must reject ciphertexts produced by menu 4 (or the affine transform must be removed).
- The same chosen-plaintext queries must not reveal n or a factor.
- The key-guess check must still accept the real key and reject wrong keys.

## Reference diffs
No applyable diff is shipped for this challenge. The before/after patterns above are the reference implementation; the change spans protocol/state design or lacks a locally runnable target.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
