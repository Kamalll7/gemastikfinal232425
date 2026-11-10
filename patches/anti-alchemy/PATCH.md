# anti-alchemy — patch guide

**Challenge:** anti-alchemy (2024, Web)
**Primary source:** `gemastik-xvii-final/anti-alchemy/src/antialchemy.py & app.py`
**Audit status:** 1 finding(s) — VALID (Critical)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Type Confusion pada JSON Nested Object -> SQL Injection
- **Status:** VALID / Critical / confidence High / CWE-89
- **Root cause:** Saat attacker mengirim JSON bersarang seperti {"title": {"": "'/**/; SELECT * FROM users;-- -"}}, fungsi _sanitize() gagal mendeteksi tanda kutip di dalam value dictionary. Saat diubah oleh str(q) dan ditempel ke query SQL, tanda kutip tersebut memutus string SQL dan memicu SQL Injection di PostgreSQL untuk membocorkan tabel salt/users dan login sebagai admin.
- **Exploit page:** `exploits/anti-alchemy/exploit.py`

**Vulnerable pattern**
```text
class ClauseBuilder:
    def _sanitize(self, q):
        for c in ["'", '"']:
            if c in q:
                q = q.replace(c, c * 2)
        return str(q).strip()

# Lalu di where():
self._queries.append("'%" + value + "%'")
```

**Patched pattern**
```text
# 1. Tolak semua value JSON yang bukan bertipe string/int murni di helper/app.py
for k, v in payload.items():
    if not isinstance(v, str):
        return make_resp(400, "Bad Request")

# 2. Gunakan Parameterized Query (%s) pada psycopg2, jangan rakit string SQL manual!
cur.execute(
    "SELECT id, username, password FROM users WHERE username = %s",
    (payload["username"],)
)
```

**Verification**
- Reject non-string JSON values with 400.
- The nested-object payload must not return salt rows.
- Use parameterized queries for every value/identifier.
- The admin login with the forged hash must fail.

## Reference diffs
No applyable diff is shipped for this challenge. The before/after patterns above are the reference implementation; the change spans protocol/state design or lacks a locally runnable target.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
