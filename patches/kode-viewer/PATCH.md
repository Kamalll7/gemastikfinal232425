# kode-viewer — patch guide

**Challenge:** kode-viewer (2024, Web)
**Primary source:** `gemastik-xvii-final/kode-viewer/src/kode/kode.service.ts & auth.dto.ts`
**Audit status:** 3 finding(s) — VALID (High), UNVERIFIED (Low), VALID (High)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Redis glob injection via wildcard email -> list all snippets
- **Status:** VALID / High / confidence High / CWE-1333
- **Root cause:** Registering with email `*` makes the per-user list pattern match every snippet key. The list page then exposes private admin snippet IDs, which can be read via the IDOR below.
- **Exploit page:** `exploits/kode-viewer/exploit.py --vuln enum`

**Vulnerable pattern**
```text
// auth.dto.ts
@IsNotEmpty()
email: string;
// kode.service.ts
await this.kv.find(`kode-${user.email}-*`);
```

**Patched pattern**
```text
@IsEmail()
@Matches(/^[^*?\[\]\\]+$/)
email: string;
// list by a stable user id, not by the email string
```

**Verification**
- Validate email format and reject glob metacharacters.
- Scope listing by a stable user id, not the email string.
- A wildcard email must be rejected; a normal user must see only their own snippets.


### 2. Payload email/isAdmin overwrite in create() (claimed)
- **Status:** UNVERIFIED / Low / confidence Low / N/A
- **Root cause:** The old HTML suggested this could escalate to admin. Source review shows the stored object is not used for authentication; the key and listing are based on the session email. No privilege escalation was demonstrated.
- **Exploit page:** none (no confirmed exploit for this claim)

No confirmed patch is provided. First reproduce the claim; if it is confirmed, apply the hardening below and add a regression test.

**Vulnerable pattern**
```text
return this.kv.set(key, { email, ...payload }, 1200);
```

**Patched pattern**
```text
return this.kv.set(key, { email, name: payload.name, kode: payload.kode, lang: payload.lang, kind: payload.kind }, 1200);
```

**Verification**
- Whitelist DTO fields and never spread the raw body into stored objects.
- The stored email must equal the session email; extra fields must be rejected.
- Reproduce the claim first; the current source does not prove it.


### 3. IDOR: GET /kode/:id reads any snippet key without ownership/private check
- **Status:** VALID / High / confidence High / CWE-639
- **Root cause:** A normal authenticated user can read another user's private snippet by requesting its key. Combined with the wildcard-email listing (or key guessing), this exposes the admin flag snippet.
- **Exploit page:** `exploits/kode-viewer/exploit.py --vuln idor`

**Vulnerable pattern**
```text
async show(key) {
  return this.kv.get(key);
}
```

**Patched pattern**
```text
async show(key, user) {
  const kode = await this.kv.get(key);
  if (!kode) return null;
  if (!user.isAdmin && kode.email !== user.email) return null;
  if (!user.isAdmin && kode.kind === 'private') return null;
  return kode;
}
```

**Verification**
- Pass the session user to `show()` and enforce owner/admin + private checks.
- Another user's private key must return 404; the owner's key must still load.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvii-final/kode-viewer
patch -p1 --dry-run < ../../patches/fix-ownership-and-email.diff
patch -p1 < ../../patches/fix-ownership-and-email.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
