# gemas-notes — patch guide

**Challenge:** gemas-notes (2023, Web)
**Primary source:** `gemastik-xvi-final/services/gemas-notes/src/note-service/src/repository/notes/notes.go`
**Audit status:** 2 finding(s) — VALID (Critical), VALID (High)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. JSON Parser Differential Bypass + SQL Injection pada GetNotesCount
- **Status:** VALID / Critical / confidence High / CWE-89
- **Root cause:** Attacker mengirim JSON dengan dua key `keyword`: yang pertama berisi payload SQL Injection untuk membaca `rewards.fl4gg`, dan yang kedua berisi teks bersih `'hehe'`. Validation service (Python) mengecek key terakhir dan meloloskannya, lalu Note service (Go) mengambil key pertama dan mengeksekusinya di MySQL!
- **Exploit page:** `exploits/gemas-notes/exploit.py --vuln sqli`

**Vulnerable pattern**
```text
const countNote = "SELECT count(*) FROM Notes WHERE %s LIKE '%%%s%%'"

func (r *NotesRepo) GetNotesCount(key string, keyword string) (*int, error) {
    var count int
    err := r.db.Get(&count, fmt.Sprintf(countNote, key, keyword))
    return &count, err
}
```

**Patched pattern**
```text
func (r *NotesRepo) GetNotesCount(key string, keyword string) (*int, error) {
    var count int
    var query string
    switch key {
    case "title":
        query = "SELECT count(*) FROM Notes WHERE title LIKE ?"
    case "tags":
        query = "SELECT count(*) FROM Notes WHERE tags LIKE ?"
    default:
        return nil, fmt.Errorf("invalid column")
    }
    err := r.db.Get(&count, query, "%" + keyword + "%")
    return &count, err
}
```

**Verification**
- Reject duplicate JSON keys and use the same parser on both services.
- Use a parameterized query and allowlist `count_by` (`title`/`tags`).
- The duplicate-key payload must return an error or a normal count, not the injected result.


### 2. IDOR: GET /api/notes/:id has no authentication or ownership check
- **Status:** VALID / High / confidence High / CWE-639
- **Root cause:** Any unauthenticated attacker can enumerate note IDs and read every note, including private notes. This is a separate issue from the count SQL injection.
- **Exploit page:** `exploits/gemas-notes/exploit.py --vuln idor`

**Vulnerable pattern**
```text
router.GET("/api/notes/:id", Logger(noteHandler.GetDetailNotes))
// GetDetailNotes: SELECT ... WHERE Notes.id=?
```

**Patched pattern**
```text
router.GET("/api/notes/:id", Logger(AuthorizationCheck(noteHandler.GetDetailNotes)))
// and add `AND Notes.author = ?` with the session user id.
```

**Verification**
- Require authentication and filter by the session user id (or admin role).
- A request for another user's note must return 404/403; the owner's note must still load.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvi-final/services/gemas-notes
patch -p1 --dry-run < ../../../patches/fix-parameterized-count.diff
patch -p1 < ../../../patches/fix-parameterized-count.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
