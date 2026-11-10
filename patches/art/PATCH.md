# art — patch guide

**Challenge:** art (2023, Web)
**Primary source:** `gemastik-xvi-final/services/art/app.rb`
**Audit status:** 1 finding(s) — VALID (Critical)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Server-Side Template Injection (SSTI) pada Slim::Template
- **Status:** VALID / Critical / confidence High / CWE-1336
- **Root cause:** Karena `params[:word]` ditempel langsung menjadi kode sumber template Slim, attacker cukup mengakses URL `/art/%23{File.read('/flag.txt')}` (di mana `%23` adalah karakter `#`), maka Slim akan mengeksekusi `File.read('/flag.txt')` dan menampilkan flag di dalam HTML.
- **Exploit page:** `exploits/art/exploit.py`

**Vulnerable pattern**
```text
get '/art/:word' do
  return Slim::Template.new{
    '<iframe height="100%" width="100%" frameborder="0" src=https://asciified.thelicato.io/api/v2/ascii?text=' + params[:word] + '></iframe>'
  }.render
end
```

**Patched pattern**
```text
require 'cgi'

get '/art/:word' do
  safe_word = CGI.escape(params[:word].to_s)
  return '<iframe height="100%" width="100%" frameborder="0" src="https://asciified.thelicato.io/api/v2/ascii?text=' + safe_word + '"></iframe>'
end
```

**Verification**
- The payload must render as literal text, not execute.
- A normal word such as `gemastik` must still render the iframe.
- Use `CGI.escape`/`ERB::Util.html_escape` and never build template source from input.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvi-final/services/art
patch -p1 --dry-run < ../../../patches/fix-template-escaping.diff
patch -p1 < ../../../patches/fix-template-escaping.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
