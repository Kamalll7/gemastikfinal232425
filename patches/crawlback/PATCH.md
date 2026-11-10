# crawlback — patch guide

**Challenge:** crawlback (2023, Web)
**Primary source:** `gemastik-xvi-final/services/crawlback/src/crawlback.php`
**Audit status:** 1 finding(s) — VALID (High)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. Unrestricted SSRF / Arbitrary File Read via file:// Protocol di cURL
- **Status:** VALID / High / confidence High / CWE-918
- **Root cause:** Attacker cukup mengirimkan `url=file:///flag.txt`. Fungsi `curl_exec` akan membaca isi `/flag.txt` dari dalam server, menyimpannya ke `backups/<random>.html`, dan langsung me-redirect browser attacker ke file berisi flag tersebut!
- **Exploit page:** `exploits/crawlback/exploit.py`

**Vulnerable pattern**
```text
function get($url){
    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_RETURNTRANSFER => 1,
        CURLOPT_URL => $url,
    ));
    $resp = curl_exec($curl);
    curl_close($curl);
    return $resp;
}
```

**Patched pattern**
```text
function get($url){
    $parts = parse_url($url);
    if (!$parts || !in_array($parts['scheme'] ?? '', ['http', 'https'], true)) {
        http_response_code(400);
        die("Invalid URL scheme");
    }
    $host = $parts['host'] ?? '';
    $ip = gethostbyname($host);
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        http_response_code(400);
        die("Forbidden internal IP");
    }
    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_RETURNTRANSFER => 1,
        CURLOPT_URL => $url,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_TIMEOUT => 5,
    ));
    $resp = curl_exec($curl);
    curl_close($curl);
    return $resp;
}
```

**Verification**
- Allow only `http`/`https`, resolve the host, and block private/loopback addresses.
- `file://`, `gopher://`, and `dict://` must be rejected.
- A normal http URL must still be fetched and saved.

## Reference diffs
No applyable diff is shipped for this challenge. The before/after patterns above are the reference implementation; the change spans protocol/state design or lacks a locally runnable target.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
