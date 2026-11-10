# tempest-poc — patch guide

**Challenge:** tempest-poc (2024, Web)
**Primary source:** `gemastik-xvii-final/tempest-poc/backend/src/app.py & frontend/nginx.conf`
**Audit status:** 4 finding(s) — VALID (High), VALID (Critical), VALID (High), PARTIALLY VALID (Low)

This guide is defensive material for the audited challenge. The original challenge source was not modified; apply the reference diffs only to a copy or a lab deployment.

## Findings and fixes

### 1. WebSocket smuggling through /api/public -> /api/private/report
- **Status:** VALID / High / confidence Medium / CWE-444
- **Root cause:** The private report endpoint relies on nginx to block external access. WebSocket smuggling turns the public test endpoint into a raw tunnel to the backend, so `/api/private/report` becomes reachable. The attacker must control a host that returns HTTP 101.
- **Exploit page:** `exploits/tempest-poc/exploit.py --vuln smuggle`

**Vulnerable pattern**
```text
location ~ ^/api/public {
    proxy_pass http://tempest-poc:5000;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
}
```

**Patched pattern**
```text
location = /api/public/ws/ {
    proxy_pass http://tempest-poc:5000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "Upgrade";
}
location /api/public/ {
    proxy_pass http://tempest-poc:5000;
    proxy_set_header Upgrade "";
    proxy_set_header Connection "";
}
```

**Verification**
- Only the exact `/api/public/ws/` location may receive Upgrade/Connection headers.
- The smuggling sequence must not reach `/api/private/report`; normal WebSocket and public API traffic must still work.
- Require authentication on `/api/private/report` as defense in depth.


### 2. Tornado SSTI via report_name
- **Status:** VALID / Critical / confidence High / CWE-1336
- **Root cause:** `report_name` is concatenated into template source, so a query value containing `{{ ... }}` is compiled and executed. Direct external access is blocked by nginx, but the WebSocket-smuggling primitive above reaches the endpoint.
- **Exploit page:** `exploits/tempest-poc/exploit.py --vuln smuggle`

**Vulnerable pattern**
```text
report_template = report_template.replace("<REPORT_NAME>", report_name)
self.write(tornado.template.Template(report_template).generate(scan_id=scan_id, scan_data=scan_data))
```

**Patched pattern**
```text
report_template = report_template.replace("<REPORT_NAME>", "{{ report_name }}")
self.write(tornado.template.Template(report_template).generate(scan_id=scan_id, scan_data=scan_data, report_name=report_name))
```

**Verification**
- Pass `report_name` as a template variable and autoescape it; never concatenate into template source.
- The SSTI payload must render literally; normal report names must work.


### 3. SSRF in /api/public/test via numeric-IP validation bypass
- **Status:** VALID / High / confidence High / CWE-918
- **Root cause:** An attacker can make the backend request loopback/internal services by using decimal or short-form IPs. The response status is returned to the attacker, enabling internal port scanning; the path is stripped, so this primitive alone does not reach `/api/private/report`.
- **Exploit page:** `exploits/tempest-poc/exploit.py --vuln ssrf`

**Vulnerable pattern**
```text
if not netloc.replace(".", "").isdigit():
    ip = socket.gethostbyname(netloc)
    ...
else:
    if is_local_ip(netloc, local_ips): return False
```

**Patched pattern**
```text
ip = ipaddress.ip_address(socket.gethostbyname(netloc))
if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
    return False
```

**Verification**
- Resolve the host to an IP and reject private/loopback/link-local/reserved ranges.
- Numeric and short-form IPs must be normalized before validation.
- A normal external URL must still work.


### 4. Path traversal in scan_id (limited to .json files)
- **Status:** PARTIALLY VALID / Low / confidence Medium / CWE-22
- **Root cause:** `scan_id=../../some/file` can escape the `report/` directory, but the `.json` suffix restricts the target. This is a real traversal primitive, but the old claim that it reads the flag is not supported unless the flag is in a `.json` file.
- **Exploit page:** `exploits/tempest-poc/exploit.py --vuln traversal`

**Vulnerable pattern**
```text
report_file = f"report/{scan_id}.json"
with open(report_file, "r") as f:
    scan_data = json.load(f)
```

**Patched pattern**
```text
scan_id = str(uuid.UUID(scan_id))
report_file = os.path.join("report", scan_id + ".json")
if not os.path.realpath(report_file).startswith(os.path.realpath("report") + os.sep):
    raise ValueError("invalid scan_id")
```

**Verification**
- Validate `scan_id` as a UUID and resolve the path under `report/`.
- Traversal strings must return 400; a legitimate report must still render.

## Reference diffs
Apply from the challenge root with `patch -p1`:

```bash
cd gemastik-xvii-final/tempest-poc
patch -p1 --dry-run < ../../patches/fix-upgrade-scope.diff
patch -p1 < ../../patches/fix-upgrade-scope.diff
```

Each diff is generated against the unmodified source in this workspace and was dry-run tested with `patch -p1 --dry-run`.

## Regression checklist
- The original exploit/request from the matching `exploits/` page must fail.
- The normal functionality described in the challenge must still work.
- Add the verification assertions from every finding above to CI or a lab smoke test.
