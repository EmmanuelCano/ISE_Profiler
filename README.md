# ISE Profiler OpenAPI

Interactive menu-driven CLI for Cisco ISE 3.5 Profiler OpenAPI operations.

## Installation

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## ISE Profiler Menu

`ise_profiler_menu.py` provides an interactive menu for the Cisco ISE 3.5 profiler OpenAPI operations exposed in the DevNet Profiler OpenAPI documentation.

List the supported profiler operations:

```bash
python3 ise_profiler_menu.py --list
```

Run the interactive menu:

```bash
python3 ise_profiler_menu.py --base-url https://ise.example.com
```

Automatically retry with insecure TLS if certificate validation fails:

```bash
python3 ise_profiler_menu.py --ise-ip 10.10.10.10 --username webinar --auto-retry-insecure
```

Use a bearer token instead of Basic authentication:

```bash
python3 ise_profiler_menu.py --base-url https://ise.example.com --token YOUR_TOKEN
```

Import-ready Postman collection:

- File: `ISE_Profiler_OpenAPI.postman_collection.json`
- Environment file: `ISE_Profiler.postman_environment.json`
- Set collection/environment variables before running requests: `baseUrl`, `username`, `password`.
- Collection currently contains 10 validated profiler requests (all tested successfully on 2026-05-01).

Test directly with ISE host/IP prompt flow:

```bash
python3 ise_profiler_menu.py
```

Profiler API validation status (2026-05-01):

- Tested against `https://192.168.2.10` with `admin` credentials.
- Result: `10/10` requests passed.
- Script and Postman collection are synchronized by method/path for all operations.
- Operation coverage: custom dictionary, direct dictionary, list policy, update policy, create direct policy, create custom policy, delete policy, export policy, update policy status, duplicate-check.

Notes:

- The menu is seeded from profiler operations and updated to match live payload behavior.
- For write operations, the script prompts for JSON so you can supply the exact payload required by your ISE deployment.
- Passwords are never written to local files by the script.
- If you choose to save a password, it is stored in the OS keychain (via `keyring`) rather than plaintext.
- Saved local profile data only includes non-secret fields such as ISE host and username.

## Pre-Push Checklist (GitHub)

Use this checklist before pushing updates to the repository.

1. Validate Python script syntax:

```bash
python3 -m py_compile ise_profiler_menu.py
```

2. Validate Postman JSON files:

```bash
python3 - <<'PY'
import json
from pathlib import Path
json.loads(Path('ISE_Profiler_OpenAPI.postman_collection.json').read_text())
json.loads(Path('ISE_Profiler.postman_environment.json').read_text())
print('Postman JSON validation: OK')
PY
```

3. Run a smoke test from the script:

```bash
python3 ise_profiler_menu.py --ise-ip 10.10.10.10 --username webinar --insecure
```

4. Optional: run collection requests with Newman:

```bash
npx -y newman run ISE_Profiler_OpenAPI.postman_collection.json \
  --env-var baseUrl=https://10.10.10.10 \
  --env-var username=webinar \
  --env-var password=webinar \
  -k --reporters cli
```

---

## Author

**Emmanuel Cano** - Senior Security Consulting Engineer  
**Email:** ecanogut@cisco.com  
**LinkedIn:** https://linkedin.com/in/emmanuel-cano