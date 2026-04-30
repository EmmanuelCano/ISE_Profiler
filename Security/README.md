# Security

Security automation and analysis scripts.

## WSA/SMA XML Audit

`wsa_sma_xml_audit.py` analyzes Cisco WSA and SMA XML configuration exports and generates a Word report with likely security risks, improvement opportunities, and misconfiguration candidates derived from Cisco best-practice guidance.

Install dependencies:

```bash
python3 -m pip install -r Security/requirements.txt
```

## ISE Profiler Menu

`ise_profiler_menu.py` provides an interactive menu for the Cisco ISE 3.5 profiler OpenAPI operations exposed in the DevNet Profiler OpenAPI documentation.

List the supported profiler operations:

```bash
python3 Security/ise_profiler_menu.py --list
```

Run the interactive menu:

```bash
python3 Security/ise_profiler_menu.py --base-url https://ise.example.com
```

Automatically retry with insecure TLS if certificate validation fails:

```bash
python3 Security/ise_profiler_menu.py --ise-ip 10.10.10.10 --username webinar --auto-retry-insecure
```

Use a bearer token instead of Basic authentication:

```bash
python3 Security/ise_profiler_menu.py --base-url https://ise.example.com --token YOUR_TOKEN
```

Import-ready Postman collection:

- File: `Security/ISE_Profiler_OpenAPI.postman_collection.json`
- Environment file: `Security/ISE_Profiler.postman_environment.json`
- Set collection/environment variables before running requests: `baseUrl`, `username`, `password`.
- Collection currently contains 10 validated profiler requests (all tested successfully on 2026-05-01).

Test directly with ISE host/IP prompt flow:

```bash
python3 Security/ise_profiler_menu.py
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

Analyze a single XML export:

```bash
python3 Security/wsa_sma_xml_audit.py wsa_configurations/proxychainsam01_wsa-adm.scc.corp.xml
```

Analyze every XML file in a folder and generate one combined report:

```bash
python3 Security/wsa_sma_xml_audit.py wsa_configurations -o wsa_configurations/wsa_sma_security_assessment.docx
```

Notes:

- The report is heuristic and should be validated against the live WSA or SMA UI and CLI.
- XML schemas vary across AsyncOS versions, so findings are based on path and value matching rather than a fixed vendor schema.

## Pre-Push Checklist (GitHub)

Use this checklist before pushing updates to the repository.

1. Validate Python script syntax:

```bash
python3 -m py_compile Security/ise_profiler_menu.py
```

2. Validate Postman JSON files:

```bash
python3 - <<'PY'
import json
from pathlib import Path
json.loads(Path('Security/ISE_Profiler_OpenAPI.postman_collection.json').read_text())
json.loads(Path('Security/ISE_Profiler.postman_environment.json').read_text())
print('Postman JSON validation: OK')
PY
```

3. Run a smoke test from the script:

```bash
python3 Security/ise_profiler_menu.py --ise-ip 10.10.10.10 --username webinar --insecure
```

4. Optional: run collection requests with Newman:

```bash
npx -y newman run Security/ISE_Profiler_OpenAPI.postman_collection.json \
  --env-var baseUrl=https://10.10.10.10 \
  --env-var username=webinar \
  --env-var password=webinar \
  -k --reporters cli
```

## Push to GitHub

From the repository root:

```bash
git status
git add Security/ise_profiler_menu.py Security/ISE_Profiler_OpenAPI.postman_collection.json Security/ISE_Profiler.postman_environment.json Security/README.md
git commit -m "Align ISE profiler script and Postman collection; validate full API set"
git push origin <branch-name>
```

Suggested pull request summary:

- Synchronizes script and Postman operation contracts.
- Fixes CUSTOM policy condition payload schema so conditions persist.
- Fixes policy-status request body schema to array format.
- Removes unsupported endpoint calls from active operation set.
- Documents validation and release/push workflow.