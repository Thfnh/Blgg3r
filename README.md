# WebVulnScanner V2 — Python CLI

A small **passive-first** web inventory and security review tool for authorized assessments. It crawls HTML links and forms, records query/form parameter names, checks selected response headers/cookie attributes, flags a few information-disclosure heuristics, and writes JSON + HTML reports.

## Install

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

## Run against an authorized public website

```bash
python scanner.py https://staging.example.com --max-pages 50
```

The scanner stays on the target hostname by default. Add another host only when it is explicitly included in your authorization:

```bash
python scanner.py https://example.com --scope-host www.example.com --max-pages 100
```

Subdomains of an explicitly allowed domain are considered in scope by this initial version. Review the allowed hosts carefully before scanning.

## Authenticated scan with a test account

Export cookies from your authorized test session into a JSON file, for example `test-cookies.json`:

```json
{
  "session": "REPLACE_WITH_TEST_SESSION_VALUE"
}
```

Then run:

```bash
python scanner.py https://staging.example.com --cookie-file test-cookies.json
```

Treat the cookie file as a password: do not commit it, share it, or include it in reports. This version does not automate login forms; login flows vary and can trigger MFA/CSRF protections. It reuses the supplied cookies for GET requests.

## Local lab only

Private and loopback IPs are blocked by default. For your own local lab, use:

```bash
python scanner.py http://127.0.0.1:5000 --allow-private
```

## Output

Reports are written to `reports/` as JSON and HTML. Do not publish reports without reviewing them for session data or sensitive content.

## Current limitations

- Passive checks only; no exploit payloads are sent.
- HTML crawling only; JavaScript-rendered routes may be missed.
- Forms are inventoried but not submitted.
- Findings are heuristic review items, not proof of exploitability.
- No robots.txt bypass, directory brute forcing, port scanning, or out-of-scope crawling.
- This is a learning project, not a replacement for a professional security testing workflow.

Only scan systems you own or have explicit permission to test. Follow the program's written scope and automation policy.
