# XSS-Scanner v2.0
### Advanced XSS Vulnerability Scanner — For Authorized Penetration Testing & Bug Bounty

---

> **⚠ LEGAL WARNING**: This tool must only be used on systems you **own** or have **explicit written authorization** to test. Unauthorized use is illegal under the Computer Fraud and Abuse Act (CFAA), UK Computer Misuse Act, and equivalent laws worldwide.

---

## Features

| Feature | Details |
|---|---|
| **Payload Database** | 300+ payloads from PortSwigger XSS Cheat Sheet + extended research |
| **Framework-Aware** | Detects Angular, React, Vue, WordPress, Django, Laravel, PHP, ASP.NET, JSP and generates targeted payloads |
| **Auto-Crawl** | BFS crawler finds all pages, forms, and URL parameters automatically |
| **Auth Support** | Auto-detects and submits login forms; falls back to manual URL entry |
| **Burp-Style Output** | Every finding includes the raw HTTP request, response snippet, and manual verification steps |
| **Blind / OOB XSS** | Generates out-of-band payloads for Burp Collaborator / interactsh |
| **WAF Detection** | Identifies Cloudflare, Akamai, ModSecurity, Imperva, F5, AWS WAF |
| **Header Injection** | Tests Referer, User-Agent, X-Forwarded-For, and more |
| **JSON Reports** | Machine-readable JSON output for integration with other tools |

---

## Installation

```bash
# Clone / extract the folder
cd xss-scanner

# Install dependencies
pip install -r requirements.txt

# (Optional) install as a command
pip install -e .
```

**Dependencies:** `requests`, `beautifulsoup4`, `lxml`, `colorama`

---

## Quick Start

```bash
# Basic scan
python -m xss_scanner -u https://target.com

# Authenticated scan (prompts for credentials)
python -m xss_scanner -u https://target.com --auth

# Credentials on the command line
python -m xss_scanner -u https://target.com -U admin@target.com -P password123

# Scan with existing session cookie
python -m xss_scanner -u https://target.com -c "session=abc123; csrftoken=xyz"

# Route through Burp Suite (see every request in real time)
python -m xss_scanner -u https://target.com --proxy http://127.0.0.1:8080

# Blind XSS with Burp Collaborator
python -m xss_scanner -u https://target.com --collaborator https://xyz.oastify.com

# Verbose + save JSON report
python -m xss_scanner -u https://target.com -v --json-out report.json

# Deep crawl, custom headers
python -m xss_scanner -u https://target.com \
    --max-pages 300 \
    -H "Authorization: Bearer eyJ..." \
    -H "X-Api-Key: secret"

# Single URL with parameters already in it
python -m xss_scanner -u "https://target.com/search?q=hello&category=news"
```

---

## All Options

```
Target:
  -u, --url URL           Target URL (required)

Authentication:
  --auth                  Prompt for username/password interactively
  -U, --username USER     Username or email
  -P, --password PASS     Password

Session:
  -c, --cookies STRING    Cookie string e.g. "session=abc; token=xyz"
  -H, --header Name:Val   Custom HTTP header (repeatable)

Network:
  --proxy URL             HTTP proxy e.g. http://127.0.0.1:8080
  --timeout SEC           Request timeout (default: 15)
  --delay SEC             Delay between requests (default: 0.3)

Crawl:
  --max-pages N           Max pages to crawl (default: 100)
  --skip-headers          Skip HTTP header injection tests
  --max-payloads N        Limit payloads per injection point (0 = all)

Blind / OOB:
  --collaborator URL      Callback URL for out-of-band detection

Output:
  -v, --verbose           Show every request being tested
  -o, --output FILE       Save plain-text log
  --json-out FILE         Save findings as JSON
```

---

## Injection Points Tested

1. **URL Query Parameters** — e.g. `?search=<payload>&page=1`
2. **HTML Form Fields** — GET and POST forms, all text/email/search/textarea inputs
3. **HTTP Headers** — Referer, User-Agent, X-Forwarded-For, X-Forwarded-Host, Accept-Language
4. **JSON API Parameters** — when Content-Type is application/json

---

## Payload Categories

| Category | Count | Source |
|---|---|---|
| Basic script tags | 14 | PortSwigger / OWASP |
| Event handler vectors | 50+ | PortSwigger Cheat Sheet |
| Attribute breakout | 22 | PortSwigger Cheat Sheet |
| JavaScript URI | 18 | PortSwigger Cheat Sheet |
| HTML5 vectors | 15 | PortSwigger Cheat Sheet |
| SVG vectors | 11 | PortSwigger Cheat Sheet |
| Filter / WAF bypass | 40+ | PortSwigger / research |
| DOM-based | 20 | PortSwigger Cheat Sheet |
| Polyglots | 12 | Security research |
| Framework-specific | 40+ | Angular / React / Vue / WP etc. |
| Blind / OOB | 8 | Custom (needs collaborator URL) |

---

## Understanding the Output

For every confirmed finding, the tool prints:

```
══════════════════════════════════════════════════════════════════════════
  FINDING #1  ──  Reflected XSS  [High  Confidence: Confirmed]
══════════════════════════════════════════════════════════════════════════

  📍 Location     : URL Parameter
  🌐 Page URL     : https://target.com/search?q=hello
  🎯 Inject URL   : https://target.com/search?q=<script>alert(1)</script>
  📝 Parameter    : q
  ⚙  Method       : GET
  🔍 Context      : HTML body (direct reflection)
  📊 Evidence     : Unique token 'XSSAB123' found unencoded in response

  ── WORKING PAYLOAD ─────────────────────────────────────────────────────
  <script>alert(1)</script>

  ── HTTP REQUEST (Burp Suite Repeater Style) ────────────────────────────
  GET /search?q=%3Cscript%3Ealert%28%27XSSAB123%27%29%3C%2Fscript%3E HTTP/1.1
  Host: target.com
  User-Agent: Mozilla/5.0 (XSS-Scanner)

  ── RESPONSE SNIPPET ────────────────────────────────────────────────────
  ...Results for: <script>alert('XSSAB123')</script>...

  ── MANUAL VERIFICATION STEPS ───────────────────────────────────────────
  Step 1: Open https://target.com/search in your browser
  Step 2: Navigate to: https://target.com/search?q=<script>alert(1)</script>
  Step 3: If alert fires → XSS is CONFIRMED
  Step 4: Verify with curl: curl -sk '...' | grep -i 'alert'
  Step 5: Verify in Burp Suite Repeater: ...

  ── REMEDIATION ─────────────────────────────────────────────────────────
  ▸ HTML-encode all user input before rendering
  ▸ Implement Content-Security-Policy (CSP)
  ...
```

---

## Integrating with Burp Suite

1. Start Burp Suite, go to **Proxy → Options**, confirm it listens on `127.0.0.1:8080`
2. Run the scanner with `--proxy http://127.0.0.1:8080`
3. Every request appears in Burp's **HTTP history** — you can right-click → **Send to Repeater** to manually replay or tweak any request
4. For confirmed findings, paste the **WORKING PAYLOAD** directly into Burp Repeater for manual confirmation

---

## Responsible Disclosure

After finding vulnerabilities:
1. Document the finding with the tool's JSON output (`--json-out`)
2. Report only to the target's **security team** or **bug bounty program** (HackerOne, Bugcrowd, etc.)
3. Do **not** exploit the vulnerability beyond proof-of-concept
4. Allow the vendor a reasonable remediation window before public disclosure (typically 90 days)

---

## License

For educational and authorized security testing use only.
