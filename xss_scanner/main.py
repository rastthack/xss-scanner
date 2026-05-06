#!/usr/bin/env python3
"""
xss-scanner — Advanced XSS Vulnerability Scanner
For authorized penetration testing and bug bounty programs only.
"""

import sys
import time
import argparse
import urllib.parse

from colorama import Fore, Style, init
init(autoreset=True)

from .client      import HTTPClient
from .fingerprint import TechFingerprinter
from .crawler     import Crawler
from .auth        import AuthHandler
from .engine      import Engine
from .reporter    import Logger, Reporter

# ─────────────────────────────────────────────────────────────────────────────
BANNER = rf"""
{Fore.RED}██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
{Fore.RED}╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
{Fore.YELLOW} ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
{Fore.YELLOW} ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
{Fore.RED}██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
{Fore.RED}╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.CYAN}  ┌─────────────────────────────────────────────────────────────────────────┐
{Fore.CYAN}  │  {Fore.WHITE}Advanced XSS Vulnerability Scanner  {Fore.YELLOW}v2.0{Fore.WHITE}  by Security Research      {Fore.CYAN}│
{Fore.CYAN}  │  {Fore.GREEN}✔  PortSwigger Cheat Sheet Payloads   ✔  Framework-aware          {Fore.CYAN}│
{Fore.CYAN}  │  {Fore.GREEN}✔  Auto-crawl + Form detection        ✔  Burp-style output        {Fore.CYAN}│
{Fore.CYAN}  │  {Fore.GREEN}✔  Auth bypass support                ✔  Blind / OOB XSS         {Fore.CYAN}│
{Fore.CYAN}  │  {Fore.RED}⚠  For AUTHORIZED use only — Unauthorized access is illegal  ⚠   {Fore.CYAN}│
{Fore.CYAN}  └─────────────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}"""


# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="xss-scanner",
        description="Advanced XSS Vulnerability Scanner — authorized use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━  EXAMPLES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Basic scan:
    python -m xss_scanner -u https://target.com

  Authenticated scan (interactive credentials prompt):
    python -m xss_scanner -u https://target.com --auth

  Authenticated scan (credentials on command line):
    python -m xss_scanner -u https://target.com -U admin -P secret123

  Deep crawl (200 pages) through Burp Suite proxy:
    python -m xss_scanner -u https://target.com \\
        --max-pages 200 --proxy http://127.0.0.1:8080

  Blind / Out-of-Band XSS with Burp Collaborator:
    python -m xss_scanner -u https://target.com \\
        --collaborator https://xyz.burpcollaborator.net

  Inject existing session cookie + save JSON report:
    python -m xss_scanner -u https://target.com \\
        -c "session=abc123; csrftoken=xyz" --json-out report.json

  Single URL with specific parameters, verbose, save log:
    python -m xss_scanner -u "https://target.com/search?q=hello&page=1" \\
        -v -o scan.log

  Custom headers (e.g. API key):
    python -m xss_scanner -u https://target.com \\
        -H "X-Api-Key: secret" -H "Authorization: Bearer token123"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━""")

    # Target
    p.add_argument("-u", "--url",  required=True,
                   help="Target URL  (e.g. https://example.com or https://example.com/search?q=test)")

    # Auth
    auth = p.add_argument_group("Authentication")
    auth.add_argument("--auth",  action="store_true",
                      help="Enable authenticated scan (prompts for credentials)")
    auth.add_argument("-U", "--username", metavar="USER",
                      help="Username / email for login")
    auth.add_argument("-P", "--password", metavar="PASS",
                      help="Password for login")

    # Session
    sess = p.add_argument_group("Session")
    sess.add_argument("-c", "--cookies", metavar="COOKIE_STRING",
                      help='Cookie string  e.g. "session=abc; token=xyz"')
    sess.add_argument("-H", "--header", dest="headers", action="append",
                      metavar="Name:Value",
                      help="Add custom HTTP header (repeatable)")

    # Network
    net = p.add_argument_group("Network")
    net.add_argument("--proxy",   metavar="URL",
                     help="HTTP proxy  e.g. http://127.0.0.1:8080  (Burp Suite)")
    net.add_argument("--timeout", type=int, default=15, metavar="SEC",
                     help="Request timeout in seconds  (default: 15)")
    net.add_argument("--delay",   type=float, default=0.3, metavar="SEC",
                     help="Delay between requests in seconds  (default: 0.3)")

    # Crawl
    crawl = p.add_argument_group("Crawl")
    crawl.add_argument("--max-pages", type=int, default=100, metavar="N",
                       help="Maximum pages to crawl  (default: 100)")
    crawl.add_argument("--skip-headers", action="store_true",
                       help="Skip HTTP header injection tests")
    crawl.add_argument("--max-payloads", type=int, default=0, metavar="N",
                       help="Limit payload count per point  (0 = all)")

    # Blind XSS
    blind = p.add_argument_group("Blind / OOB XSS")
    blind.add_argument("--collaborator", metavar="URL",
                       help="Callback URL for blind XSS  (Burp Collaborator / interactsh)")

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="Verbose: show every request being tested")
    out.add_argument("-o", "--output", metavar="FILE",
                     help="Save plain-text log to FILE")
    out.add_argument("--json-out", metavar="FILE",
                     help="Save findings as JSON to FILE")

    return p


# ─────────────────────────────────────────────────────────────────────────────

class Scanner:
    def __init__(self, args):
        self.args  = args
        self.log   = Logger(verbose=args.verbose, outfile=args.output)
        self.client= HTTPClient(proxy=args.proxy,
                                timeout=args.timeout,
                                delay=args.delay)
        self.findings = []
        self.tech_stack = []

        # Apply session cookies
        if args.cookies:
            self.client.set_cookies_from_string(args.cookies)

        # Apply custom headers
        if args.headers:
            for h in args.headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    self.client.set_header(k.strip(), v.strip())

    # ── Step runner ───────────────────────────────────────────────────────────

    def run(self):
        args   = self.args
        log    = self.log
        client = self.client

        # Normalise URL
        target = args.url
        if not target.startswith("http"):
            target = "https://" + target

        print(BANNER)

        # ── Legal gate ────────────────────────────────────────────────────────
        print(f"{Fore.RED}{'━'*74}")
        print("  ⚠  LEGAL NOTICE: Only use this tool on systems you own or have")
        print("  ⚠  explicit written authorisation to test. Unauthorised use is")
        print("  ⚠  a criminal offence in most jurisdictions.")
        print(f"{'━'*74}{Style.RESET_ALL}\n")
        confirm = input(
            f"{Fore.YELLOW}  Do you have authorisation to test  {target} ?{Style.RESET_ALL}\n"
            f"  Type {Fore.GREEN}yes{Style.RESET_ALL} to continue: ").strip().lower()
        if confirm not in ("yes", "y"):
            print(f"\n{Fore.RED}  Scan aborted.{Style.RESET_ALL}\n")
            sys.exit(0)

        start = time.time()

        # ── Step 1: Reachability ──────────────────────────────────────────────
        log.section("STEP 1 ── Target Reachability")
        resp = client.get(target)
        if not resp:
            log.error(f"Cannot reach {target}. Check URL and connectivity.")
            sys.exit(1)
        log.success(f"Target online  →  HTTP {resp.status_code}  |  "
                    f"Server: {resp.headers.get('Server','?')}")

        # ── Step 2: Fingerprint ───────────────────────────────────────────────
        log.section("STEP 2 ── Technology Fingerprinting")
        self.tech_stack = TechFingerprinter.detect(resp)
        waf             = TechFingerprinter.detect_waf(resp)

        if self.tech_stack:
            log.success("Detected: " + ", ".join(self.tech_stack))
        else:
            log.warn("No specific technologies identified — using generic payload set.")
        if waf:
            log.warn(f"WAF / Security layer detected: {Fore.RED}{waf}{Style.RESET_ALL}")
            log.warn("WAF bypass payloads are included in the test set.")

        # ── Step 3: Auth ──────────────────────────────────────────────────────
        if args.auth or args.username:
            log.section("STEP 3 ── Authentication")
            username = args.username
            password = args.password
            if not username:
                username = input(f"{Fore.YELLOW}  Username / Email: {Style.RESET_ALL}").strip()
            if not password:
                import getpass
                password = getpass.getpass(f"{Fore.YELLOW}  Password: {Style.RESET_ALL}")
            ah = AuthHandler(client, target)
            ah.login(username, password, log)
        else:
            log.section("STEP 3 ── Authentication")
            log.info("No auth requested — scanning as guest/unauthenticated user.")
            log.info("Use --auth or -U/-P flags to test authenticated areas.")

        # ── Step 4: Payload prep ──────────────────────────────────────────────
        log.section("STEP 4 ── Payload Preparation")
        from .payloads import PayloadDB
        generic = PayloadDB.all_generic()
        fw      = PayloadDB.for_stack(self.tech_stack)
        blind   = PayloadDB.blind(args.collaborator) if args.collaborator else []
        total   = len(list(dict.fromkeys(generic + fw + blind)))

        log.success(f"Generic payloads   : {len(generic)}")
        if fw:
            log.success(f"Framework payloads : {len(fw)}  "
                        f"(matched: {', '.join(self.tech_stack[:4])})")
        if blind:
            log.success(f"Blind OOB payloads : {len(blind)}  → {args.collaborator}")
        log.success(f"Total unique       : {total} payloads queued")

        # ── Step 5: Crawl ─────────────────────────────────────────────────────
        log.section("STEP 5 ── Web Crawling")
        crawler = Crawler(client, target, max_pages=args.max_pages)

        # If target URL has query params, add them immediately
        parsed_target = urllib.parse.urlparse(target)
        if parsed_target.query:
            for name in urllib.parse.parse_qs(parsed_target.query):
                crawler.url_params.append({
                    "url":      target,
                    "param":    name,
                    "original": urllib.parse.parse_qs(parsed_target.query)[name][0],
                })

        crawler.crawl(log)
        log.success(crawler.summary())

        # ── Step 6: Scan ──────────────────────────────────────────────────────
        engine = Engine(
            client      = client,
            tech_stack  = self.tech_stack,
            collaborator= args.collaborator,
            verbose     = args.verbose,
            max_payloads= args.max_payloads,
        )

        # 6a — URL parameters
        if crawler.url_params:
            # Deduplicate param+url combos
            seen_p, unique_params = set(), []
            for t in crawler.url_params:
                key = (t["url"], t["param"])
                if key not in seen_p:
                    seen_p.add(key)
                    unique_params.append(t)

            log.section(f"STEP 6a ── URL Parameter Injection  [{len(unique_params)} params]")
            for i, tgt in enumerate(unique_params, 1):
                log.info(f"[{i}/{len(unique_params)}] "
                         f"param='{tgt['param']}'  url={tgt['url'][:70]}")
                results = engine.test_url_param(tgt, log)
                engine.findings.extend(results)
        else:
            log.section("STEP 6a ── URL Parameter Injection")
            log.warn("No URL parameters found to test.")

        # 6b — Form fields
        if crawler.forms:
            # Deduplicate forms
            seen_f, unique_forms = set(), []
            for f in crawler.forms:
                key = (f["action"], f["method"], tuple(sorted(f["fields"])))
                if key not in seen_f:
                    seen_f.add(key)
                    unique_forms.append(f)

            log.section(f"STEP 6b ── Form Field Injection  [{len(unique_forms)} forms]")
            for i, form in enumerate(unique_forms, 1):
                testable = len([k for k in form["fields"]
                                if not __import__('re').search(
                                    r'csrf|token|nonce', k, __import__('re').I)])
                log.info(f"[{i}/{len(unique_forms)}] "
                         f"{form['method']} {form['action'][:60]}  "
                         f"({len(form['fields'])} fields, {testable} injectable)")
                results = engine.test_form(form, log)
                engine.findings.extend(results)
        else:
            log.section("STEP 6b ── Form Field Injection")
            log.warn("No forms found to test.")

        # 6c — HTTP headers
        if not args.skip_headers:
            log.section("STEP 6c ── HTTP Header Injection")
            results = engine.test_headers(target, log)
            engine.findings.extend(results)
        else:
            log.section("STEP 6c ── HTTP Header Injection")
            log.info("Skipped (--skip-headers flag set).")

        # Deduplicate all findings
        engine.deduplicate()
        self.findings = engine.findings

        # ── Step 7: Report ────────────────────────────────────────────────────
        log.section(f"STEP 7 ── VULNERABILITY REPORT  [{len(self.findings)} found]")

        if self.findings:
            for i, finding in enumerate(self.findings, 1):
                Reporter.print_finding(finding, i, log)
        else:
            log.success("No XSS vulnerabilities detected in the tested scope.")

        Reporter.print_summary(self.findings, client, start, target, log)

        # ── Save outputs ──────────────────────────────────────────────────────
        if args.json_out:
            Reporter.save_json(self.findings, args.json_out,
                               target, self.tech_stack)
            log.success(f"JSON report  → {args.json_out}")

        if args.output:
            log.save()


# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()
    try:
        Scanner(args).run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
