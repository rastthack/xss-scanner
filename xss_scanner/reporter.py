"""
Logger + Reporter
Colourised terminal output and actionable vulnerability reports.
"""

import re
import json
import urllib.parse
from datetime import datetime
from collections import Counter
from typing import List

from colorama import Fore, Back, Style, init
init(autoreset=True)

from .client import HTTPClient


# ─────────────────────────────────────────────────────────────────────────────
#  LOGGER
# ─────────────────────────────────────────────────────────────────────────────

class Logger:
    def __init__(self, verbose: bool = False, outfile: str = None):
        self.verbose   = verbose
        self.outfile   = outfile
        self._lines: List[str] = []

    def _emit(self, colour_msg: str, plain: str = ""):
        print(colour_msg)
        self._lines.append(plain or self._strip(colour_msg))

    @staticmethod
    def _strip(s: str) -> str:
        return re.sub(r'\x1b\[[0-9;]*m', '', s)

    def info(self, msg: str):
        self._emit(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}", f"[*] {msg}")

    def success(self, msg: str):
        self._emit(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}", f"[+] {msg}")

    def warn(self, msg: str):
        self._emit(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}", f"[!] {msg}")

    def error(self, msg: str):
        self._emit(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}", f"[-] {msg}")

    def debug(self, msg: str):
        if self.verbose:
            self._emit(f"{Fore.MAGENTA}[D]{Style.RESET_ALL} {msg}", f"[D] {msg}")

    def vuln(self, msg: str):
        self._emit(
            f"{Back.RED}{Fore.WHITE}[VULN]{Style.RESET_ALL} {Fore.RED}{msg}{Style.RESET_ALL}",
            f"[VULN] {msg}")

    def progress(self, msg: str):
        print(f"\r{Fore.BLUE}{msg:<100}{Style.RESET_ALL}", end="", flush=True)

    def section(self, title: str):
        bar = "═" * 72
        plain_bar = "=" * 72
        self._emit(
            f"\n{Fore.CYAN}{bar}\n  {title}\n{bar}{Style.RESET_ALL}",
            f"\n{plain_bar}\n  {title}\n{plain_bar}")

    def save(self):
        if self.outfile:
            with open(self.outfile, "w", encoding="utf-8") as f:
                f.write("\n".join(self._lines))
            self.success(f"Log saved → {self.outfile}")


# ─────────────────────────────────────────────────────────────────────────────
#  REPORTER
# ─────────────────────────────────────────────────────────────────────────────

class Reporter:

    @staticmethod
    def print_finding(finding, index: int, log: Logger):
        from .engine import Finding   # avoid circular

        sev_colour = {
            "Critical": Fore.RED + Style.BRIGHT,
            "High":     Fore.RED,
            "Medium":   Fore.YELLOW,
            "Low":      Fore.GREEN,
        }.get(finding.severity, Fore.WHITE)

        log.section(
            f"FINDING #{index}  ──  {finding.vuln_type}  "
            f"[{sev_colour}{finding.severity}{Style.RESET_ALL}  "
            f"Confidence: {finding.confidence}]")

        fields = [
            ("📍 Location",  finding.location),
            ("🌐 Page URL",  finding.page_url),
            ("🎯 Inject URL",finding.injection_url),
            ("📝 Parameter", finding.parameter),
            ("⚙  Method",   finding.method),
            ("🔍 Context",  finding.context),
            ("📊 Evidence",  finding.evidence),
            ("📶 Status",   str(finding.status_code)),
        ]
        for label, val in fields:
            print(f"  {Fore.YELLOW}{label:<14}{Style.RESET_ALL}: {val}")

        # Payload box
        print(f"\n  {Fore.YELLOW}{'─'*68}")
        print(f"  WORKING PAYLOAD")
        print(f"  {'─'*68}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}{finding.payload}{Style.RESET_ALL}")

        # HTTP Request (Burp Repeater style)
        print(f"\n  {Fore.YELLOW}{'─'*68}")
        print(f"  HTTP REQUEST  (Burp Suite Repeater Style)")
        print(f"  {'─'*68}{Style.RESET_ALL}")
        for line in finding.request_raw.split("\n"):
            colour = Fore.CYAN if line.startswith(
                ("GET", "POST", "PUT", "DELETE", "HTTP")) else Fore.WHITE
            print(f"  {colour}{line}{Style.RESET_ALL}")

        # Response snippet
        print(f"\n  {Fore.YELLOW}{'─'*68}")
        print(f"  RESPONSE SNIPPET  (first 500 chars)")
        print(f"  {'─'*68}{Style.RESET_ALL}")
        snippet = (finding.response_snippet or "")[:500]
        print(f"  {Fore.CYAN}{snippet}{Style.RESET_ALL}")

        # Manual verification steps
        print(f"\n  {Fore.YELLOW}{'─'*68}")
        print(f"  MANUAL VERIFICATION STEPS")
        print(f"  {'─'*68}{Style.RESET_ALL}")
        steps = Reporter._manual_steps(finding)
        for i, step in enumerate(steps, 1):
            # Multi-line steps
            lines = step.split("\n")
            print(f"\n  {Fore.WHITE}Step {i}:{Style.RESET_ALL} {lines[0]}")
            for extra in lines[1:]:
                print(f"         {extra}")

        # Remediation
        print(f"\n  {Fore.RED}{'─'*68}")
        print(f"  REMEDIATION")
        print(f"  {'─'*68}{Style.RESET_ALL}")
        for r in Reporter._remediation():
            print(f"  {Fore.GREEN}▸{Style.RESET_ALL} {r}")

    # ── Manual steps generator ────────────────────────────────────────────────

    @staticmethod
    def _manual_steps(f) -> List[str]:
        G  = Fore.GREEN
        C  = Fore.CYAN
        Y  = Fore.YELLOW
        R  = Style.RESET_ALL
        url    = f.injection_url
        base   = url.split("?")[0]
        param  = f.parameter
        payload= f.payload
        method = f.method
        loc    = f.location

        enc_payload = urllib.parse.quote(payload, safe="")

        steps = []

        if "URL Parameter" in loc or method == "GET":
            test_url = f"{base}?{param}={enc_payload}"
            steps = [
                (f"Open {C}{base}{R} in your browser\n"
                 f"         (Chrome/Firefox with DevTools open → F12)"),
                (f"Manually navigate to this crafted URL:\n\n"
                 f"         {G}{test_url}{R}\n\n"
                 f"         Watch for a JavaScript alert dialog."),
                (f"If alert fires → XSS is {G}CONFIRMED{R}.\n"
                 f"         If no alert → check DevTools Console for errors\n"
                 f"         and view the Page Source to see how payload lands."),
                (f"Verify with {C}curl{R}:\n\n"
                 f"         {C}curl -sk '{test_url}' | grep -i '{payload[:30]}'{R}"),
                (f"Verify in {Y}Burp Suite Repeater{R}:\n"
                 f"         a) Proxy → Intercept → visit target\n"
                 f"         b) Intercept the GET request, Send to Repeater (Ctrl+R)\n"
                 f"         c) In the query string set:\n"
                 f"            {param} = {G}{payload}{R}\n"
                 f"         d) Click Send → inspect Response tab for unencoded payload"),
            ]

        elif "Form" in loc or method == "POST":
            curl_data = urllib.parse.urlencode({param: payload})
            steps = [
                f"Open {C}{base}{R} in your browser — locate the form",
                (f"Find the field named '{Y}{param}{R}' and clear its value.\n"
                 f"         Paste this payload into it:\n\n"
                 f"         {G}{payload}{R}\n\n"
                 f"         Submit the form and watch for an alert."),
                (f"Verify with {C}curl{R}:\n\n"
                 f"         {C}curl -sk -X POST '{url}' \\\n"
                 f"              --data '{curl_data}'{R}\n\n"
                 f"         Then check if the payload appears unencoded in the output."),
                (f"Verify in {Y}Burp Suite Repeater{R}:\n"
                 f"         a) Proxy → visit the page, fill and submit the form\n"
                 f"         b) Intercept the POST, Send to Repeater (Ctrl+R)\n"
                 f"         c) In the body, change {param} value to:\n"
                 f"            {G}{payload}{R}\n"
                 f"         d) Click Send → check Response for unencoded payload"),
            ]

        elif "Header" in loc:
            steps = [
                (f"The injection point is in the HTTP header:\n"
                 f"         {Y}{param}{R}"),
                (f"Verify with {C}curl{R}:\n\n"
                 f"         {C}curl -sk '{url}' \\\n"
                 f"              -H '{param}: {payload}'{R}\n\n"
                 f"         Check if payload appears unencoded in the response."),
                (f"Verify in {Y}Burp Suite Repeater{R}:\n"
                 f"         a) Intercept any request to {url}\n"
                 f"         b) Send to Repeater\n"
                 f"         c) Add / modify the header:\n"
                 f"            {Y}{param}: {G}{payload}{R}\n"
                 f"         d) Click Send → check Response"),
            ]
        else:
            steps = [
                f"Navigate to {C}{url}{R} and test the injection point manually.",
                f"Try injecting: {G}{payload}{R}",
            ]

        steps += [
            (f"{Y}Impact Assessment{R}:\n"
             f"         • Session hijacking via {C}document.cookie{R} theft\n"
             f"         • Credential harvesting (fake login overlays)\n"
             f"         • Account takeover via CSRF token theft\n"
             f"         • Defacement / drive-by malware distribution"),
        ]
        return steps

    @staticmethod
    def _remediation() -> List[str]:
        return [
            "HTML-encode ALL user input before rendering: use htmlspecialchars() / escapeHtml()",
            "Implement a strict Content-Security-Policy (CSP) response header",
            "Use HttpOnly + Secure flags on all session cookies",
            "Apply a trusted sanitiser library: DOMPurify (JS) or OWASP Java HTML Sanitizer",
            "Validate and allowlist input server-side — never rely on client-side only",
            "Enable X-XSS-Protection: 1; mode=block and X-Content-Type-Options: nosniff headers",
            "For React/Angular/Vue — never use dangerouslySetInnerHTML or [innerHTML] with user data",
        ]

    # ── Summary ───────────────────────────────────────────────────────────────

    @staticmethod
    def print_summary(findings: list, client: HTTPClient,
                      start_time: float, target: str, log: Logger):
        import time
        elapsed = time.time() - start_time
        log.section("SCAN SUMMARY")

        counts = Counter(f.vuln_type for f in findings)

        print(f"\n  {Fore.CYAN}Target          :{Style.RESET_ALL} {target}")
        print(f"  {Fore.CYAN}Requests sent   :{Style.RESET_ALL} {client.sent}")
        print(f"  {Fore.CYAN}Responses recv  :{Style.RESET_ALL} {client.received}")
        print(f"  {Fore.CYAN}Duration        :{Style.RESET_ALL} {elapsed:.1f}s")
        print(f"  {Fore.CYAN}Vulnerabilities :{Style.RESET_ALL} "
              f"{Fore.RED if findings else Fore.GREEN}"
              f"{len(findings)}{Style.RESET_ALL}\n")

        if findings:
            for vtype, cnt in sorted(counts.items(), key=lambda x: -x[1]):
                print(f"    {Fore.RED}[{cnt:2d}]{Style.RESET_ALL}  {vtype}")
            print(f"\n  {Fore.YELLOW}⚠  Report these findings only to the target's security team "
                  f"or bug bounty programme.{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}  ✓ No XSS vulnerabilities detected in tested scope.{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}  Note: Clean result does not guarantee full security.{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}  Consider DOM-based XSS, stored XSS, and client-side code review.{Style.RESET_ALL}")

        print()

    # ── Save JSON ─────────────────────────────────────────────────────────────

    @staticmethod
    def save_json(findings: list, path: str, target: str, tech_stack: list):
        report = {
            "tool":       "xss-scanner",
            "version":    "2.0",
            "timestamp":  datetime.utcnow().isoformat() + "Z",
            "target":     target,
            "tech_stack": tech_stack,
            "total":      len(findings),
            "findings":   [f.to_dict() for f in findings],
        }
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2)
