"""
XSS Detection Engine
Tests injection points: URL params, form fields, HTTP headers, JSON params.
Analyses responses to determine reflection context and executability.
"""

import re
import html
import urllib.parse
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

import requests

from .client  import HTTPClient
from .payloads import PayloadDB

# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    vuln_type:        str          # "Reflected XSS", "DOM XSS", etc.
    severity:         str          # Critical / High / Medium
    confidence:       str          # Confirmed / Likely / Possible
    location:         str          # "URL Parameter", "Form Field", etc.
    page_url:         str
    injection_url:    str
    parameter:        str
    method:           str
    payload:          str
    context:          str          # "HTML body", "HTML attribute", "JS string"
    evidence:         str
    request_raw:      str
    response_snippet: str
    status_code:      int
    form_data:        Dict = field(default_factory=dict)
    extra_headers:    Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type":           self.vuln_type,
            "severity":       self.severity,
            "confidence":     self.confidence,
            "location":       self.location,
            "page_url":       self.page_url,
            "injection_url":  self.injection_url,
            "parameter":      self.parameter,
            "method":         self.method,
            "payload":        self.payload,
            "context":        self.context,
            "evidence":       self.evidence,
            "status_code":    self.status_code,
        }


# ─────────────────────────────────────────────────────────────────────────────

class Analyser:
    """Determines whether and how a payload is reflected in a response."""

    # Tags / attributes that indicate potential execution
    EXEC_PATTERNS = [
        r"<script[^>]*>",
        r"onerror\s*=",
        r"onload\s*=",
        r"onfocus\s*=",
        r"onclick\s*=",
        r"onmouseover\s*=",
        r"ontoggle\s*=",
        r"onbegin\s*=",
        r"onanimationstart\s*=",
        r"onpointerover\s*=",
        r"javascript\s*:",
        r"<svg[^>]*onload",
        r"<img[^>]*onerror",
        r"<details[^>]*ontoggle",
    ]

    @classmethod
    def analyse(cls, payload: str, token: str,
                resp: requests.Response) -> tuple[bool, str, str]:
        """
        Returns (is_vulnerable, context, evidence).
        Checks for:
          1. Token reflected in body (confirms reflection without encoding)
          2. Payload structure survives unencoded (indicates executability)
        """
        if not resp:
            return False, "", ""

        body      = resp.text
        body_low  = body.lower()
        pay_low   = payload.lower()

        # ── Check 1: token reflected unencoded ──────────────────────────────
        if token and token in body:
            context  = cls._get_context(body, token)
            evidence = f"Unique token '{token}' found unencoded in response"
            return True, context, evidence

        # ── Check 2: full payload reflected ─────────────────────────────────
        if pay_low in body_low:
            # Make sure it isn't HTML-escaped
            escaped = html.escape(payload).lower()
            if escaped not in body_low:
                context  = cls._get_context(body, payload[:20])
                evidence = f"Payload reflected unencoded in response body"
                return True, context, evidence

        # ── Check 3: dangerous patterns survive (partial execution) ─────────
        for pat in cls.EXEC_PATTERNS:
            key = re.sub(r'\\.+', '', pat).replace(r"\s*", "").strip()
            if re.search(pat, pay_low) and re.search(pat, body_low):
                # Only flag if the payload snippet appears nearby
                match = re.search(pat, body_low)
                if match:
                    snippet_around = body_low[max(0, match.start()-50):match.end()+50]
                    if any(frag in snippet_around
                           for frag in pay_low.split("=")[:1]):
                        context  = cls._get_context(body, match.group())
                        evidence = f"Dangerous pattern '{pat}' found unencoded"
                        return True, context, evidence

        return False, "", ""

    @classmethod
    def _get_context(cls, body: str, needle: str) -> str:
        """Determine injection context from surrounding HTML."""
        idx = body.lower().find(needle.lower())
        if idx == -1:
            return "Unknown"

        before = body[max(0, idx - 200):idx]
        after  = body[idx:idx + 200]

        # Inside a JS block?
        if re.search(r'<script[^>]*>\s*$', before, re.I | re.S):
            return "JavaScript context (between <script> tags)"
        # Inside a JS string?
        if re.search(r"""(var|let|const)\s+\w+\s*=\s*['"]\s*$""", before):
            return "JavaScript string variable"
        # Inside an attribute value?
        if re.search(r'<\w+[^>]*(href|src|value|action|data)[^>]*=\s*["\']?\s*$',
                     before, re.I):
            return "HTML attribute value"
        # Inside an HTML comment?
        if re.search(r'<!--[^-]*$', before, re.S):
            return "HTML comment"
        # Inside a style block?
        if re.search(r'<style[^>]*>[^<]*$', before, re.I | re.S):
            return "CSS / style block"

        return "HTML body (direct reflection)"


# ─────────────────────────────────────────────────────────────────────────────

class Engine:
    """Main injection engine — tests every injection point."""

    # HTTP header names to test for injection
    INJECTABLE_HEADERS = [
        "Referer",
        "User-Agent",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Original-URL",
        "X-Custom-Header",
        "Accept-Language",
    ]

    def __init__(self, client: HTTPClient, tech_stack: list,
                 collaborator: str = None, verbose: bool = False,
                 max_payloads: int = 0):
        self.client      = client
        self.tech_stack  = tech_stack
        self.collaborator= collaborator
        self.verbose     = verbose
        self.findings:   List[Finding] = []

        # Build master payload list
        generic = PayloadDB.all_generic()
        fw      = PayloadDB.for_stack(tech_stack)
        blind   = PayloadDB.blind(collaborator) if collaborator else []

        all_p = list(dict.fromkeys(generic + fw + blind))
        self.payloads = all_p[:max_payloads] if max_payloads else all_p

    # ── URL Parameters ────────────────────────────────────────────────────────

    def test_url_param(self, target: dict, log) -> List[Finding]:
        """Inject each payload into a URL query parameter."""
        findings = []
        url      = target["url"]
        param    = target["param"]
        parsed   = urllib.parse.urlparse(url)

        for payload in self.payloads:
            token          = PayloadDB.make_token()
            tagged_payload = PayloadDB.tokenize(payload, token)

            qs       = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[param]= [tagged_payload]
            new_q    = urllib.parse.urlencode(qs, doseq=True)
            test_url = parsed._replace(query=new_q).geturl()

            if self.verbose:
                log.debug(f"  GET {param}={tagged_payload[:60]}")

            resp = self.client.get(test_url)
            if not resp:
                continue

            vuln, context, evidence = Analyser.analyse(payload, token, resp)
            if vuln:
                f = Finding(
                    vuln_type       = "Reflected XSS",
                    severity        = "High",
                    confidence      = "Confirmed" if token in (resp.text if resp else "") else "Likely",
                    location        = "URL Parameter",
                    page_url        = url,
                    injection_url   = test_url,
                    parameter       = param,
                    method          = "GET",
                    payload         = payload,
                    context         = context,
                    evidence        = evidence,
                    request_raw     = self._fmt_req("GET", test_url, {}),
                    response_snippet= (resp.text if resp else "")[:600],
                    status_code     = resp.status_code if resp else 0,
                )
                findings.append(f)
                log.vuln(f"[URL PARAM] {param} | {payload[:70]}")

        return findings

    # ── Form Fields ───────────────────────────────────────────────────────────

    def test_form(self, form: dict, log) -> List[Finding]:
        """Inject into every non-hidden form field."""
        findings   = []
        action     = form["action"]
        method     = form["method"]
        base_fields= dict(form["fields"])

        # Identify testable (non-hidden, non-csrf) fields
        testable = [
            name for name in base_fields
            if not re.search(r'csrf|token|nonce|__RequestVerification|_method',
                             name, re.I)
        ]
        if not testable:
            testable = list(base_fields.keys())  # test all as fallback

        for field_name in testable:
            for payload in self.payloads:
                token          = PayloadDB.make_token()
                tagged_payload = PayloadDB.tokenize(payload, token)

                data = dict(base_fields)
                data[field_name] = tagged_payload

                if self.verbose:
                    log.debug(f"  {method} {field_name}={tagged_payload[:60]}")

                if method == "POST":
                    resp = self.client.post(action, data=data)
                else:
                    resp = self.client.get(action, params=data)

                if not resp:
                    continue

                vuln, context, evidence = Analyser.analyse(payload, token, resp)
                if vuln:
                    f = Finding(
                        vuln_type       = "Reflected XSS",
                        severity        = "High",
                        confidence      = "Confirmed" if token in (resp.text if resp else "") else "Likely",
                        location        = f"Form Field ({method})",
                        page_url        = form["page_url"],
                        injection_url   = action,
                        parameter       = field_name,
                        method          = method,
                        payload         = payload,
                        context         = context,
                        evidence        = evidence,
                        request_raw     = self._fmt_req(method, action, data),
                        response_snippet= (resp.text if resp else "")[:600],
                        status_code     = resp.status_code if resp else 0,
                        form_data       = data,
                    )
                    findings.append(f)
                    log.vuln(f"[FORM {method}] {field_name} @ {action[:60]} | {payload[:60]}")

        return findings

    # ── HTTP Headers ──────────────────────────────────────────────────────────

    def test_headers(self, url: str, log) -> List[Finding]:
        """Inject into common HTTP headers and check for reflection."""
        findings = []
        header_payloads = [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
            "'-alert(1)-'",
        ]

        for header_name in self.INJECTABLE_HEADERS:
            for payload in header_payloads:
                token          = PayloadDB.make_token()
                tagged_payload = PayloadDB.tokenize(payload, token)
                extra          = {header_name: tagged_payload}

                resp = self.client.get(url, extra_headers=extra)
                if not resp:
                    continue

                vuln, context, evidence = Analyser.analyse(payload, token, resp)
                if vuln:
                    f = Finding(
                        vuln_type       = "Reflected XSS (HTTP Header)",
                        severity        = "High",
                        confidence      = "Likely",
                        location        = f"HTTP Header: {header_name}",
                        page_url        = url,
                        injection_url   = url,
                        parameter       = header_name,
                        method          = "GET",
                        payload         = payload,
                        context         = context,
                        evidence        = evidence,
                        request_raw     = self._fmt_req("GET", url, {}, extra),
                        response_snippet= (resp.text if resp else "")[:600],
                        status_code     = resp.status_code if resp else 0,
                        extra_headers   = extra,
                    )
                    findings.append(f)
                    log.vuln(f"[HEADER] {header_name}: {payload[:60]}")

        return findings

    # ── JSON Body ─────────────────────────────────────────────────────────────

    def test_json_param(self, url: str, param: str,
                        base_json: dict, log) -> List[Finding]:
        """Inject into JSON API endpoints."""
        findings = []
        json_payloads = [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]
        for payload in json_payloads:
            token = PayloadDB.make_token()
            tagged = PayloadDB.tokenize(payload, token)
            data   = dict(base_json)
            data[param] = tagged

            resp = self.client.post(
                url, json_data=data,
                extra_headers={"Content-Type": "application/json"})
            if not resp:
                continue

            vuln, context, evidence = Analyser.analyse(payload, token, resp)
            if vuln:
                f = Finding(
                    vuln_type       = "Reflected XSS (JSON API)",
                    severity        = "High",
                    confidence      = "Likely",
                    location        = "JSON Body Parameter",
                    page_url        = url,
                    injection_url   = url,
                    parameter       = param,
                    method          = "POST",
                    payload         = payload,
                    context         = context,
                    evidence        = evidence,
                    request_raw     = self._fmt_req("POST", url,
                                                    {param: tagged}),
                    response_snippet= (resp.text if resp else "")[:600],
                    status_code     = resp.status_code if resp else 0,
                )
                findings.append(f)
                log.vuln(f"[JSON] {param}: {payload[:60]}")

        return findings

    # ── Utility ───────────────────────────────────────────────────────────────

    def _fmt_req(self, method: str, url: str,
                 data: dict, headers: dict = None) -> str:
        parsed = urllib.parse.urlparse(url)
        path   = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        lines  = [f"{method} {path} HTTP/1.1",
                  f"Host: {parsed.netloc}",
                  "User-Agent: Mozilla/5.0 (XSS-Scanner)"]
        if headers:
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
        if method == "POST" and data:
            body = urllib.parse.urlencode(data)
            lines += ["Content-Type: application/x-www-form-urlencoded",
                      f"Content-Length: {len(body)}", "", body]
        else:
            lines.append("")
        return "\n".join(lines)

    def deduplicate(self) -> None:
        seen, unique = set(), []
        for f in self.findings:
            key = (f.injection_url, f.parameter, f.payload[:30])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique
