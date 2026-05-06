"""
HTTP Client — persistent session with retry, proxy, and cookie support.
Mimics Burp Suite Repeater behaviour: sends request, captures full response.
"""

import time
import urllib.parse
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

requests.packages.urllib3.disable_warnings()


class RequestRecord:
    """Stores a complete request/response pair for reporting."""

    def __init__(self, method: str, url: str,
                 headers: dict, body: str,
                 status_code: int, resp_headers: dict,
                 resp_body: str, elapsed: float):
        self.method       = method
        self.url          = url
        self.headers      = headers
        self.body         = body
        self.status_code  = status_code
        self.resp_headers = resp_headers
        self.resp_body    = resp_body
        self.elapsed      = elapsed

    def format_request(self) -> str:
        parsed = urllib.parse.urlparse(self.url)
        path   = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        lines  = [f"{self.method} {path} HTTP/1.1",
                  f"Host: {parsed.netloc}"]
        for k, v in self.headers.items():
            if k.lower() not in ("host",):
                lines.append(f"{k}: {v}")
        if self.body:
            lines.append(f"Content-Length: {len(self.body.encode())}")
            lines.append("")
            lines.append(self.body)
        else:
            lines.append("")
        return "\n".join(lines)

    def format_response(self) -> str:
        lines = [f"HTTP/1.1 {self.status_code}"]
        for k, v in self.resp_headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(self.resp_body[:2000])
        return "\n".join(lines)


class HTTPClient:
    USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/124.0.0.0 Safari/537.36")

    BASE_HEADERS = {
        "User-Agent":      USER_AGENT,
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection":      "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    def __init__(self, proxy: str = None, timeout: int = 15,
                 delay: float = 0.3, max_retries: int = 3):
        self.timeout  = timeout
        self.delay    = delay
        self.sent     = 0
        self.received = 0
        self.history: list[RequestRecord] = []

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(self.BASE_HEADERS)

        retry = Retry(total=max_retries, backoff_factor=0.4,
                      status_forcelist=[500, 502, 503, 504],
                      allowed_methods=["GET", "POST", "HEAD"])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://",  adapter)
        self.session.mount("https://", adapter)

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    # ── Public helpers ────────────────────────────────────────────────────────

    def set_header(self, key: str, value: str):
        self.session.headers[key] = value

    def set_cookie(self, name: str, value: str, domain: str = None):
        self.session.cookies.set(name, value, domain=domain)

    def set_cookies_from_string(self, cookie_str: str):
        """Accept 'name=val; name2=val2' format."""
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                self.session.cookies.set(k.strip(), v.strip())

    # ── Core request methods ──────────────────────────────────────────────────

    def get(self, url: str, params: dict = None,
            extra_headers: dict = None) -> Optional[requests.Response]:
        return self._send("GET", url, params=params,
                          extra_headers=extra_headers)

    def post(self, url: str, data: dict = None, json_data: dict = None,
             extra_headers: dict = None) -> Optional[requests.Response]:
        return self._send("POST", url, data=data, json_data=json_data,
                          extra_headers=extra_headers)

    def _send(self, method: str, url: str,
              params: dict = None, data: dict = None,
              json_data: dict = None,
              extra_headers: dict = None) -> Optional[requests.Response]:
        time.sleep(self.delay)
        self.sent += 1

        merged_headers = dict(self.session.headers)
        if extra_headers:
            merged_headers.update(extra_headers)

        try:
            kwargs = dict(
                timeout        = self.timeout,
                allow_redirects= True,
                headers        = extra_headers or {},
            )
            if params:
                kwargs["params"] = params
            if data:
                kwargs["data"] = data
            if json_data:
                kwargs["json"] = json_data

            resp = self.session.request(method, url, **kwargs)
            self.received += 1

            # Build body string for record
            req_body = ""
            if data:
                import urllib.parse as up
                req_body = up.urlencode(data)

            rec = RequestRecord(
                method       = method,
                url          = resp.url,
                headers      = dict(merged_headers),
                body         = req_body,
                status_code  = resp.status_code,
                resp_headers = dict(resp.headers),
                resp_body    = resp.text,
                elapsed      = resp.elapsed.total_seconds(),
            )
            self.history.append(rec)
            return resp

        except requests.exceptions.SSLError:
            # Retry without SSL verify
            try:
                resp = self.session.request(method, url,
                                            verify=False, timeout=self.timeout,
                                            allow_redirects=True)
                self.received += 1
                return resp
            except Exception:
                return None
        except Exception:
            return None
