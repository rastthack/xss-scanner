"""
Web Crawler — discovers pages, forms, URL parameters, and injection points.
"""

import re
import urllib.parse
from typing import List, Dict, Any
from bs4 import BeautifulSoup

from .client import HTTPClient


FormTarget = Dict[str, Any]   # action, method, fields, page_url
URLTarget  = Dict[str, Any]   # url, param, original_value


class Crawler:

    def __init__(self, client: HTTPClient, base_url: str,
                 max_pages: int = 100, same_origin: bool = True):
        self.client      = client
        self.base_url    = base_url.rstrip("/")
        self.base_parsed = urllib.parse.urlparse(base_url)
        self.base_host   = self.base_parsed.netloc
        self.max_pages   = max_pages
        self.same_origin = same_origin

        self.visited:    set        = set()
        self.queue:      List[str]  = [base_url]
        self.forms:      List[FormTarget] = []
        self.url_params: List[URLTarget]  = []

    # ── Public ────────────────────────────────────────────────────────────────

    def crawl(self, log) -> None:
        """BFS crawl — populate self.forms and self.url_params."""
        page_no = 0

        while self.queue and page_no < self.max_pages:
            url = self.queue.pop(0)

            # Normalise (strip fragment)
            url = url.split("#")[0]
            if url in self.visited:
                continue
            self.visited.add(url)
            page_no += 1

            log.progress(f"  Crawl [{page_no}/{self.max_pages}] {url[:90]}")

            resp = self.client.get(url)
            if not resp or resp.status_code not in range(200, 400):
                continue

            # Skip binary content
            ct = resp.headers.get("Content-Type", "")
            if not any(t in ct for t in ("html", "xml", "text")):
                continue

            soup = BeautifulSoup(resp.text, "lxml")

            self._extract_links(url, soup)
            self._extract_forms(url, soup)
            self._extract_url_params(url)

        print()  # end progress line

    def add_url(self, url: str):
        """Manually add a URL to crawl (e.g. specific endpoint from user)."""
        if url not in self.visited:
            self.queue.insert(0, url)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _normalise_url(self, base: str, href: str) -> str | None:
        """Resolve href relative to base; return None if off-scope."""
        try:
            abs_url = urllib.parse.urljoin(base, href.strip())
            parsed  = urllib.parse.urlparse(abs_url)
            # Only http/https
            if parsed.scheme not in ("http", "https"):
                return None
            if self.same_origin and parsed.netloc != self.base_host:
                return None
            # Strip fragment
            return parsed._replace(fragment="").geturl()
        except Exception:
            return None

    def _extract_links(self, base_url: str, soup: BeautifulSoup):
        found = set()
        for tag in soup.find_all(True):
            for attr in ("href", "src", "action", "data-url", "data-href"):
                val = tag.get(attr, "")
                if val:
                    url = self._normalise_url(base_url, val)
                    if url:
                        found.add(url)

        for url in found:
            if url not in self.visited and url not in self.queue:
                self.queue.append(url)

    def _extract_forms(self, page_url: str, soup: BeautifulSoup):
        for form in soup.find_all("form"):
            raw_action = form.get("action", page_url) or page_url
            action     = urllib.parse.urljoin(page_url, raw_action)
            method     = form.get("method", "GET").upper()
            if method not in ("GET", "POST"):
                method = "POST"

            fields: Dict[str, str] = {}

            for el in form.find_all(["input", "textarea", "select"]):
                name  = el.get("name", "").strip()
                if not name:
                    continue
                itype = el.get("type", "text").lower()
                value = el.get("value", "") or ""

                if itype in ("submit", "button", "reset", "image"):
                    continue
                if itype == "hidden":
                    fields[name] = value   # keep CSRF tokens etc.
                elif itype == "checkbox":
                    fields[name] = el.get("value", "on")
                elif itype == "radio":
                    if name not in fields:
                        fields[name] = el.get("value", "on")
                else:
                    # injectable text/email/search/etc.
                    fields[name] = value or "test"

            if not any(
                t not in ("hidden",)
                for t in [form.find("input", {"type": t}) is not None
                          for t in ("text", "email", "search", "password",
                                    "url", "number", "tel", None)]
            ):
                # form has no visible injectable fields — skip? No, still test
                pass

            if fields:
                target: FormTarget = {
                    "page_url": page_url,
                    "action":   action,
                    "method":   method,
                    "fields":   fields,
                    "raw_html": str(form)[:500],
                }
                self.forms.append(target)

                # Also queue the action URL
                url = self._normalise_url(page_url, raw_action)
                if url and url not in self.visited:
                    self.queue.append(url)

    def _extract_url_params(self, url: str):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for name, values in params.items():
            self.url_params.append({
                "url":      url,
                "param":    name,
                "original": values[0] if values else "",
            })

    # ── Summary ───────────────────────────────────────────────────────────────

    def summary(self) -> str:
        return (f"Pages: {len(self.visited)}  |  "
                f"Forms: {len(self.forms)}  |  "
                f"URL params: {len(self.url_params)}")
