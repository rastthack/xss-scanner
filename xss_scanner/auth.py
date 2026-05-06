"""
Authentication Handler
Auto-detects and submits login forms. Falls back to manual URL entry.
"""

import re
import getpass
import urllib.parse
from bs4 import BeautifulSoup

from .client import HTTPClient


COMMON_LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/log-in", "/auth", "/authenticate",
    "/account/login", "/user/login", "/users/sign_in",
    "/admin/login", "/admin", "/wp-login.php",
    "/accounts/login", "/session/new", "/portal/login",
    "/member/login", "/members/login", "/customer/account/login",
]

SUCCESS_KEYWORDS = [
    "logout", "log out", "sign out", "signout", "dashboard",
    "welcome", "my account", "profile", "settings", "admin panel",
]
FAILURE_KEYWORDS = [
    "invalid", "incorrect", "wrong password", "failed", "error",
    "try again", "does not match", "not found", "unauthorized",
]


class AuthHandler:

    def __init__(self, client: HTTPClient, base_url: str):
        self.client   = client
        self.base_url = base_url.rstrip("/")

    def login(self, username: str, password: str, log) -> bool:
        """
        1. Find login page
        2. Parse login form
        3. Submit credentials
        4. Return True if session looks authenticated
        """
        log.info("Searching for login page…")
        login_url = self._find_login_page(log)
        if not login_url:
            login_url = input(
                "\033[33m  [?] Could not auto-detect login page.\n"
                "      Enter login URL manually: \033[0m"
            ).strip()
            if not login_url.startswith("http"):
                login_url = self.base_url + "/" + login_url.lstrip("/")

        log.info(f"Login page: {login_url}")

        resp = self.client.get(login_url)
        if not resp:
            log.error("Cannot reach login page.")
            return False

        soup = BeautifulSoup(resp.text, "lxml")
        form = self._find_login_form(soup)
        if not form:
            log.warn("No password form found — trying to post credentials directly.")
            return self._brute_post(login_url, username, password, log)

        action = urllib.parse.urljoin(login_url,
                                      form.get("action") or login_url)
        method = form.get("method", "POST").upper()

        data = self._build_form_data(form, username, password)
        log.info(f"Submitting → {method} {action}")
        log.debug(f"POST fields: {list(data.keys())}")

        if method == "POST":
            post_resp = self.client.post(action, data=data)
        else:
            post_resp = self.client.get(action, params=data)

        if not post_resp:
            log.error("Login request timed out.")
            return False

        return self._check_login_success(post_resp, log)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_login_page(self, log) -> str | None:
        # First check if base URL itself has a login form
        resp = self.client.get(self.base_url)
        if resp and self._has_password_field(resp.text):
            return self.base_url

        for path in COMMON_LOGIN_PATHS:
            url  = self.base_url + path
            resp = self.client.get(url)
            if resp and resp.status_code == 200 and self._has_password_field(resp.text):
                log.success(f"Login form found at: {url}")
                return url

        return None

    def _has_password_field(self, html: str) -> bool:
        return bool(re.search(r'type=["\']?password', html, re.I))

    def _find_login_form(self, soup: BeautifulSoup):
        for form in soup.find_all("form"):
            if form.find("input", {"type": re.compile(r"password", re.I)}):
                return form
        return None

    def _build_form_data(self, form, username: str, password: str) -> dict:
        data = {}
        for inp in form.find_all(["input", "select", "textarea"]):
            name  = inp.get("name", "").strip()
            itype = inp.get("type", "text").lower()
            value = inp.get("value", "") or ""

            if not name or itype in ("submit", "button", "reset"):
                continue

            # Guess which field is username and which is password
            if itype == "password" or re.search(r"pass|pwd|secret", name, re.I):
                data[name] = password
            elif (itype in ("text", "email")
                  or re.search(r"user|email|login|name|mail|id", name, re.I)):
                data[name] = username
            else:
                data[name] = value  # keep hidden fields / tokens as-is

        return data

    def _brute_post(self, url: str, username: str, password: str, log) -> bool:
        """Fallback: try common field names when no form found."""
        combos = [
            {"username": username, "password": password},
            {"email":    username, "password": password},
            {"login":    username, "password": password},
            {"user":     username, "pass":     password},
        ]
        for data in combos:
            resp = self.client.post(url, data=data)
            if resp and self._check_login_success(resp, log):
                return True
        return False

    def _check_login_success(self, resp, log) -> bool:
        body = resp.text.lower()

        if any(kw in body for kw in SUCCESS_KEYWORDS):
            log.success("Login successful! (authenticated session active)")
            return True
        if any(kw in body for kw in FAILURE_KEYWORDS):
            log.error("Login failed — check your credentials.")
            return False

        # Heuristic: redirect to non-login page = likely success
        final_path = urllib.parse.urlparse(resp.url).path
        if not any(p in final_path for p in ("/login", "/signin", "/auth")):
            log.success("Login likely succeeded (redirected away from login page).")
            return True

        log.warn("Login result ambiguous — continuing with current session.")
        return True  # optimistic
