"""
Web Technology Fingerprinter
Detects CMS, frameworks, languages, servers from headers, cookies, HTML.
"""

import re
from typing import List
import requests


# Each entry: (display_name, [regex_patterns_to_match])
SIGNATURES = [
    # CMS
    ("WordPress",     [r"wp-content", r"wp-includes", r"WordPress", r"/wp-json/"]),
    ("Drupal",        [r"Drupal", r"drupal\.js", r"/sites/default/files/", r"X-Generator: Drupal"]),
    ("Joomla",        [r"Joomla!", r"/components/com_", r"joomla", r"/media/system/js/"]),
    ("Magento",       [r"Magento", r"MAGE_", r"Mage\.Cookies"]),
    ("Shopify",       [r"shopify", r"Shopify\.theme", r"myshopify\.com"]),
    ("WooCommerce",   [r"woocommerce", r"wc-cart"]),
    ("Ghost",         [r"ghost", r"content/themes/casper"]),
    # JS Frameworks
    ("Angular",       [r"ng-version", r"angular\.js", r"ng-app", r"\bangular\b", r"_ng_"]),
    ("React",         [r"react\.js", r"react-dom", r"__REACT_", r"data-reactroot", r"__reactFiber"]),
    ("Vue.js",        [r"vue\.js", r"__vue__", r"v-bind", r"v-model", r"nuxt"]),
    ("Next.js",       [r"__NEXT_DATA__", r"/_next/static", r"next/dist"]),
    ("Nuxt.js",       [r"__nuxt", r"/_nuxt/"]),
    ("Ember.js",      [r"ember\.js", r"Ember\.", r"__EMBER"]),
    ("Backbone.js",   [r"backbone\.js", r"Backbone\."]),
    ("jQuery",        [r"jquery[\.\-][\d]", r"jQuery\.fn\.jquery"]),
    # Backend Languages / Frameworks
    ("PHP",           [r"\.php", r"X-Powered-By: PHP", r"PHPSESSID", r"php_errors"]),
    ("ASP.NET",       [r"\.aspx?", r"ASP\.NET", r"__VIEWSTATE", r"X-AspNet-Version", r"__RequestVerificationToken"]),
    ("Java/JSP",      [r"\.jsp", r"JSESSIONID", r"javax\.faces", r"\.do\b"]),
    ("Django",        [r"csrfmiddlewaretoken", r"django", r"__django"]),
    ("Laravel",       [r"laravel_session", r"XSRF-TOKEN", r"Laravel"]),
    ("Ruby on Rails", [r"_rails", r"X-Runtime", r"_session_id", r"rails"]),
    ("Express",       [r"X-Powered-By: Express", r"connect\.sid"]),
    ("Flask",         [r"Werkzeug", r"Flask", r"__flask"]),
    ("Spring",        [r"JSESSIONID", r"X-Application-Context", r"org\.springframework"]),
    ("FastAPI",       [r"fastapi", r"uvicorn"]),
    ("Struts",        [r"struts", r"\.action\b"]),
    # Servers / CDN
    ("Nginx",         [r"Server: nginx"]),
    ("Apache",        [r"Server: Apache"]),
    ("IIS",           [r"Server: Microsoft-IIS", r"X-Powered-By: ASP\.NET"]),
    ("LiteSpeed",     [r"Server: LiteSpeed"]),
    ("Cloudflare",    [r"cf-ray", r"cloudflare", r"__cfduid"]),
    ("AWS CloudFront",[r"X-Cache: Hit from cloudfront", r"x-amz-cf"]),
    ("Varnish",       [r"X-Varnish", r"Via: varnish"]),
    # Template Engines (injectable!)
    ("Twig",          [r"twig", r"{% block", r"{{ "]),
    ("Smarty",        [r"{if\s", r"{foreach\s", r"Smarty"]),
    ("Thymeleaf",     [r"th:text", r"th:href", r"thymeleaf"]),
    ("Handlebars",    [r"handlebars", r"{{#if ", r"{{#each "]),
]


class TechFingerprinter:

    @classmethod
    def detect(cls, response: requests.Response) -> List[str]:
        """Return list of detected technology names."""
        # Combine all response data into one searchable blob
        headers_str = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        cookies_str = "\n".join(f"{k}={v}" for k, v in response.cookies.items())
        body_str    = response.text[:80_000]

        corpus = "\n".join([headers_str, cookies_str, body_str])

        detected = []
        for name, patterns in SIGNATURES:
            for pat in patterns:
                if re.search(pat, corpus, re.IGNORECASE):
                    detected.append(name)
                    break

        return detected

    @classmethod
    def detect_waf(cls, response: requests.Response) -> str | None:
        """Try to identify WAF/security headers."""
        waf_sigs = {
            "Cloudflare":     [r"cf-ray", r"cloudflare"],
            "AWS WAF":        [r"x-amzn-requestid", r"awselb"],
            "Akamai":         [r"akamai", r"X-Check-Cacheable"],
            "Sucuri":         [r"x-sucuri-id", r"sucuri"],
            "Barracuda":      [r"barra", r"bnmobileweb"],
            "ModSecurity":    [r"mod_security", r"NOYB"],
            "F5 BIG-IP":      [r"BigIP", r"BIGipServer"],
            "Imperva/Incapsula": [r"incap_ses", r"visid_incap", r"X-Iinfo"],
        }
        corpus = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        corpus += "\n" + str(dict(response.cookies))

        for waf, patterns in waf_sigs.items():
            for pat in patterns:
                if re.search(pat, corpus, re.IGNORECASE):
                    return waf
        return None
