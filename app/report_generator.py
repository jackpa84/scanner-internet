"""
High-quality report generator for HackerOne submissions.

Better reports = higher payouts + bonuses + faster triage.

Features:
  - 25+ per-vulnerability-type report templates
  - CVSS 3.1 score calculator
  - Business impact analysis with regulatory context (GDPR, LGPD, PCI-DSS)
  - Detailed Steps to Reproduce with cURL commands
  - Proof of Concept formatting
  - Remediation recommendations
  - De-duplication logic
  - Enhanced confidence scoring
"""

import logging
import re
from datetime import datetime
from typing import Any
logger = logging.getLogger("scanner.report_gen")

CVSS_BASE_SCORES = {
    "critical": 9.8,
    "high": 8.5,
    "medium": 5.5,
    "low": 3.1,
    "info": 0.0,
}

VULN_TEMPLATES: dict[str, dict[str, Any]] = {
    # ── Subdomain / DNS ──────────────────────────────────────────────
    "subdomain_takeover": {
        "title": "Subdomain Takeover on {domain}",
        "weakness": "CWE-284: Improper Access Control",
        "impact_template": (
            "An attacker can claim the dangling subdomain `{domain}` and serve arbitrary content, "
            "including credential harvesting pages, malware, or content that damages the organization's reputation. "
            "Since the subdomain belongs to the target's domain, any cookies scoped to the parent domain "
            "can be stolen, potentially leading to session hijacking.\n\n"
            "**Regulatory impact:** If the subdomain previously served user-facing functionality, "
            "an attacker could harvest PII, constituting a GDPR Art. 32 / LGPD Art. 46 violation."
        ),
        "remediation": (
            "1. Remove the dangling DNS record (CNAME/A) pointing to the deprovisioned service.\n"
            "2. If the service is still needed, reclaim it on the hosting platform.\n"
            "3. Implement monitoring for dangling DNS records.\n"
            "4. Consider using a subdomain monitoring service (e.g. `can-i-take-over-xyz`)."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
    },
    "dns_zone_transfer": {
        "title": "DNS Zone Transfer Enabled on {domain}",
        "weakness": "CWE-200: Exposure of Sensitive Information",
        "impact_template": (
            "DNS zone transfer (AXFR) is enabled for `{domain}`, allowing anyone to dump "
            "the entire DNS zone. This reveals all subdomains, internal hosts, mail servers, "
            "and network infrastructure details. An attacker can use this information to map "
            "the full attack surface and identify high-value internal targets."
        ),
        "remediation": (
            "1. Restrict zone transfers to authorized secondary DNS servers only.\n"
            "2. Configure ACLs on the DNS server to deny AXFR from unauthorized IPs.\n"
            "3. Use TSIG (Transaction Signatures) for zone transfer authentication.\n"
            "4. Audit DNS configuration periodically with `dig axfr @ns.target.com target.com`."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },

    # ── CORS ─────────────────────────────────────────────────────────
    "cors_reflected_origin": {
        "title": "CORS Misconfiguration with Reflected Origin on {domain}",
        "weakness": "CWE-942: Permissive Cross-domain Policy",
        "impact_template": (
            "The server at `{domain}` reflects arbitrary Origin headers in the Access-Control-Allow-Origin response header. "
            "Combined with Access-Control-Allow-Credentials: true, this allows an attacker to read authenticated "
            "responses cross-origin, potentially stealing sensitive user data, tokens, or PII.\n\n"
            "**Attack scenario:** An attacker hosts a malicious page that makes fetch requests to "
            "`{domain}` with `credentials: 'include'`. The browser sends the victim's cookies, and the "
            "attacker-controlled Origin is reflected, allowing the response to be read."
        ),
        "remediation": (
            "1. Implement a whitelist of allowed origins.\n"
            "2. Never reflect arbitrary origins when credentials are allowed.\n"
            "3. Use a CORS library with strict origin validation.\n"
            "4. Validate against the full origin string, not just substrings."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    },
    "cors_credentials_wildcard": {
        "title": "CORS Wildcard with Credentials on {domain}",
        "weakness": "CWE-942: Permissive Cross-domain Policy",
        "impact_template": (
            "The server responds with Access-Control-Allow-Origin: * alongside "
            "Access-Control-Allow-Credentials: true. While browsers block this combination, "
            "it indicates a misconfigured CORS policy that may be exploitable in certain contexts "
            "or via non-browser HTTP clients."
        ),
        "remediation": (
            "1. Remove the wildcard origin when credentials are required.\n"
            "2. Implement specific origin whitelisting.\n"
            "3. Return the requesting origin only if it is in the allow-list."
        ),
        "severity": "medium",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    },

    # ── Redirect / Injection ─────────────────────────────────────────
    "open_redirect": {
        "title": "Open Redirect on {domain}",
        "weakness": "CWE-601: URL Redirection to Untrusted Site",
        "impact_template": (
            "The application at `{domain}` redirects users to attacker-controlled URLs without validation. "
            "This can be chained with OAuth flows for token theft, used in phishing campaigns that "
            "appear to originate from a trusted domain, or combined with SSRF for internal access.\n\n"
            "**Chain potential:** Open redirects on authentication endpoints can be chained to steal "
            "OAuth authorization codes or tokens (see OAuth 2.0 redirect_uri manipulation)."
        ),
        "remediation": (
            "1. Validate redirect URLs against a whitelist of allowed destinations.\n"
            "2. Use relative URLs for internal redirects.\n"
            "3. Display an interstitial warning page for external redirects.\n"
            "4. Strip or block `//`, `\\`, and encoded variants in redirect parameters."
        ),
        "severity": "medium",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "crlf_injection": {
        "title": "CRLF Injection (HTTP Response Splitting) on {domain}",
        "weakness": "CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers",
        "impact_template": (
            "The application at `{domain}` is vulnerable to CRLF injection, allowing an attacker to "
            "inject arbitrary HTTP headers or split the HTTP response. This can be used to set malicious "
            "cookies, perform XSS via injected headers, poison web caches, or bypass security controls.\n\n"
            "**Impact:** An attacker can inject `Set-Cookie` headers to fixate sessions, "
            "or inject a `Content-Type: text/html` header followed by a malicious body for stored XSS."
        ),
        "remediation": (
            "1. Strip or encode CR (\\r, %0d) and LF (\\n, %0a) characters from all user input used in HTTP headers.\n"
            "2. Use framework-provided header-setting functions that auto-escape.\n"
            "3. Implement a WAF rule to block CRLF sequences in request parameters."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "host_header_injection": {
        "title": "Host Header Injection on {domain}",
        "weakness": "CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax",
        "impact_template": (
            "The application at `{domain}` trusts the Host header for generating URLs (e.g. password reset links, "
            "email verification links). An attacker can inject a malicious Host header to redirect "
            "sensitive tokens to an attacker-controlled server.\n\n"
            "**Attack scenario:** Attacker triggers a password reset for the victim, intercepting the request "
            "and replacing the Host header with `evil.com`. The reset link sent to the victim's email "
            "points to `evil.com`, leaking the reset token."
        ),
        "remediation": (
            "1. Use a server-side configuration for the canonical hostname instead of trusting the Host header.\n"
            "2. Validate the Host header against a whitelist of expected values.\n"
            "3. Use the `X-Forwarded-Host` header only from trusted proxies."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },

    # ── XSS ──────────────────────────────────────────────────────────
    "xss_reflected": {
        "title": "Reflected Cross-Site Scripting (XSS) on {domain}",
        "weakness": "CWE-79: Improper Neutralization of Input During Web Page Generation",
        "impact_template": (
            "A reflected XSS vulnerability was identified on `{domain}`. An attacker can craft a URL containing "
            "malicious JavaScript that executes in the context of the victim's browser session when clicked.\n\n"
            "**Impact:** Session hijacking via cookie theft, keylogging, phishing overlays, "
            "and actions on behalf of the victim. If the victim is an admin, this can lead to full "
            "account takeover and administrative access.\n\n"
            "**Regulatory impact:** Exploitation could lead to unauthorized access to PII, "
            "violating GDPR Art. 5(1)(f) and LGPD Art. 46 (security of processing)."
        ),
        "remediation": (
            "1. Implement context-aware output encoding (HTML, JS, URL, CSS contexts).\n"
            "2. Use Content-Security-Policy headers to mitigate execution of inline scripts.\n"
            "3. Enable the `HttpOnly` and `Secure` flags on session cookies.\n"
            "4. Use a modern framework with automatic escaping (React, Angular, Vue)."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "xss_stored": {
        "title": "Stored Cross-Site Scripting (XSS) on {domain}",
        "weakness": "CWE-79: Improper Neutralization of Input During Web Page Generation",
        "impact_template": (
            "A stored XSS vulnerability was identified on `{domain}`. Malicious JavaScript is persisted "
            "server-side and executes in the browser of every user who views the affected page.\n\n"
            "**Impact:** Unlike reflected XSS, stored XSS does not require victim interaction beyond "
            "visiting the page. This enables mass session hijacking, worm propagation, "
            "cryptocurrency mining, and persistent backdoors in the application.\n\n"
            "**Regulatory impact:** A stored XSS worm could exfiltrate PII at scale, "
            "constituting a notifiable data breach under GDPR Art. 33 and LGPD Art. 48."
        ),
        "remediation": (
            "1. Sanitize all user input on storage (server-side) using a library like DOMPurify or Bleach.\n"
            "2. Implement context-aware output encoding on display.\n"
            "3. Deploy a strict Content-Security-Policy that blocks inline scripts.\n"
            "4. Implement input length limits and character whitelists where possible."
        ),
        "severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
    },
    "xss_dom": {
        "title": "DOM-Based Cross-Site Scripting (XSS) on {domain}",
        "weakness": "CWE-79: Improper Neutralization of Input During Web Page Generation",
        "impact_template": (
            "A DOM-based XSS vulnerability was identified on `{domain}`. The client-side JavaScript "
            "reads from an attacker-controllable source (e.g., `location.hash`, `document.referrer`) "
            "and passes it to a dangerous sink (e.g., `innerHTML`, `eval`, `document.write`) without sanitization.\n\n"
            "**Impact:** Session hijacking, credential theft, and phishing attacks. DOM XSS is often "
            "harder to detect by WAFs since the payload never reaches the server."
        ),
        "remediation": (
            "1. Avoid using dangerous sinks (`innerHTML`, `eval`, `document.write`); prefer `textContent`.\n"
            "2. Sanitize all DOM-sourced data before rendering.\n"
            "3. Use Trusted Types API to enforce sink-level policies.\n"
            "4. Audit JavaScript with tools like `semgrep` or `ESLint security plugins`."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },

    # ── Injection ────────────────────────────────────────────────────
    "sql_injection": {
        "title": "SQL Injection on {domain}",
        "weakness": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        "impact_template": (
            "An SQL injection vulnerability was identified on `{domain}`. An attacker can manipulate "
            "SQL queries to extract, modify, or delete data from the database, bypass authentication, "
            "or in some cases execute operating system commands via `xp_cmdshell` or `LOAD_FILE()`.\n\n"
            "**Impact:** Full database compromise including user credentials, PII, payment data, "
            "and business-critical records. In worst-case scenarios, this leads to remote code execution.\n\n"
            "**Regulatory impact:** Database exfiltration constitutes a data breach under GDPR Art. 4(12), "
            "LGPD Art. 44, and PCI-DSS Requirement 6.5.1. Mandatory notification within 72 hours."
        ),
        "remediation": (
            "1. Use parameterized queries / prepared statements for all database interactions.\n"
            "2. Implement input validation with strict whitelists (reject unexpected characters).\n"
            "3. Apply the principle of least privilege to database accounts.\n"
            "4. Deploy a WAF with SQL injection rule sets.\n"
            "5. Use an ORM that auto-parameterizes queries."
        ),
        "severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },
    "sql_injection_blind": {
        "title": "Blind SQL Injection on {domain}",
        "weakness": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        "impact_template": (
            "A blind SQL injection vulnerability was identified on `{domain}`. Although the application "
            "does not display query results directly, an attacker can infer data through boolean-based "
            "or time-based techniques, extracting the entire database character by character.\n\n"
            "**Impact:** Same as standard SQL injection — full database compromise — but slower to exploit. "
            "Automated tools like `sqlmap` can fully dump the database in minutes to hours."
        ),
        "remediation": (
            "1. Use parameterized queries / prepared statements exclusively.\n"
            "2. Implement input validation with strict type checking.\n"
            "3. Normalize error responses to avoid boolean-based inference.\n"
            "4. Set query execution timeouts to limit time-based techniques."
        ),
        "severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    },
    "ssti": {
        "title": "Server-Side Template Injection (SSTI) on {domain}",
        "weakness": "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine",
        "impact_template": (
            "A Server-Side Template Injection vulnerability was identified on `{domain}`. "
            "User input is embedded directly into a server-side template engine without sanitization, "
            "allowing an attacker to inject template directives that execute arbitrary code on the server.\n\n"
            "**Impact:** Remote Code Execution (RCE) with the privileges of the web application. "
            "An attacker can read files, access environment variables (database credentials, API keys), "
            "pivot to internal services, or establish a reverse shell."
        ),
        "remediation": (
            "1. Never pass user input directly into template rendering functions.\n"
            "2. Use a logic-less template engine (Mustache, Handlebars) where possible.\n"
            "3. If user input must appear in templates, use strict sandboxing (Jinja2 SandboxedEnvironment).\n"
            "4. Implement input validation that rejects template syntax characters ({{ }}, <% %>, etc.)."
        ),
        "severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },
    "xxe": {
        "title": "XML External Entity (XXE) Injection on {domain}",
        "weakness": "CWE-611: Improper Restriction of XML External Entity Reference",
        "impact_template": (
            "An XXE vulnerability was identified on `{domain}`. The XML parser processes external entity "
            "declarations, allowing an attacker to read local files (e.g., `/etc/passwd`, application configs), "
            "perform SSRF to internal services, or cause denial of service via recursive entity expansion.\n\n"
            "**Impact:** File disclosure, SSRF, and in some cases remote code execution via PHP `expect://` wrapper. "
            "Credentials and secrets stored in configuration files are at risk."
        ),
        "remediation": (
            "1. Disable external entity processing and DTD loading in the XML parser.\n"
            "2. Use JSON instead of XML where possible.\n"
            "3. If XML is required, use defused libraries (e.g., `defusedxml` for Python).\n"
            "4. Implement input validation that rejects DOCTYPE declarations."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:L",
    },

    # ── Path Traversal / File Disclosure ─────────────────────────────
    "path_traversal": {
        "title": "Path Traversal / Local File Inclusion on {domain}",
        "weakness": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
        "impact_template": (
            "A path traversal vulnerability was identified on `{domain}`. An attacker can use sequences "
            "like `../` to escape the intended directory and read arbitrary files from the server, "
            "including `/etc/passwd`, application source code, configuration files, and secrets.\n\n"
            "**Impact:** Disclosure of sensitive files including database credentials, API keys, "
            "and application source code. Combined with file upload, this can escalate to Remote Code Execution."
        ),
        "remediation": (
            "1. Canonicalize file paths and validate against a whitelist of allowed directories.\n"
            "2. Use `os.path.realpath()` or equivalent to resolve symlinks before access checks.\n"
            "3. Run the application with minimal filesystem permissions.\n"
            "4. Block `../`, `..\\`, and URL-encoded variants (`%2e%2e%2f`) in file parameters."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "git_head_exposed": {
        "title": "Exposed .git Repository on {domain}",
        "weakness": "CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory",
        "impact_template": (
            "The `.git` directory is publicly accessible on `{domain}`, allowing an attacker to "
            "reconstruct the entire source code repository using tools like `git-dumper`. "
            "This may reveal hardcoded credentials, API keys, internal URLs, database connection strings, "
            "and business logic.\n\n"
            "**Impact:** Full source code disclosure enables an attacker to identify further vulnerabilities "
            "with white-box analysis, find secrets in commit history, and understand internal architecture."
        ),
        "remediation": (
            "1. Block access to `.git` directory in the web server configuration (nginx: `location ~ /\\.git { deny all; }`).\n"
            "2. Remove `.git` from deployed environments.\n"
            "3. Rotate ALL credentials found in the repository history.\n"
            "4. Use `.gitignore` and `git-secrets` to prevent accidental credential commits."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "env_file_exposed": {
        "title": "Exposed .env File on {domain}",
        "weakness": "CWE-200: Exposure of Sensitive Information",
        "impact_template": (
            "The `.env` file is publicly accessible on `{domain}`, exposing environment variables "
            "that typically contain database credentials, API keys, secret tokens, and other "
            "sensitive configuration. This provides direct access to backend services.\n\n"
            "**Regulatory impact:** Exposed database credentials can lead to unauthorized access to "
            "personal data, constituting a notifiable breach under GDPR Art. 33 (72-hour notification) "
            "and LGPD Art. 48. If payment data is accessible, PCI-DSS Requirement 6.5 is also violated."
        ),
        "remediation": (
            "1. Block access to `.env` files in the web server configuration.\n"
            "2. Move `.env` outside the web root.\n"
            "3. Rotate ALL exposed credentials immediately.\n"
            "4. Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) instead of `.env` files."
        ),
        "severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    },

    # ── Information Disclosure ───────────────────────────────────────
    "info_disclosure_stacktrace": {
        "title": "Sensitive Information Disclosure via Stack Trace on {domain}",
        "weakness": "CWE-209: Generation of Error Message Containing Sensitive Information",
        "impact_template": (
            "The application at `{domain}` exposes detailed stack traces or debug information in error responses. "
            "This reveals internal file paths, library versions, database types, and application architecture.\n\n"
            "**Impact:** While not directly exploitable, this information significantly reduces the effort "
            "required to exploit other vulnerabilities. Framework versions enable targeted CVE exploitation."
        ),
        "remediation": (
            "1. Disable debug mode in production (`DEBUG=False`, `APP_ENV=production`).\n"
            "2. Implement custom error pages that do not reveal internal details.\n"
            "3. Log detailed errors server-side, return generic messages to clients.\n"
            "4. Ensure framework-specific debug endpoints (e.g., Laravel Telescope, Django Debug Toolbar) are disabled."
        ),
        "severity": "medium",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "info_disclosure_version": {
        "title": "Server Version Disclosure on {domain}",
        "weakness": "CWE-200: Exposure of Sensitive Information",
        "impact_template": (
            "The server at `{domain}` discloses version information in HTTP headers or response bodies "
            "(e.g., `Server: Apache/2.4.49`, `X-Powered-By: PHP/7.4.3`). This enables targeted attacks "
            "using known CVEs for specific versions."
        ),
        "remediation": (
            "1. Remove or obfuscate `Server`, `X-Powered-By`, and `X-AspNet-Version` headers.\n"
            "2. In Apache: `ServerTokens Prod` and `ServerSignature Off`.\n"
            "3. In Nginx: `server_tokens off;`.\n"
            "4. In PHP: `expose_php = Off` in php.ini."
        ),
        "severity": "low",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "directory_listing": {
        "title": "Directory Listing Enabled on {domain}",
        "weakness": "CWE-548: Exposure of Information Through Directory Listing",
        "impact_template": (
            "Directory listing is enabled on `{domain}`, allowing browsing of directory contents. "
            "This can expose backup files, configuration files, source code, and other sensitive assets "
            "that were not intended to be publicly accessible."
        ),
        "remediation": (
            "1. Disable directory listing in the web server configuration.\n"
            "2. Apache: `Options -Indexes` in `.htaccess` or `httpd.conf`.\n"
            "3. Nginx: `autoindex off;` in the server block.\n"
            "4. Place an `index.html` in all directories as a fallback."
        ),
        "severity": "low",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },

    # ── Authentication / Authorization ───────────────────────────────
    "idor_id_increment": {
        "title": "IDOR via Sequential ID on {domain}",
        "weakness": "CWE-639: Authorization Bypass Through User-Controlled Key",
        "impact_template": (
            "The API endpoint on `{domain}` uses sequential numeric IDs for object access "
            "without proper authorization checks. By incrementing/decrementing the ID, "
            "an attacker can access other users' data including {sensitive_data}.\n\n"
            "**Impact:** Mass enumeration of user data. With sequential IDs, the total number of records "
            "can be estimated and all records scraped in a single automated session.\n\n"
            "**Regulatory impact:** Unauthorized access to personal data violates GDPR Art. 5(1)(f), "
            "LGPD Art. 46, and depending on data type, PCI-DSS Requirement 7."
        ),
        "remediation": (
            "1. Implement proper authorization checks on every object access.\n"
            "2. Use UUIDs or non-guessable identifiers instead of sequential IDs.\n"
            "3. Implement object-level access control (OLAC) middleware.\n"
            "4. Log and alert on sequential enumeration patterns."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    },
    "broken_auth_jwt": {
        "title": "Broken Authentication via Weak JWT on {domain}",
        "weakness": "CWE-345: Insufficient Verification of Data Authenticity",
        "impact_template": (
            "The JWT implementation on `{domain}` has a security weakness: {evidence}. "
            "This may allow an attacker to forge, tamper, or bypass JWT validation "
            "to impersonate any user, including administrators.\n\n"
            "**Common issues found:** `alg: none` accepted, weak HMAC secret (brute-forceable), "
            "RS256→HS256 algorithm confusion, missing expiration validation, or JWK injection."
        ),
        "remediation": (
            "1. Reject `alg: none` and enforce a specific algorithm (e.g., RS256 only).\n"
            "2. Use a strong, random secret (256+ bits) for HMAC-based algorithms.\n"
            "3. Validate `exp`, `nbf`, `iss`, and `aud` claims on every request.\n"
            "4. Use a well-maintained JWT library and keep it updated."
        ),
        "severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    "session_fixation": {
        "title": "Session Fixation on {domain}",
        "weakness": "CWE-384: Session Fixation",
        "impact_template": (
            "The application at `{domain}` does not regenerate the session identifier after "
            "successful authentication. An attacker can fixate a known session ID on the victim "
            "and wait for them to authenticate, gaining access to their authenticated session."
        ),
        "remediation": (
            "1. Regenerate the session ID after every successful login.\n"
            "2. Invalidate old session tokens on authentication state changes.\n"
            "3. Set `SameSite=Strict` or `SameSite=Lax` on session cookies.\n"
            "4. Use `HttpOnly` and `Secure` flags on all session cookies."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    },

    # ── SSRF ─────────────────────────────────────────────────────────
    "ssrf_aws_metadata": {
        "title": "SSRF to AWS Metadata on {domain}",
        "weakness": "CWE-918: Server-Side Request Forgery",
        "impact_template": (
            "The application on `{domain}` is vulnerable to SSRF, allowing access to the AWS EC2 "
            "metadata service at 169.254.169.254. An attacker can retrieve IAM credentials, "
            "instance metadata, and potentially pivot to other AWS services.\n\n"
            "**Impact:** With stolen IAM credentials, an attacker can access S3 buckets, RDS databases, "
            "Lambda functions, and other AWS resources. This is the same technique used in the "
            "Capital One breach (2019, 100M+ records)."
        ),
        "remediation": (
            "1. Implement URL validation and block internal/metadata IPs (169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12).\n"
            "2. Use IMDSv2 (require session tokens for metadata access).\n"
            "3. Apply network-level restrictions (firewall rules for metadata endpoint).\n"
            "4. Use a dedicated outbound proxy that enforces URL allow-lists."
        ),
        "severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    },
    "ssrf_localhost": {
        "title": "SSRF to Internal Services on {domain}",
        "weakness": "CWE-918: Server-Side Request Forgery",
        "impact_template": (
            "The application on `{domain}` allows server-side requests to internal addresses "
            "(127.0.0.1 / localhost). This exposes internal services, admin panels, and databases "
            "that are not intended to be publicly accessible.\n\n"
            "**Impact:** An attacker can scan internal ports, access admin interfaces, "
            "interact with databases (Redis, Memcached), and potentially achieve RCE."
        ),
        "remediation": (
            "1. Implement strict URL validation with deny-list for internal IPs.\n"
            "2. Use a dedicated proxy/gateway for outbound requests.\n"
            "3. Apply network segmentation to limit internal access.\n"
            "4. Block DNS rebinding attacks by resolving and validating IPs before making requests."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    },

    # ── GraphQL / API ────────────────────────────────────────────────
    "graphql_introspection": {
        "title": "GraphQL Introspection Enabled on {domain}",
        "weakness": "CWE-200: Exposure of Sensitive Information",
        "impact_template": (
            "GraphQL introspection is enabled on `{domain}`, exposing the entire API schema "
            "including all types, queries, and mutations. This reveals internal data structures, "
            "hidden endpoints, and potentially sensitive operations.\n\n"
            "**Impact:** An attacker can discover undocumented mutations for privilege escalation, "
            "identify sensitive data types (SSN, payment info), and craft targeted queries."
        ),
        "remediation": (
            "1. Disable introspection in production environments.\n"
            "2. Implement query depth limiting and complexity analysis.\n"
            "3. Use persistent queries (whitelisted) in production.\n"
            "4. Implement field-level authorization on sensitive types."
        ),
        "severity": "medium",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },

    # ── Race Condition ───────────────────────────────────────────────
    "race_condition": {
        "title": "Race Condition on {domain}",
        "weakness": "CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization",
        "impact_template": (
            "The endpoint on `{domain}` is vulnerable to race conditions. By sending concurrent "
            "requests, an attacker can manipulate application state, potentially resulting in "
            "double-spending, duplicate actions, or privilege escalation.\n\n"
            "**Impact:** Financial loss through double-spending on rewards/coupons/credits, "
            "duplicate account creation, or bypassing rate limits on sensitive operations."
        ),
        "remediation": (
            "1. Implement proper locking mechanisms (database-level or distributed locks).\n"
            "2. Use idempotency keys for state-changing operations.\n"
            "3. Implement optimistic concurrency control with version checks.\n"
            "4. Use `SELECT ... FOR UPDATE` or equivalent for critical transactions."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:N",
    },

    # ── Cloud / S3 ───────────────────────────────────────────────────
    "s3_bucket_public": {
        "title": "Publicly Accessible S3 Bucket on {domain}",
        "weakness": "CWE-284: Improper Access Control",
        "impact_template": (
            "An Amazon S3 bucket associated with `{domain}` is publicly accessible, allowing "
            "unauthenticated users to list and download stored objects. The bucket may contain "
            "user uploads, backups, logs, or internal documents.\n\n"
            "**Impact:** Depending on bucket contents, this can lead to PII exposure, "
            "credential leakage, intellectual property theft, or access to database backups."
        ),
        "remediation": (
            "1. Enable S3 Block Public Access at the account level.\n"
            "2. Review and restrict bucket ACLs and policies.\n"
            "3. Enable S3 access logging and CloudTrail for audit.\n"
            "4. Use signed URLs for time-limited access instead of public permissions."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },

    # ── JavaScript Secrets ───────────────────────────────────────────
    "js_aws_key": {
        "title": "AWS Access Key Exposed in JavaScript on {domain}",
        "weakness": "CWE-798: Use of Hard-coded Credentials",
        "impact_template": (
            "An AWS access key was found in client-side JavaScript on `{domain}`. "
            "This credential can be used to access AWS services with the permissions of the associated IAM user/role.\n\n"
            "**Impact:** Depending on the IAM policy, an attacker can read/write S3 data, "
            "invoke Lambda functions, access RDS databases, or escalate privileges within the AWS account."
        ),
        "remediation": (
            "1. Revoke the exposed AWS credentials immediately.\n"
            "2. Use server-side proxy endpoints instead of direct AWS calls from the browser.\n"
            "3. If client-side AWS access is needed, use Cognito Identity Pools with minimal permissions.\n"
            "4. Scan code for secrets using `trufflehog` or `gitleaks` in CI/CD."
        ),
        "severity": "critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    },
    "js_api_key": {
        "title": "API Key Exposed in JavaScript on {domain}",
        "weakness": "CWE-798: Use of Hard-coded Credentials",
        "impact_template": (
            "A sensitive API key or secret token was found in client-side JavaScript on `{domain}`. "
            "Exposed keys can be used to access third-party services, internal APIs, or backend systems "
            "with elevated privileges."
        ),
        "remediation": (
            "1. Rotate the exposed API key immediately.\n"
            "2. Move API calls to a server-side proxy endpoint.\n"
            "3. If client-side keys are necessary, restrict them by domain/IP and scope.\n"
            "4. Implement secret scanning in CI/CD pipelines."
        ),
        "severity": "high",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    },
}

DEFAULT_TEMPLATE = {
    "title": "Security Finding on {domain}",
    "weakness": "CWE-16: Configuration",
    "impact_template": (
        "A security issue was identified on `{domain}`: {finding_title}. "
        "{evidence}"
    ),
    "remediation": "Investigate and remediate the finding based on the evidence provided.",
    "severity": "medium",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
}


# ── Confidence Scoring ───────────────────────────────────────────────

HIGH_CONFIDENCE_CODES = {
    "subdomain_takeover", "git_head_exposed", "env_file_exposed",
    "ssrf_aws_metadata", "idor_id_increment", "dns_zone_transfer",
    "graphql_introspection", "js_aws_key", "js_api_key",
    "sql_injection", "sql_injection_blind", "xss_stored",
    "ssti", "xxe", "path_traversal", "s3_bucket_public",
    "broken_auth_jwt",
}

MEDIUM_CONFIDENCE_CODES = {
    "xss_reflected", "xss_dom", "cors_reflected_origin",
    "ssrf_localhost", "race_condition", "crlf_injection",
    "host_header_injection", "session_fixation",
}


def calculate_confidence(finding: dict) -> int:
    """Calculate confidence score (0-100) for a finding based on multiple signals."""
    confidence = 40

    evidence = finding.get("evidence", "")
    if evidence:
        if len(evidence) > 200:
            confidence += 20
        elif len(evidence) > 50:
            confidence += 15
        elif len(evidence) > 10:
            confidence += 5

    code = finding.get("code", "")
    if code in HIGH_CONFIDENCE_CODES:
        confidence += 20
    elif code in MEDIUM_CONFIDENCE_CODES:
        confidence += 12

    severity = finding.get("severity", "")
    if severity == "critical":
        confidence += 10
    elif severity == "high":
        confidence += 7

    indicators = finding.get("indicators", [])
    if isinstance(indicators, list):
        confidence += min(15, len(indicators) * 5)

    if finding.get("verified"):
        confidence += 15

    tool = finding.get("tool", "")
    if tool in ("nuclei", "sqlmap", "dalfox"):
        confidence += 8
    elif tool in ("nmap", "ffuf"):
        confidence += 4

    if finding.get("response_code") and finding.get("response_body"):
        confidence += 5

    return min(100, confidence)


def should_auto_submit(finding: dict, min_confidence: int = 80) -> bool:
    """Determine if a finding is reliable enough for auto-submission."""
    confidence = calculate_confidence(finding)

    code = finding.get("code", "")
    never_auto_submit = {
        "missing_hsts", "missing_csp", "missing_xfo", "missing_xcto",
        "robots_interesting", "directory_listing", "trace_enabled",
        "info_disclosure_version",
    }
    if code in never_auto_submit:
        return False

    severity = finding.get("severity", "")
    if severity in ("low", "info"):
        return False

    return confidence >= min_confidence


# ── Report Generation ────────────────────────────────────────────────

def _extract_urls(text: str) -> list[str]:
    """Extract HTTP(S) URLs from text."""
    return re.findall(r'https?://[^\s\'"<>]+', text)


def _build_curl_command(url: str, method: str = "GET", headers: dict | None = None, body: str | None = None) -> str:
    """Build a cURL command for reproducibility."""
    parts = [f"curl -isk -X {method}"]
    if headers:
        for k, v in headers.items():
            parts.append(f"  -H '{k}: {v}'")
    if body:
        parts.append(f"  -d '{body[:500]}'")
    parts.append(f"  '{url}'")
    return " \\\n".join(parts)


def _build_steps_to_reproduce(domain: str, primary: dict, _template: dict) -> list[str]:
    """Build detailed, HackerOne-quality Steps to Reproduce."""
    steps: list[str] = []
    evidence = primary.get("evidence", "")
    code = primary.get("code", "")
    urls = _extract_urls(evidence)
    target_url = urls[0] if urls else f"https://{domain}"

    if code in ("sql_injection", "sql_injection_blind"):
        steps.append(f"1. Navigate to `{target_url}`")
        steps.append("2. Identify the vulnerable parameter in the request")
        steps.append("3. Inject a SQL payload (e.g., `' OR 1=1--`, `' AND SLEEP(5)--`)")
        steps.append("4. Observe the response: altered results (boolean-based) or delayed response (time-based)")
        if evidence:
            steps.append(f"5. Evidence from scan: `{evidence[:300]}`")
        steps.append("\n**Reproduce with sqlmap:**")
        steps.append("```")
        steps.append(f"sqlmap -u '{target_url}' --batch --level=3 --risk=2")
        steps.append("```")

    elif code in ("xss_reflected", "xss_dom"):
        steps.append("1. Open a browser with Developer Tools (F12) → Console tab")
        steps.append(f"2. Navigate to `{target_url}`")
        steps.append("3. Inject the payload into the vulnerable parameter: `<script>alert(document.domain)</script>`")
        steps.append("4. Observe: the JavaScript executes, displaying the domain in an alert box")
        steps.append("5. Check the Console tab for any CSP violations (if CSP is absent, exploitation is trivial)")
        if evidence:
            steps.append(f"6. Scanner evidence: `{evidence[:300]}`")
        steps.append("\n**cURL to reproduce:**")
        steps.append("```")
        steps.append(_build_curl_command(target_url))
        steps.append("```")

    elif code == "xss_stored":
        steps.append(f"1. Authenticate to the application at `{target_url}`")
        steps.append("2. Navigate to the input field where user content is stored (e.g., profile, comment, post)")
        steps.append("3. Submit the payload: `<img src=x onerror=alert(document.domain)>`")
        steps.append("4. Navigate to the page where the stored content is rendered")
        steps.append("5. Observe: the JavaScript executes for any user viewing the page")
        if evidence:
            steps.append(f"6. Scanner evidence: `{evidence[:300]}`")

    elif code == "ssti":
        steps.append(f"1. Navigate to `{target_url}`")
        steps.append(f"2. Inject a template expression in the vulnerable parameter: `{{{{7*7}}}}`")
        steps.append("3. Observe: the response contains `49` instead of the literal string")
        steps.append(f"4. Escalate with: `{{{{config.__class__.__init__.__globals__['os'].popen('id').read()}}}}` (Jinja2)")
        steps.append("5. Observe: the response contains the output of the `id` command")
        if evidence:
            steps.append(f"6. Scanner evidence: `{evidence[:300]}`")

    elif code in ("ssrf_aws_metadata", "ssrf_localhost"):
        target_internal = "http://169.254.169.254/latest/meta-data/" if code == "ssrf_aws_metadata" else "http://127.0.0.1/"
        steps.append(f"1. Navigate to `{target_url}`")
        steps.append("2. Identify the parameter that accepts URLs (e.g., `url=`, `redirect=`, `callback=`)")
        steps.append(f"3. Replace the value with: `{target_internal}`")
        steps.append("4. Observe: the response contains internal data (metadata credentials or localhost service response)")
        if evidence:
            steps.append(f"5. Scanner evidence: `{evidence[:300]}`")
        steps.append("\n**cURL to reproduce:**")
        steps.append("```")
        steps.append(_build_curl_command(target_url))
        steps.append("```")

    elif code == "idor_id_increment":
        steps.append("1. Authenticate as User A and navigate to your profile/resource endpoint")
        steps.append("2. Note the numeric ID in the URL (e.g., `/api/users/123`)")
        steps.append("3. Change the ID to another value (e.g., `/api/users/124`)")
        steps.append("4. Observe: the response contains User B's data without authorization error")
        steps.append("5. Verify by comparing the returned email/username — it belongs to a different account")
        if evidence:
            steps.append(f"6. Scanner evidence: `{evidence[:300]}`")

    elif code == "subdomain_takeover":
        steps.append(f"1. Run DNS lookup: `dig CNAME {domain}`")
        steps.append("2. Observe: the CNAME points to a service that returns an error (e.g., \"NoSuchBucket\", \"There isn't a GitHub Pages site here\")")
        steps.append("3. Register the target resource on the hosting platform (e.g., create the S3 bucket, claim the Heroku app)")
        steps.append(f"4. Verify: `https://{domain}` now serves attacker-controlled content")
        if evidence:
            steps.append(f"5. Scanner evidence: `{evidence[:300]}`")

    elif code == "git_head_exposed":
        steps.append(f"1. Navigate to `https://{domain}/.git/HEAD`")
        steps.append("2. Observe: the response contains `ref: refs/heads/main` (or similar)")
        steps.append(f"3. Navigate to `https://{domain}/.git/config` to confirm access to repository configuration")
        steps.append(f"4. Use `git-dumper` to reconstruct the repository: `git-dumper https://{domain}/.git/ output_dir`")
        steps.append("5. Search the dumped repo for secrets: `trufflehog filesystem output_dir/`")

    elif code == "env_file_exposed":
        steps.append(f"1. Navigate to `https://{domain}/.env`")
        steps.append("2. Observe: the response contains environment variables with database credentials, API keys, etc.")
        steps.append("3. Verify: try using one of the exposed credentials to access the respective service")
        if evidence:
            steps.append(f"4. Redacted evidence: `{_redact_secrets(evidence[:300])}`")
        steps.append("\n**cURL to reproduce:**")
        steps.append("```")
        steps.append(_build_curl_command(f"https://{domain}/.env"))
        steps.append("```")

    elif code == "graphql_introspection":
        steps.append("1. Send an introspection query to the GraphQL endpoint:")
        steps.append("```")
        steps.append(_build_curl_command(
            target_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            body='{"query": "{ __schema { types { name fields { name type { name } } } } }"}',
        ))
        steps.append("```")
        steps.append("2. Observe: the response contains the full API schema")
        steps.append("3. Use a tool like GraphQL Voyager to visualize the schema and identify sensitive types")

    elif code == "cors_reflected_origin":
        steps.append("1. Send a request with an arbitrary Origin header:")
        steps.append("```")
        steps.append(_build_curl_command(
            target_url,
            headers={"Origin": "https://evil.com"},
        ))
        steps.append("```")
        steps.append("2. Observe: `Access-Control-Allow-Origin: https://evil.com` is reflected in the response")
        steps.append("3. Verify `Access-Control-Allow-Credentials: true` is also present")
        steps.append("4. PoC: host a page on evil.com that makes a fetch request with `credentials: 'include'`")

    elif code == "race_condition":
        steps.append(f"1. Identify the state-changing endpoint on `{target_url}`")
        steps.append("2. Prepare a concurrent request using tools like `turbo-intruder` or `curl` in parallel:")
        steps.append("```bash")
        steps.append(f"for i in $(seq 1 20); do curl -s '{target_url}' & done; wait")
        steps.append("```")
        steps.append("3. Observe: the action is executed multiple times (e.g., balance deducted only once, reward applied N times)")
        if evidence:
            steps.append(f"4. Scanner evidence: `{evidence[:300]}`")

    else:
        if urls:
            for i, url in enumerate(urls[:3], 1):
                steps.append(f"{i}. Navigate to `{url}`")
        else:
            steps.append(f"1. Navigate to `https://{domain}`")
        steps.append(f"{len(urls[:3]) + 1 if urls else 2}. Observe: {primary.get('title', 'the vulnerability')}")
        if evidence:
            steps.append(f"{len(urls[:3]) + 2 if urls else 3}. Evidence: `{evidence[:300]}`")
        steps.append("\n**cURL to reproduce:**")
        steps.append("```")
        steps.append(_build_curl_command(target_url))
        steps.append("```")

    return steps


def _redact_secrets(text: str) -> str:
    """Partially redact obvious secrets in evidence for responsible disclosure."""
    text = re.sub(
        r'(password|secret|token|key|apikey|api_key)\s*[=:]\s*\S+',
        lambda m: m.group(0)[:20] + "***REDACTED***",
        text,
        flags=re.IGNORECASE,
    )
    return text


def _business_impact_section(code: str, severity: str, _domain: str) -> str:
    """Generate a separate business impact subsection with regulatory context."""
    parts = []

    if severity in ("critical", "high"):
        parts.append(
            "**Business Impact:** This vulnerability poses a significant risk to the organization's "
            "security posture. Successful exploitation could result in:"
        )
        impacts = []
        if code in ("sql_injection", "sql_injection_blind", "idor_id_increment", "env_file_exposed"):
            impacts.append("- Unauthorized access to sensitive data (PII, credentials, financial records)")
            impacts.append("- Mandatory breach notification under **GDPR Art. 33** (72-hour deadline) and **LGPD Art. 48**")
        if code in ("sql_injection", "ssti", "xxe", "ssrf_aws_metadata"):
            impacts.append("- Potential Remote Code Execution, leading to full server compromise")
        if code in ("xss_stored", "xss_reflected", "cors_reflected_origin"):
            impacts.append("- Mass session hijacking and account takeover")
        if code in ("broken_auth_jwt", "session_fixation"):
            impacts.append("- Complete authentication bypass, impersonation of any user")
        if code in ("s3_bucket_public", "git_head_exposed"):
            impacts.append("- Intellectual property theft and source code disclosure")
        if code in ("race_condition",):
            impacts.append("- Financial loss through double-spending or reward abuse")
        if not impacts:
            impacts.append("- Unauthorized access, data exfiltration, or service disruption")

        parts.extend(impacts)

    elif severity == "medium":
        parts.append(
            "**Business Impact:** This vulnerability could be leveraged as part of a larger attack chain "
            "or exploited to extract limited sensitive information. While not critical in isolation, "
            "it reduces the overall security posture."
        )

    return "\n".join(parts)


def generate_h1_report(
    domain: str,
    findings: list[dict],
    program_name: str = "",
    program_url: str = "",
) -> dict[str, Any]:
    """Generate a high-quality HackerOne report with detailed PoC and impact analysis."""
    if not findings:
        return {"title": "", "body": "", "severity": "medium", "impact": ""}

    primary = findings[0]
    code = primary.get("code", "")
    severity = primary.get("severity", "medium")

    template = VULN_TEMPLATES.get(code, DEFAULT_TEMPLATE)

    title = template["title"].format(
        domain=domain,
        finding_title=primary.get("title", "Security Finding"),
    )

    impact = template["impact_template"].format(
        domain=domain,
        evidence=_redact_secrets(primary.get("evidence", "")),
        sensitive_data="personal data, account details, and session tokens",
        finding_title=primary.get("title", ""),
    )

    body_parts = [
        "## Summary\n",
        f"During security assessment of **{program_name or domain}**, "
        f"a **{severity.upper()}** severity vulnerability was identified on `{domain}`.\n",
    ]

    body_parts.extend([
        "## Vulnerability Details\n",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Type** | {primary.get('title', 'Security Finding')} |",
        f"| **Severity** | {severity.upper()} |",
        f"| **Weakness** | {template['weakness']} |",
        f"| **CVSS 3.1** | `{primary.get('cvss_vector') or template['cvss_vector']}` (Base: **{primary.get('cvss_base') or CVSS_BASE_SCORES.get(severity, 5.5):.1f}**) |",
        f"| **Confidence** | {calculate_confidence(primary)}% |",
        f"| **Tool** | {primary.get('tool', 'nuclei')} |",
        f"| **Affected URL** | `{primary.get('matched_at', domain)}` |",
        "",
    ])

    body_parts.extend([
        "## Impact\n",
        impact,
        "",
    ])

    biz_impact = _business_impact_section(code, severity, domain)
    if biz_impact:
        body_parts.extend([
            f"\n{biz_impact}",
            "",
        ])

    body_parts.append("## Steps to Reproduce\n")
    steps = _build_steps_to_reproduce(domain, primary, template)
    body_parts.extend(steps)

    evidence = primary.get("evidence", "")
    response_body = primary.get("response_body", primary.get("http_response", ""))
    response_headers = primary.get("response_headers", "")
    http_request = primary.get("http_request", "")
    curl_command = primary.get("curl_command", "")
    matched_at = primary.get("matched_at", "")

    # Sempre incluir seção de PoC se houver qualquer evidência
    has_poc = response_body or response_headers or http_request or curl_command or (evidence and len(evidence) > 50)

    if has_poc:
        body_parts.append("\n## Proof of Concept\n")

        if matched_at:
            body_parts.append(f"**Affected URL:** `{matched_at}`\n")

        if curl_command:
            body_parts.append("**Reproduce with cURL:**")
            body_parts.append("```bash")
            body_parts.append(_redact_secrets(str(curl_command)[:800]))
            body_parts.append("```\n")

        if http_request:
            body_parts.append("**HTTP Request:**")
            body_parts.append("```http")
            body_parts.append(_redact_secrets(str(http_request)[:1500]))
            body_parts.append("```\n")

        if response_headers:
            body_parts.append("**Response Headers:**")
            body_parts.append("```http")
            body_parts.append(_redact_secrets(str(response_headers)[:500]))
            body_parts.append("```\n")

        if response_body:
            body_parts.append("**HTTP Response (truncated):**")
            body_parts.append("```")
            body_parts.append(_redact_secrets(str(response_body)[:1500]))
            body_parts.append("```\n")

        if evidence and len(evidence) > 50 and not http_request and not response_body:
            body_parts.append("**Scanner Evidence:**")
            body_parts.append("```")
            body_parts.append(_redact_secrets(evidence[:800]))
            body_parts.append("```")

    if len(findings) > 1:
        body_parts.append(f"\n## Additional Findings ({len(findings) - 1} more)\n")
        for f in findings[1:8]:
            sev = f.get("severity", "medium").upper()
            conf = calculate_confidence(f)
            body_parts.append(f"- **[{sev}]** {f.get('title', '?')} (confidence: {conf}%)")
            if f.get("evidence"):
                body_parts.append(f"  - Evidence: `{_redact_secrets(f['evidence'][:150])}`")

    body_parts.extend([
        "\n## Remediation\n",
        template["remediation"],
    ])

    body_parts.extend([
        "\n## References\n",
        _generate_references(code),
    ])

    body_parts.append(
        f"\n---\n*Security assessment performed on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*"
    )

    # Usar CVSS real do scanner quando disponível
    real_cvss_score = primary.get("cvss_base", 0)
    real_cvss_vector = primary.get("cvss_vector", "")
    if not real_cvss_score or real_cvss_score == 0:
        real_cvss_score = CVSS_BASE_SCORES.get(severity, 5.5)
    if not real_cvss_vector:
        real_cvss_vector = template["cvss_vector"]

    return {
        "title": title[:250],
        "body": "\n".join(body_parts),
        "severity": severity,
        "impact": impact,
        "weakness": template["weakness"],
        "cvss_vector": real_cvss_vector,
        "cvss_score": real_cvss_score,
        "confidence": calculate_confidence(primary),
        "auto_submit_eligible": should_auto_submit(primary),
        "findings_count": len(findings),
    }


def _generate_references(code: str) -> str:
    """Generate relevant reference links for a vulnerability type."""
    refs = {
        "sql_injection": (
            "- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)\n"
            "- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)\n"
            "- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)"
        ),
        "sql_injection_blind": (
            "- [OWASP Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)\n"
            "- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)"
        ),
        "xss_reflected": (
            "- [OWASP XSS](https://owasp.org/www-community/attacks/xss/)\n"
            "- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)\n"
            "- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)"
        ),
        "xss_stored": (
            "- [OWASP Stored XSS](https://owasp.org/www-community/attacks/xss/#stored-xss-attacks)\n"
            "- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)"
        ),
        "xss_dom": (
            "- [OWASP DOM XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)\n"
            "- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)"
        ),
        "ssti": (
            "- [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection)\n"
            "- [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html)\n"
            "- [HackTricks SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)"
        ),
        "ssrf_aws_metadata": (
            "- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)\n"
            "- [CWE-918](https://cwe.mitre.org/data/definitions/918.html)\n"
            "- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)"
        ),
        "ssrf_localhost": (
            "- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)\n"
            "- [CWE-918](https://cwe.mitre.org/data/definitions/918.html)"
        ),
        "idor_id_increment": (
            "- [OWASP IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)\n"
            "- [CWE-639](https://cwe.mitre.org/data/definitions/639.html)"
        ),
        "subdomain_takeover": (
            "- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)\n"
            "- [CWE-284](https://cwe.mitre.org/data/definitions/284.html)"
        ),
        "cors_reflected_origin": (
            "- [PortSwigger CORS](https://portswigger.net/web-security/cors)\n"
            "- [CWE-942](https://cwe.mitre.org/data/definitions/942.html)"
        ),
        "open_redirect": (
            "- [OWASP Unvalidated Redirects](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)\n"
            "- [CWE-601](https://cwe.mitre.org/data/definitions/601.html)"
        ),
        "graphql_introspection": (
            "- [GraphQL Security](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)\n"
            "- [CWE-200](https://cwe.mitre.org/data/definitions/200.html)"
        ),
        "race_condition": (
            "- [PortSwigger Race Conditions](https://portswigger.net/web-security/race-conditions)\n"
            "- [CWE-362](https://cwe.mitre.org/data/definitions/362.html)"
        ),
        "xxe": (
            "- [OWASP XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)\n"
            "- [CWE-611](https://cwe.mitre.org/data/definitions/611.html)"
        ),
        "path_traversal": (
            "- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)\n"
            "- [CWE-22](https://cwe.mitre.org/data/definitions/22.html)"
        ),
        "broken_auth_jwt": (
            "- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)\n"
            "- [CWE-345](https://cwe.mitre.org/data/definitions/345.html)"
        ),
    }
    return refs.get(code, f"- [{template_weakness_for(code)}](https://cwe.mitre.org/)")


def template_weakness_for(code: str) -> str:
    """Get the CWE weakness string for a vuln code."""
    t = VULN_TEMPLATES.get(code, DEFAULT_TEMPLATE)
    return t.get("weakness", "CWE-16: Configuration")


# ── Deduplication ────────────────────────────────────────────────────

def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Remove duplicate findings based on code + evidence + severity."""
    seen: set[str] = set()
    unique: list[dict] = []

    for f in findings:
        code = f.get("code", "")
        evidence_prefix = f.get("evidence", "")[:80]
        severity = f.get("severity", "medium")
        key = f"{code}:{severity}:{evidence_prefix}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(key=lambda x: _severity_rank(x.get("severity", "medium")), reverse=True)
    return unique


def _severity_rank(severity: str) -> int:
    """Rank severity for sorting (higher = more severe)."""
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(severity, 0)
