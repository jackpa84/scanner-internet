"""
IDOR (Insecure Direct Object Reference) Scanner.

Detects authorization bypass by manipulating object identifiers in API endpoints.
Typical payout: $1,000 - $25,000.

Techniques:
  - Sequential ID increment/decrement
  - UUID swapping
  - Parameter pollution
  - HTTP method switching (GET vs POST)
  - Encoded ID variants (base64, hex)
"""

import base64
import json
import logging
import os
import re
import time
from typing import Any
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

import requests

logger = logging.getLogger("scanner.idor")

IDOR_ENABLED = os.getenv("IDOR_SCANNER_ENABLED", "true").lower() in ("1", "true", "yes")
IDOR_TIMEOUT = int(os.getenv("IDOR_TIMEOUT", "8"))
IDOR_MAX_ENDPOINTS = int(os.getenv("IDOR_MAX_ENDPOINTS", "50"))

INTERESTING_PARAMS = {
    "id", "user_id", "uid", "account_id", "account", "profile_id",
    "order_id", "order", "invoice_id", "invoice", "doc_id", "document_id",
    "file_id", "report_id", "project_id", "org_id", "team_id",
    "message_id", "comment_id", "post_id", "ticket_id", "item_id",
    "customer_id", "member_id", "employee_id", "record_id", "ref",
}

API_PATH_PATTERNS = [
    r'/api/v\d+/\w+/(\d+)',
    r'/api/\w+/(\d+)',
    r'/v\d+/\w+/(\d+)',
    r'/\w+/(\d+)$',
    r'/users?/(\d+)',
    r'/accounts?/(\d+)',
    r'/orders?/(\d+)',
    r'/profiles?/(\d+)',
    r'/documents?/(\d+)',
    r'/files?/(\d+)',
    r'/reports?/(\d+)',
    r'/invoices?/(\d+)',
]

_stats = {
    "endpoints_tested": 0,
    "idor_found": 0,
    "errors": 0,
}


def get_idor_stats() -> dict[str, Any]:
    return dict(_stats)


def _is_numeric_id(value: str) -> bool:
    return value.isdigit() and 1 <= len(value) <= 12


def _is_uuid(value: str) -> bool:
    return bool(re.match(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        value, re.IGNORECASE,
    ))


def _is_base64_id(value: str) -> bool:
    if len(value) < 4 or len(value) > 100:
        return False
    try:
        decoded = base64.b64decode(value + "==").decode("utf-8", errors="ignore")
        return bool(re.match(r'^\d+$', decoded) or ':' in decoded)
    except Exception:
        return False


def _generate_id_variants(original_id: str) -> list[tuple[str, str]]:
    """Generate alternate IDs to test for IDOR. Returns (variant_id, technique) pairs."""
    variants = []

    if _is_numeric_id(original_id):
        num = int(original_id)
        variants.append((str(num + 1), "id_increment"))
        variants.append((str(num - 1), "id_decrement"))
        if num > 100:
            variants.append((str(num + 100), "id_jump"))
        variants.append(("1", "id_first"))
        variants.append(("0", "id_zero"))

    elif _is_uuid(original_id):
        parts = original_id.split("-")
        last_hex = int(parts[-1], 16)
        parts[-1] = format(last_hex + 1, '012x')
        variants.append(("-".join(parts), "uuid_increment"))
        variants.append(("00000000-0000-0000-0000-000000000001", "uuid_known"))

    elif _is_base64_id(original_id):
        try:
            decoded = base64.b64decode(original_id + "==").decode("utf-8", errors="ignore")
            if decoded.isdigit():
                new_id = str(int(decoded) + 1)
                variants.append((base64.b64encode(new_id.encode()).decode().rstrip("="), "base64_increment"))
        except Exception:
            pass

    return variants


def _extract_api_endpoints(urls: list[str]) -> list[dict[str, Any]]:
    """Extract API endpoints with identifiable object references from discovered URLs."""
    endpoints = []
    seen = set()

    for url in urls:
        parsed = urlparse(url)
        path = parsed.path

        for pattern in API_PATH_PATTERNS:
            match = re.search(pattern, path)
            if match:
                object_id = match.group(1)
                template = re.sub(re.escape(object_id), "{ID}", path, count=1)
                key = f"{parsed.scheme}://{parsed.netloc}{template}"
                if key not in seen:
                    seen.add(key)
                    endpoints.append({
                        "url": url,
                        "base_url": f"{parsed.scheme}://{parsed.netloc}",
                        "path": path,
                        "template": template,
                        "original_id": object_id,
                        "id_position": "path",
                    })
                break

        params = parse_qs(parsed.query)
        for param_name, values in params.items():
            if param_name.lower() in INTERESTING_PARAMS and values:
                value = values[0]
                if _is_numeric_id(value) or _is_uuid(value):
                    key = f"{parsed.scheme}://{parsed.netloc}{path}?{param_name}={{ID}}"
                    if key not in seen:
                        seen.add(key)
                        endpoints.append({
                            "url": url,
                            "base_url": f"{parsed.scheme}://{parsed.netloc}",
                            "path": path,
                            "param_name": param_name,
                            "original_id": value,
                            "id_position": "query",
                        })

    return endpoints[:IDOR_MAX_ENDPOINTS]


def _build_url_with_id(endpoint: dict, new_id: str) -> str:
    """Build URL with substituted ID."""
    if endpoint["id_position"] == "path":
        new_path = endpoint["path"].replace(endpoint["original_id"], new_id, 1)
        return f"{endpoint['base_url']}{new_path}"

    parsed = urlparse(endpoint["url"])
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[endpoint["param_name"]] = [new_id]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _compare_responses(
    original_resp: requests.Response,
    tampered_resp: requests.Response,
) -> dict[str, Any]:
    """Compare original and tampered responses to detect IDOR."""
    result = {
        "is_idor": False,
        "confidence": 0,
        "indicators": [],
    }

    if tampered_resp.status_code == 403 or tampered_resp.status_code == 401:
        return result

    if tampered_resp.status_code == 404:
        return result

    if tampered_resp.status_code == 200 and original_resp.status_code == 200:
        orig_len = len(original_resp.text)
        tamp_len = len(tampered_resp.text)

        if tamp_len > 50 and abs(orig_len - tamp_len) > 10:
            result["indicators"].append("different_content_length")
            result["confidence"] += 30

        try:
            orig_json = original_resp.json()
            tamp_json = tampered_resp.json()

            if isinstance(orig_json, dict) and isinstance(tamp_json, dict):
                orig_id_fields = {k: v for k, v in orig_json.items()
                                  if k.lower() in INTERESTING_PARAMS or k.lower() == "id"}
                tamp_id_fields = {k: v for k, v in tamp_json.items()
                                  if k.lower() in INTERESTING_PARAMS or k.lower() == "id"}

                if orig_id_fields and tamp_id_fields and orig_id_fields != tamp_id_fields:
                    result["indicators"].append("different_object_ids_in_response")
                    result["confidence"] += 40

                sensitive_keys = {"email", "phone", "address", "name", "username",
                                  "password", "ssn", "credit_card", "token"}
                tamp_keys = {k.lower() for k in tamp_json.keys()}
                if tamp_keys & sensitive_keys:
                    result["indicators"].append("sensitive_data_in_response")
                    result["confidence"] += 20

        except (json.JSONDecodeError, ValueError):
            if tamp_len > 50 and original_resp.text != tampered_resp.text:
                result["indicators"].append("different_html_content")
                result["confidence"] += 15

    if tampered_resp.status_code in (200, 201) and original_resp.status_code in (200, 201):
        if result["confidence"] >= 50:
            result["is_idor"] = True

    return result


def scan_for_idor(
    target_url: str,
    discovered_urls: list[str],
    cookies: dict | None = None,
    headers: dict | None = None,
) -> list[dict[str, Any]]:
    """Scan discovered URLs for IDOR vulnerabilities.

    Args:
        target_url: Base URL of the target
        discovered_urls: List of URLs discovered during recon (from katana, gau, wayback)
        cookies: Optional session cookies
        headers: Optional HTTP headers

    Returns:
        List of IDOR findings
    """
    if not IDOR_ENABLED:
        return []

    findings = []
    req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"}
    if headers:
        req_headers.update(headers)

    endpoints = _extract_api_endpoints(discovered_urls)
    logger.info("[IDOR] Testing %d API endpoints for IDOR", len(endpoints))

    for endpoint in endpoints:
        try:
            original_url = endpoint["url"]
            original_resp = requests.get(
                original_url, headers=req_headers, cookies=cookies,
                timeout=IDOR_TIMEOUT, allow_redirects=True,
            )

            if original_resp.status_code not in (200, 201):
                continue

            variants = _generate_id_variants(endpoint["original_id"])

            for variant_id, technique in variants:
                tampered_url = _build_url_with_id(endpoint, variant_id)

                try:
                    tampered_resp = requests.get(
                        tampered_url, headers=req_headers, cookies=cookies,
                        timeout=IDOR_TIMEOUT, allow_redirects=True,
                    )

                    comparison = _compare_responses(original_resp, tampered_resp)

                    if comparison["is_idor"]:
                        finding = {
                            "severity": "high",
                            "code": f"idor_{technique}",
                            "title": f"IDOR via {technique.replace('_', ' ')}",
                            "evidence": (
                                f"Original: {original_url} (status={original_resp.status_code}, "
                                f"len={len(original_resp.text)}) | "
                                f"Tampered: {tampered_url} (status={tampered_resp.status_code}, "
                                f"len={len(tampered_resp.text)})"
                            )[:200],
                            "confidence": comparison["confidence"],
                            "indicators": comparison["indicators"],
                            "original_url": original_url,
                            "tampered_url": tampered_url,
                            "technique": technique,
                            "original_id": endpoint["original_id"],
                            "tampered_id": variant_id,
                        }
                        findings.append(finding)
                        _stats["idor_found"] += 1
                        logger.info("[IDOR] FOUND: %s on %s (confidence=%d%%)",
                                    technique, original_url, comparison["confidence"])
                        break

                except requests.RequestException:
                    continue

                time.sleep(0.5)

            _stats["endpoints_tested"] += 1

        except requests.RequestException:
            _stats["errors"] += 1
            continue
        except Exception as e:
            logger.debug("[IDOR] Error testing %s: %s", endpoint.get("url", "?"), e)
            _stats["errors"] += 1

    return findings


def scan_target_for_idor(domain: str, crawled_urls: list[str], wayback_urls: list[str]) -> list[dict[str, Any]]:
    """Convenience function: scan a bounty target for IDOR using all discovered URLs."""
    all_urls = list(set(crawled_urls + wayback_urls))
    domain_urls = [u for u in all_urls if domain in u]

    if not domain_urls:
        return []

    return scan_for_idor(f"https://{domain}", domain_urls)
