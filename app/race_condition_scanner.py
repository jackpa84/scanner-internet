"""
Race condition scanner.

Detects time-of-check-to-time-of-use (TOCTOU) vulnerabilities
by sending concurrent requests to the same endpoint.
Typical payout: $1,000 - $10,000.

Techniques:
  - Parallel request flooding (same endpoint, same params)
  - Response comparison for inconsistent state
  - Coupon/discount double-apply
  - Balance manipulation via concurrent transfers
  - Vote/like count manipulation
"""

import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urlparse

import requests

logger = logging.getLogger("scanner.race")

RACE_ENABLED = os.getenv("RACE_SCANNER_ENABLED", "true").lower() in ("1", "true", "yes")
RACE_TIMEOUT = int(os.getenv("RACE_TIMEOUT", "10"))
RACE_CONCURRENCY = int(os.getenv("RACE_CONCURRENCY", "20"))

RACE_PRONE_PATTERNS = [
    r'/api/v\d+/(vote|like|follow|subscribe|apply|redeem|coupon|discount)',
    r'/api/(vote|like|follow|subscribe|apply|redeem|coupon|discount)',
    r'/(checkout|purchase|buy|transfer|send|withdraw|deposit)',
    r'/(register|signup|sign-up|create-account)',
    r'/(reset-password|forgot-password|change-password)',
    r'/(verify|confirm|activate|approve)',
    r'/(invite|refer|referral)',
    r'/(claim|bonus|reward|points)',
]

RACE_PRONE_PARAMS = {
    "quantity", "amount", "count", "times", "votes",
    "coupon", "discount_code", "promo", "referral_code",
}

_stats = {
    "endpoints_tested": 0,
    "race_conditions_found": 0,
    "errors": 0,
}


def get_race_stats() -> dict[str, Any]:
    return dict(_stats)


def _is_race_prone_endpoint(url: str) -> bool:
    """Check if URL matches patterns likely to have race conditions."""
    parsed = urlparse(url)
    path = parsed.path.lower()

    for pattern in RACE_PRONE_PATTERNS:
        if re.search(pattern, path):
            return True

    return False


def _identify_race_candidates(urls: list[str]) -> list[str]:
    """Filter URLs to those likely susceptible to race conditions."""
    candidates = []
    seen_paths = set()

    for url in urls:
        parsed = urlparse(url)
        path = parsed.path.lower()

        if path in seen_paths:
            continue

        if _is_race_prone_endpoint(url):
            seen_paths.add(path)
            candidates.append(url)

    return candidates


def _send_request(url: str, method: str, headers: dict, data: dict | None = None) -> dict:
    """Send a single HTTP request and capture timing + response."""
    start = time.perf_counter()
    try:
        if method == "POST":
            resp = requests.post(url, headers=headers, json=data, timeout=RACE_TIMEOUT, allow_redirects=False)
        else:
            resp = requests.get(url, headers=headers, timeout=RACE_TIMEOUT, allow_redirects=False)

        elapsed = time.perf_counter() - start
        return {
            "status_code": resp.status_code,
            "content_length": len(resp.text),
            "response_time": elapsed,
            "headers": dict(resp.headers),
            "body_preview": resp.text[:500],
            "success": True,
        }
    except Exception as e:
        return {
            "status_code": 0,
            "error": str(e),
            "response_time": time.perf_counter() - start,
            "success": False,
        }


def test_race_condition(
    url: str,
    method: str = "GET",
    data: dict | None = None,
    headers: dict | None = None,
    concurrency: int = 0,
) -> dict[str, Any]:
    """Send concurrent requests to test for race conditions."""
    if concurrency <= 0:
        concurrency = RACE_CONCURRENCY

    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        "Content-Type": "application/json",
    }
    if headers:
        req_headers.update(headers)

    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(_send_request, url, method, req_headers, data)
            for _ in range(concurrency)
        ]
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass

    successful = [r for r in results if r["success"]]
    if not successful:
        return {"vulnerable": False, "error": "all requests failed"}

    status_codes = [r["status_code"] for r in successful]
    content_lengths = [r["content_length"] for r in successful]
    response_times = [r["response_time"] for r in successful]

    unique_statuses = set(status_codes)
    unique_lengths = set(content_lengths)

    analysis = {
        "total_requests": len(results),
        "successful_requests": len(successful),
        "unique_status_codes": list(unique_statuses),
        "unique_content_lengths": len(unique_lengths),
        "avg_response_time": sum(response_times) / len(response_times) if response_times else 0,
        "min_response_time": min(response_times) if response_times else 0,
        "max_response_time": max(response_times) if response_times else 0,
    }

    vulnerable = False
    indicators = []

    success_count = sum(1 for s in status_codes if s in (200, 201, 204))
    if success_count > 1 and method == "POST":
        indicators.append(f"Multiple successful POST responses ({success_count}/{len(successful)})")
        vulnerable = True

    if len(unique_statuses) > 1 and (200 in unique_statuses or 201 in unique_statuses):
        s4xx = sum(1 for s in status_codes if 400 <= s < 500)
        s2xx = sum(1 for s in status_codes if 200 <= s < 300)
        if s4xx > 0 and s2xx > 1:
            indicators.append(f"Mixed responses: {s2xx} success + {s4xx} failures (state inconsistency)")
            vulnerable = True

    if len(unique_lengths) > 3 and all(s == 200 for s in status_codes):
        indicators.append(f"High response variance ({len(unique_lengths)} unique sizes) suggests state changes")
        vulnerable = True

    analysis["vulnerable"] = vulnerable
    analysis["indicators"] = indicators
    _stats["endpoints_tested"] += 1

    if vulnerable:
        _stats["race_conditions_found"] += 1

    return analysis


def scan_for_race_conditions(
    discovered_urls: list[str],
    headers: dict | None = None,
) -> list[dict[str, Any]]:
    """Scan discovered URLs for race conditions."""
    if not RACE_ENABLED:
        return []

    candidates = _identify_race_candidates(discovered_urls)
    logger.info("[RACE] Testing %d race-prone endpoints", len(candidates))

    findings = []
    for url in candidates[:20]:
        try:
            result = test_race_condition(url, method="GET", headers=headers)

            if result.get("vulnerable"):
                findings.append({
                    "severity": "high",
                    "code": "race_condition",
                    "title": f"Potential race condition on {urlparse(url).path}",
                    "evidence": " | ".join(result.get("indicators", []))[:200],
                    "url": url,
                    "details": result,
                })
                logger.info("[RACE] FOUND: Race condition on %s", url)

        except Exception as e:
            logger.debug("[RACE] Error testing %s: %s", url, e)
            _stats["errors"] += 1

        time.sleep(1)

    return findings


def scan_target_for_race(
    domain: str,
    crawled_urls: list[str],
    wayback_urls: list[str],
) -> list[dict[str, Any]]:
    """Convenience: scan a bounty target for race conditions."""
    all_urls = list(set(crawled_urls + wayback_urls))
    domain_urls = [u for u in all_urls if domain in u]
    return scan_for_race_conditions(domain_urls)
