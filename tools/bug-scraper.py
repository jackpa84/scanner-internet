#!/usr/bin/env python3
"""
Bug Scraper - Fetches bug bounty programs from bounty-targets-data
(https://github.com/arkadiyt/bounty-targets-data).

Outputs one JSON object per line, compatible with the scanner's
bug_scraper_integration.py expected format.

Usage:
    python3 bug-scraper.py --mode discovery --output json [--bounty-only] [--platform hackerone,bugcrowd]
"""

import argparse
import json
import sys
import urllib.request
import urllib.error

SOURCES = {
    "hackerone": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
    "bugcrowd": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
    "intigriti": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json",
    "yeswehack": "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json",
}

SCOPABLE_ASSET_TYPES = {"URL", "WILDCARD", "CIDR", "IP_ADDRESS", "DOMAIN"}

SKIP_HOSTS = {"apps.apple.com", "play.google.com", "github.com", "itunes.apple.com"}


def fetch_json(url: str) -> list[dict]:
    req = urllib.request.Request(url, headers={"User-Agent": "bug-scraper/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        print(f"[BugScraper] Error fetching {url}: {e}", file=sys.stderr)
        return []


def _extract_domain_from_url(raw: str) -> str | None:
    """Extract a usable domain/wildcard from a URL or raw string."""
    raw = raw.strip().rstrip("/")
    if not raw:
        return None

    # {subdomain}.example.com → *.example.com
    if "{" in raw:
        import re
        cleaned = re.sub(r"https?://", "", raw)
        cleaned = re.sub(r"\{[^}]+\}\.", "*.", cleaned)
        cleaned = cleaned.split("/")[0].split(":")[0].strip()
        if "." in cleaned and len(cleaned) > 3:
            return cleaned
        return None

    if "://" in raw:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(raw)
            host = (parsed.hostname or "").lower().strip()
            if host and "." in host and host not in SKIP_HOSTS:
                return host
        except Exception:
            pass
        return None

    # Already looks like a domain or wildcard
    if "." in raw and " " not in raw and len(raw) < 200:
        cleaned = raw.split("/")[0].split(":")[0].strip().lower()
        cleaned = cleaned.lstrip("\\")
        if "." in cleaned and not cleaned.startswith("("):
            return cleaned

    return None


def extract_scope_items(targets: list[dict]) -> list[str]:
    items = []
    for t in targets:
        asset = (
            t.get("asset_identifier")
            or t.get("endpoint")
            or t.get("target")
            or t.get("uri")
            or ""
        )
        asset = asset.strip()
        if not asset:
            continue
        asset_type = (t.get("asset_type") or t.get("type") or "").upper()
        if asset_type and asset_type not in SCOPABLE_ASSET_TYPES:
            continue
        items.append(asset)
    return items


def parse_hackerone(data: list[dict], bounty_only: bool) -> list[dict]:
    programs = []
    for p in data:
        if p.get("submission_state") != "open":
            continue
        if bounty_only and not p.get("offers_bounties"):
            continue

        targets = p.get("targets") or {}
        in_scope = extract_scope_items(targets.get("in_scope") or [])
        out_scope = extract_scope_items(targets.get("out_of_scope") or [])

        if not in_scope:
            continue

        programs.append({
            "name": p.get("name") or p.get("handle") or "",
            "url": p.get("url") or "",
            "platform": "hackerone",
            "in_scope": in_scope,
            "out_of_scope": out_scope,
        })
    return programs


def _bugcrowd_extract_targets(raw_list: list[dict]) -> list[str]:
    """Extract domains from Bugcrowd target entries, checking all fields."""
    seen = set()
    items = []
    for t in raw_list:
        candidates = [
            t.get("uri") or "",
            t.get("target") or "",
            t.get("ipAddress") or "",
            t.get("name") or "",
        ]
        for raw in candidates:
            for part in raw.split():
                domain = _extract_domain_from_url(part)
                if domain and domain not in seen:
                    seen.add(domain)
                    items.append(domain)
    return items


def parse_bugcrowd(data: list[dict], bounty_only: bool) -> list[dict]:
    programs = []
    for p in data:
        targets = p.get("targets") or {}
        in_scope_raw = targets.get("in_scope") or []
        out_scope_raw = targets.get("out_of_scope") or []

        in_scope = _bugcrowd_extract_targets(in_scope_raw)
        if not in_scope:
            continue

        out_scope = _bugcrowd_extract_targets(out_scope_raw)

        programs.append({
            "name": p.get("name") or "",
            "url": p.get("url") or "",
            "platform": "bugcrowd",
            "in_scope": in_scope,
            "out_of_scope": out_scope,
        })
    return programs


def parse_generic(data: list[dict], platform: str, bounty_only: bool) -> list[dict]:
    programs = []
    for p in data:
        targets = p.get("targets") or {}
        in_scope_raw = targets.get("in_scope") or []
        out_scope_raw = targets.get("out_of_scope") or []

        in_scope = extract_scope_items(in_scope_raw)
        if not in_scope:
            continue
        out_scope = extract_scope_items(out_scope_raw)

        programs.append({
            "name": p.get("name") or "",
            "url": p.get("url") or "",
            "platform": platform,
            "in_scope": in_scope,
            "out_of_scope": out_scope,
        })
    return programs


PARSERS = {
    "hackerone": parse_hackerone,
    "bugcrowd": parse_bugcrowd,
}


def main():
    parser = argparse.ArgumentParser(description="Bug Scraper - Bug Bounty Program Discovery")
    parser.add_argument("--mode", default="discovery", help="Operation mode")
    parser.add_argument("--output", default="json", help="Output format")
    parser.add_argument("--bounty-only", action="store_true", help="Only programs that offer bounties")
    parser.add_argument("--platform", default="hackerone,bugcrowd",
                        help="Comma-separated platforms to fetch")
    args = parser.parse_args()

    platforms = [p.strip().lower() for p in args.platform.split(",") if p.strip()]

    all_programs = []
    for platform in platforms:
        url = SOURCES.get(platform)
        if not url:
            print(f"[BugScraper] Unknown platform: {platform}", file=sys.stderr)
            continue

        print(f"[BugScraper] Fetching {platform}...", file=sys.stderr)
        data = fetch_json(url)
        if not data:
            continue

        parse_fn = PARSERS.get(platform, lambda d, b: parse_generic(d, platform, b))
        programs = parse_fn(data, args.bounty_only)
        all_programs.extend(programs)
        print(f"[BugScraper] {platform}: {len(programs)} programs with scope", file=sys.stderr)

    for prog in all_programs:
        print(json.dumps(prog))

    print(f"[BugScraper] Total: {len(all_programs)} programs", file=sys.stderr)


if __name__ == "__main__":
    main()
