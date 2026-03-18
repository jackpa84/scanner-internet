"""
Multi-platform bug bounty program scrapers.

Integração baseada no madmax-hunter — scraping direto das APIs oficiais:
  - HackerOne    (Basic Auth)
  - Bugcrowd     (Token Auth)
  - Intigriti    (Bearer Token)
  - YesWeHack    (Bearer Token)
  - BugHunt      (Login + Token)

Diferente do bounty_targets_data.py que consome dumps estáticos do GitHub,
este módulo faz scraping ATIVO das APIs de cada plataforma para obter
dados em tempo real, detectar mudanças de escopo e novos programas.

Env vars:
  PLATFORM_WATCHER_ENABLED   = true
  PLATFORM_WATCHER_INTERVAL  = 1800  (30 min)
  PLATFORM_WATCHER_PLATFORMS = hackerone,bugcrowd,intigriti,yeswehack,bughunt
  HACKERONE_API_USERNAME      (obrigatório para HackerOne)
  HACKERONE_API_TOKEN         (obrigatório para HackerOne)
  BUGCROWD_API_TOKEN          (obrigatório para Bugcrowd)
  INTIGRITI_API_TOKEN         (obrigatório para Intigriti)
  YESWEHACK_TOKEN             (obrigatório para YesWeHack)
  BUGHUNT_EMAIL               (obrigatório para BugHunt)
  BUGHUNT_PASSWORD            (obrigatório para BugHunt)
  DISCORD_WEBHOOK_URL         (opcional — alertas de novos programas)
  SLACK_WEBHOOK_URL           (opcional — alertas de novos programas)
"""

from __future__ import annotations

import abc
import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

import requests

from app.database import get_bounty_changes, get_bounty_programs, get_redis

logger = logging.getLogger("scanner.platform_scrapers")

# ═══════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════

WATCHER_ENABLED = os.getenv("PLATFORM_WATCHER_ENABLED", "true").lower() in ("1", "true", "yes")
WATCHER_INTERVAL = int(os.getenv("PLATFORM_WATCHER_INTERVAL", "1800"))
WATCHER_PLATFORMS = [
    p.strip()
    for p in os.getenv("PLATFORM_WATCHER_PLATFORMS", "hackerone,bugcrowd,intigriti,yeswehack,bughunt").split(",")
    if p.strip()
]

# API credentials
H1_USERNAME = os.getenv("HACKERONE_API_USERNAME", "")
H1_TOKEN = os.getenv("HACKERONE_API_TOKEN", "")
BUGCROWD_TOKEN = os.getenv("BUGCROWD_API_TOKEN", "")
INTIGRITI_TOKEN = os.getenv("INTIGRITI_API_TOKEN", "")
YESWEHACK_TOKEN = os.getenv("YESWEHACK_TOKEN", "")
BUGHUNT_EMAIL = os.getenv("BUGHUNT_EMAIL", "")
BUGHUNT_PASSWORD = os.getenv("BUGHUNT_PASSWORD", "")

# Notification webhooks
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL", "")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")

# HTTP defaults
_TIMEOUT = 30
_UA = "ScannerPlatformWatcher/1.0"


# ═══════════════════════════════════════════════════════════════
# Data model
# ═══════════════════════════════════════════════════════════════

@dataclass
class Program:
    """Normalized bug bounty program from any platform."""
    name: str
    url: str
    platform: str
    program_id: str = ""
    scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    reward_type: str = "bounty"       # bounty | vdp | kudos
    program_type: str = "public"      # public | private
    max_bounty: float = 0.0
    min_bounty: float = 0.0
    submission_state: str = "open"
    first_seen: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if not d["first_seen"]:
            d["first_seen"] = datetime.utcnow().isoformat()
        return d

    def scope_hash(self) -> str:
        """Hash of sorted scope for change detection."""
        return hashlib.md5(
            json.dumps(sorted(self.scope), sort_keys=True).encode()
        ).hexdigest()


# ═══════════════════════════════════════════════════════════════
# Filter
# ═══════════════════════════════════════════════════════════════

@dataclass
class ProgramFilter:
    """Filter programs by criteria."""
    bounty_only: bool = False
    keywords: list[str] = field(default_factory=list)
    exclude_keywords: list[str] = field(default_factory=list)
    min_scope_items: int = 0
    min_bounty: float = 0.0

    def matches(self, prog: Program) -> bool:
        if self.bounty_only and prog.reward_type != "bounty":
            return False
        if self.min_bounty and prog.max_bounty < self.min_bounty:
            return False
        if self.min_scope_items and len(prog.scope) < self.min_scope_items:
            return False

        name_lower = prog.name.lower()
        if self.keywords:
            if not any(kw.lower() in name_lower for kw in self.keywords):
                return False
        if self.exclude_keywords:
            if any(kw.lower() in name_lower for kw in self.exclude_keywords):
                return False

        return True


# ═══════════════════════════════════════════════════════════════
# Base Scraper
# ═══════════════════════════════════════════════════════════════

class BaseScraper(abc.ABC):
    """Abstract base for platform scrapers."""

    platform: str = ""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers["User-Agent"] = _UA

    @abc.abstractmethod
    def fetch(self) -> list[Program]:
        """Fetch all programs from the platform."""
        ...

    def is_configured(self) -> bool:
        """Check if required credentials are set."""
        return True

    @staticmethod
    def _extract_items(
        data: Any,
        keys: tuple[str, ...] = ("items", "programs", "data", "results", "records"),
    ) -> list[dict]:
        """Pull a list of dicts from a JSON response (madmax-hunter compat)."""
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for k in keys:
                if k in data and isinstance(data[k], list):
                    return data[k]
            if "name" in data:
                return [data]
        return []


# ═══════════════════════════════════════════════════════════════
# HackerOne Scraper
# ═══════════════════════════════════════════════════════════════

class HackerOneScraper(BaseScraper):
    """
    HackerOne API scraper with Basic Auth.
    Requires HACKERONE_API_USERNAME and HACKERONE_API_TOKEN.
    """
    platform = "hackerone"
    API_BASE = "https://api.hackerone.com/v1"

    def is_configured(self) -> bool:
        return bool(H1_USERNAME and H1_TOKEN)

    def fetch(self) -> list[Program]:
        if not self.is_configured():
            logger.warning("[H1-SCRAPER] Credentials not set — skipping")
            return []

        logger.info("[H1-SCRAPER] Fetching programs...")
        programs: list[Program] = []
        url = f"{self.API_BASE}/hackers/programs"
        page = 1

        while url:
            try:
                resp = self.session.get(
                    url,
                    auth=(H1_USERNAME, H1_TOKEN),
                    params={"page[size]": 100} if page == 1 else None,
                    timeout=_TIMEOUT,
                )
                resp.raise_for_status()
                data = resp.json()
            except requests.RequestException as e:
                logger.error("[H1-SCRAPER] API error page %d: %s", page, e)
                break

            items = data.get("data", [])
            for item in items:
                attrs = item.get("attributes", {})
                name = attrs.get("name", "")
                handle = attrs.get("handle", "")
                if not handle:
                    continue

                offers_bounties = attrs.get("offers_bounties", False)
                submission_state = attrs.get("submission_state", "open")
                program_type = attrs.get("state", "public_mode")

                # Scope from relationships
                scope_items: list[str] = []
                rels = item.get("relationships", {})
                structured_scopes = rels.get("structured_scopes", {}).get("data", [])
                for sc in structured_scopes:
                    sc_attrs = sc.get("attributes", {})
                    identifier = sc_attrs.get("asset_identifier", "")
                    eligible = sc_attrs.get("eligible_for_bounty", False)
                    if identifier:
                        scope_items.append(identifier)

                programs.append(Program(
                    name=name,
                    url=f"https://hackerone.com/{handle}",
                    platform="hackerone",
                    program_id=handle,
                    scope=scope_items,
                    reward_type="bounty" if offers_bounties else "vdp",
                    program_type="public" if "public" in str(program_type).lower() else "private",
                    submission_state=submission_state,
                ))

            # Pagination
            next_link = data.get("links", {}).get("next")
            if next_link and next_link != url:
                url = next_link
                page += 1
            else:
                break

        logger.info("[H1-SCRAPER] %d programs fetched", len(programs))
        return programs


# ═══════════════════════════════════════════════════════════════
# Bugcrowd Scraper
# ═══════════════════════════════════════════════════════════════

class BugcrowdScraper(BaseScraper):
    """
    Bugcrowd API scraper with Token auth.
    Requires BUGCROWD_API_TOKEN.
    Aligned with madmax-hunter/src/platforms/bugcrowd.py.
    """
    platform = "bugcrowd"
    API_BASE = "https://api.bugcrowd.com/programs"

    def is_configured(self) -> bool:
        return bool(BUGCROWD_TOKEN)

    def fetch(self) -> list[Program]:
        if not self.is_configured():
            logger.warning("[BC-SCRAPER] Token not set — skipping")
            return []

        logger.info("[BC-SCRAPER] Fetching programs...")
        programs: list[Program] = []
        url: str | None = self.API_BASE

        while url:
            try:
                resp = self.session.get(
                    url,
                    headers={
                        "Authorization": f"Token {BUGCROWD_TOKEN}",
                        "Accept": "application/vnd.bugcrowd+json",
                    },
                    timeout=_TIMEOUT,
                )
                if resp.status_code != 200:
                    logger.error("[BC-SCRAPER] API %d: %s", resp.status_code, resp.text[:80])
                    break
                data = resp.json()
            except requests.RequestException as e:
                logger.error("[BC-SCRAPER] API error: %s", e)
                break

            items = data.get("data", [])
            for item in items:
                attrs = item.get("attributes", {})
                name = attrs.get("name", "")
                if not name:
                    continue

                code = attrs.get("code", "")

                scope_items: list[str] = []
                target_groups = attrs.get("target_groups", [])
                for tg in target_groups:
                    for target in tg.get("targets", []):
                        uri = target.get("uri", "")
                        if uri:
                            scope_items.append(uri)

                programs.append(Program(
                    name=name,
                    url=f"https://bugcrowd.com/{code}" if code else "",
                    platform="bugcrowd",
                    program_id=item.get("id", ""),
                    scope=scope_items,
                    reward_type=attrs.get("reward_type", "vdp"),
                    program_type=attrs.get("status", ""),
                    max_bounty=float(attrs.get("max_payout", 0) or 0),
                ))

            # Pagination
            next_link = data.get("links", {}).get("next")
            url = next_link if next_link else None

        logger.info("[BC-SCRAPER] %d programs fetched", len(programs))
        return programs


# ═══════════════════════════════════════════════════════════════
# Intigriti Scraper
# ═══════════════════════════════════════════════════════════════

class IntigritiScraper(BaseScraper):
    """
    Intigriti API scraper with Bearer token.
    Requires INTIGRITI_API_TOKEN.
    Uses External Researcher API v1.
    """
    platform = "intigriti"
    API_BASE = "https://api.intigriti.com/external/researcher/v1"

    def is_configured(self) -> bool:
        return bool(INTIGRITI_TOKEN)

    def fetch(self) -> list[Program]:
        if not self.is_configured():
            logger.warning("[INT-SCRAPER] Token not set — skipping")
            return []

        logger.info("[INT-SCRAPER] Fetching programs...")
        programs: list[Program] = []

        self.session.headers["Authorization"] = f"Bearer {INTIGRITI_TOKEN}"

        # Paginate through all results
        items: list[dict] = []
        offset = 0
        page_size = 50
        max_count = None
        while True:
            try:
                params = {"offset": offset, "limit": page_size}
                resp = self.session.get(
                    f"{self.API_BASE}/programs",
                    params=params,
                    timeout=_TIMEOUT,
                )
                resp.raise_for_status()
                data = resp.json()
                if isinstance(data, list):
                    page_items = data
                else:
                    page_items = data.get("records", data.get("data", []))
                    if max_count is None:
                        max_count = data.get("maxCount")
                items.extend(page_items)
                logger.info("[INT-SCRAPER] Page offset=%d: %d items (total so far: %d, maxCount=%s)",
                            offset, len(page_items), len(items), max_count or "?")
                if len(page_items) < page_size:
                    break
                offset += len(page_items)
                if max_count and offset >= max_count:
                    break
            except requests.RequestException as e:
                logger.error("[INT-SCRAPER] API error at offset %d: %s", offset, e)
                break

        for item in items:
            name = item.get("name", "")
            handle = item.get("handle", "") or item.get("companyHandle", "")
            program_id = item.get("id") or item.get("programId") or handle
            if not name:
                continue

            # Status filter: skip closed programs
            status = item.get("status", {})
            if isinstance(status, dict) and status.get("value", "").lower() == "closed":
                continue

            max_bounty = item.get("maxBounty", {})
            if isinstance(max_bounty, dict):
                max_b = float(max_bounty.get("value", 0) or 0)
            else:
                max_b = float(max_bounty or 0)

            min_bounty = item.get("minBounty", {})
            if isinstance(min_bounty, dict):
                min_b = float(min_bounty.get("value", 0) or 0)
            else:
                min_b = float(min_bounty or 0)

            # URL from webLinks or build manually
            web_links = item.get("webLinks", {})
            detail_url = ""
            if isinstance(web_links, dict) and web_links.get("detail"):
                detail_url = web_links["detail"]
            elif handle:
                detail_url = f"https://app.intigriti.com/researcher/programs/{handle}/{program_id}/detail"

            # Scope from domains if available
            scope_items: list[str] = []
            domains = item.get("domains", [])
            if isinstance(domains, list):
                for d in domains:
                    if isinstance(d, str):
                        scope_items.append(d)
                    elif isinstance(d, dict):
                        endpoint = d.get("endpoint") or d.get("domain", "")
                        if endpoint:
                            scope_items.append(endpoint)

            programs.append(Program(
                name=name,
                url=detail_url,
                platform="intigriti",
                program_id=str(program_id),
                scope=scope_items,
                reward_type="bounty" if max_b > 0 else "vdp",
                max_bounty=max_b,
                min_bounty=min_b,
            ))

        logger.info("[INT-SCRAPER] %d programs fetched", len(programs))
        return programs


# ═══════════════════════════════════════════════════════════════
# YesWeHack Scraper
# ═══════════════════════════════════════════════════════════════

class YesWeHackScraper(BaseScraper):
    """
    YesWeHack API scraper with Bearer token.
    Requires YESWEHACK_TOKEN.
    """
    platform = "yeswehack"
    API_BASE = "https://api.yeswehack.com"

    def is_configured(self) -> bool:
        return bool(YESWEHACK_TOKEN)

    def fetch(self) -> list[Program]:
        if not self.is_configured():
            logger.warning("[YWH-SCRAPER] Token not set — skipping")
            return []

        logger.info("[YWH-SCRAPER] Fetching programs...")
        programs: list[Program] = []

        self.session.headers["Authorization"] = f"Bearer {YESWEHACK_TOKEN}"

        page = 1
        total_pages = 1

        while page <= total_pages:
            try:
                resp = self.session.get(
                    f"{self.API_BASE}/programs",
                    params={"page": page},
                    timeout=_TIMEOUT,
                )
                resp.raise_for_status()
                data = resp.json()
            except requests.RequestException as e:
                logger.error("[YWH-SCRAPER] API error page %d: %s", page, e)
                break

            items = data.get("items", [])
            pagination = data.get("pagination", {})
            total_pages = pagination.get("nb_pages", 1)

            for item in items:
                title = item.get("title", "") or item.get("name", "")
                slug = item.get("slug", "")
                if not title:
                    continue

                scope_items: list[str] = []
                scopes = item.get("scopes", [])
                for sc in scopes:
                    scope_str = sc.get("scope", "") if isinstance(sc, dict) else str(sc)
                    if scope_str:
                        scope_items.append(scope_str)

                max_b = float(item.get("max_reward", 0) or 0)
                min_b = float(item.get("min_reward", 0) or 0)

                programs.append(Program(
                    name=title,
                    url=f"https://yeswehack.com/programs/{slug}" if slug else "",
                    platform="yeswehack",
                    program_id=str(item.get("id", slug or title)),
                    scope=scope_items,
                    reward_type=str(item.get("bounty_reward_type", "bounty" if max_b > 0 else "vdp")),
                    program_type=str(item.get("business_unit", "")),
                    max_bounty=max_b,
                    min_bounty=min_b,
                ))

            page += 1

        logger.info("[YWH-SCRAPER] %d programs fetched", len(programs))
        return programs


# ═══════════════════════════════════════════════════════════════
# BugHunt Scraper
# ═══════════════════════════════════════════════════════════════

class BugHuntScraper(BaseScraper):
    """
    BugHunt scraper (plataforma brasileira).
    Aligned with madmax-hunter/src/platforms/bughunt.py.

    Requer BUGHUNT_EMAIL e BUGHUNT_PASSWORD.
    Auth: CapSolver (API) → Ollama visual (fallback) → sem captcha.
    API: auth.bughunt.com.br (login) + api.bughunt.com.br (data).
    """
    platform = "bughunt"
    AUTH_URL = "https://auth.bughunt.com.br/login"
    API_BASE = "https://api.bughunt.com.br"
    ADMIN = "https://admin.bughunt.com.br"
    SITE_KEY = "6Lc7qxMqAAAAABcDOk8ypkP69TL7WK44Pur7bdq7"

    def __init__(self, config=None):
        super().__init__(config)
        # Substituir sessão por cloudscraper para bypass do Cloudflare
        try:
            import cloudscraper  # type: ignore
            self.session = cloudscraper.create_scraper(
                browser={"browser": "chrome", "platform": "windows", "mobile": False}
            )
            logger.info("[BH-SCRAPER] cloudscraper session criada")
        except ImportError:
            logger.warning("[BH-SCRAPER] cloudscraper não instalado — usando requests")

    def is_configured(self) -> bool:
        return bool(BUGHUNT_EMAIL and BUGHUNT_PASSWORD)

    # ── Captcha solving (CapSolver SDK — madmax-hunter compat) ──────
    def _solve_captcha_capsolver(self) -> str:
        """Solve reCAPTCHA v2 via CapSolver (ProxyLess)."""
        api_key = os.getenv("CAPSOLVER_API_KEY", "")
        if not api_key:
            logger.info("[BH-SCRAPER] CAPSOLVER_API_KEY not set — skipping")
            return ""

        try:
            import capsolver  # type: ignore
            capsolver.api_key = api_key
        except ImportError:
            logger.error("[BH-SCRAPER] capsolver package not installed")
            return ""

        for attempt in range(1, 4):
            try:
                logger.info("[BH-SCRAPER] CapSolver attempt %d...", attempt)
                sol = capsolver.solve({
                    "type": "ReCaptchaV2TaskProxyLess",
                    "websiteURL": self.ADMIN,
                    "websiteKey": self.SITE_KEY,
                })
                token = sol.get("gRecaptchaResponse", "")
                if token:
                    logger.warning("[BH-SCRAPER] CapSolver OK len=%d", len(token))
                    return token
            except Exception as exc:
                logger.warning("[BH-SCRAPER] CapSolver attempt %d failed: %s", attempt, exc)
                time.sleep(5)
        return ""

    # ── Auth via API (with captcha token) ────────────────
    def _auth_api(self, captcha: str) -> str:
        """Authenticate via BugHunt API with captcha token."""
        logger.info("[BH-SCRAPER] Authenticating via API...")
        UA = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
        try:
            # Obter cookies Cloudflare para o auth domain via cloudscraper
            auth_base = self.AUTH_URL.rsplit("/", 1)[0]  # https://auth.bughunt.com.br
            try:
                self.session.get(auth_base, timeout=15)
                self.session.get(self.ADMIN, timeout=15)
            except Exception:
                pass

            resp = self.session.post(
                self.AUTH_URL,
                json={
                    "username": BUGHUNT_EMAIL,
                    "password": BUGHUNT_PASSWORD,
                    "tokenRecaptcha": captcha,
                },
                headers={
                    "Origin": self.ADMIN,
                    "Referer": f"{self.ADMIN}/login",
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
                    "User-Agent": UA,
                    "sec-fetch-dest": "empty",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-site": "same-site",
                },
                timeout=_TIMEOUT,
            )
            if resp.status_code in (200, 201):
                try:
                    data = resp.json()
                except ValueError:
                    logger.error("[BH-SCRAPER] Auth response not JSON: %s", resp.text[:120])
                    return ""
                token = data.get("access_token", "")
                if token:
                    logger.info("[BH-SCRAPER] Login successful")
                    return token
                logger.error("[BH-SCRAPER] No access_token in response: %s", str(data)[:120])
                return ""
            logger.error("[BH-SCRAPER] Auth %d: %s", resp.status_code, resp.text[:120])
        except requests.RequestException as e:
            logger.error("[BH-SCRAPER] Auth request error: %s", e)
        return ""

    # ── Login flow: capsolver → no-captcha fallback ──────
    def _login(self) -> str | None:
        """Login to BugHunt. Tries CapSolver first, then without captcha."""
        # 1. Try CapSolver
        captcha = self._solve_captcha_capsolver()
        if captcha:
            token = self._auth_api(captcha)
            if token:
                return token

        # 2. Try without captcha (may work for some accounts)
        logger.info("[BH-SCRAPER] Trying login without captcha...")
        token = self._auth_api("")
        if token:
            return token

        logger.error("[BH-SCRAPER] All login methods failed")
        return None

    # ── Fetch programs list ──────────────────────────────
    def _fetch_programs(self, token: str) -> list[dict]:
        """Fetch programs from /program/list/filter (madmax-hunter compat)."""
        url = f"{self.API_BASE}/program/list/filter?page=1&pageSize=100"
        headers = {
            "Authorization": f"Bearer {token}",
            "Origin": self.ADMIN,
        }
        try:
            logger.info("[BH-SCRAPER] Fetching programs...")
            resp = self.session.get(url, headers=headers, timeout=_TIMEOUT)
            if resp.status_code != 200:
                logger.error("[BH-SCRAPER] API %d: %s", resp.status_code, resp.text[:80])
                return []
            return self._extract_items(resp.json())
        except Exception as e:
            logger.error("[BH-SCRAPER] Programs fetch error: %s", e)
            return []

    # ── Fetch scope details ──────────────────────────────
    def _fetch_scope(self, token: str, pid: str) -> str:
        """Get scope domains from /program/details/{pid} (madmax-hunter compat)."""
        url = f"{self.API_BASE}/program/details/{pid}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Origin": self.ADMIN,
        }
        try:
            resp = self.session.get(url, headers=headers, timeout=_TIMEOUT)
            if resp.status_code != 200:
                return ""
            detail = resp.json()
            scope_list = detail.get("scope", [])
            if not isinstance(scope_list, list):
                return ""
            domains = []
            for s in scope_list:
                if isinstance(s, dict):
                    desc = s.get("description", "")
                    if desc:
                        domains.append(desc)
                elif isinstance(s, str) and s:
                    domains.append(s)
            return ", ".join(domains)
        except Exception:
            return ""

    # ── Convert raw items to Program list ────────────────
    def _to_programs(self, items: list[dict]) -> list[Program]:
        """Convert raw API items to Program objects (madmax-hunter compat)."""
        programs: list[Program] = []
        for it in items:
            if not isinstance(it, dict):
                continue
            name = str(it.get("name") or it.get("title") or "")
            if not name:
                continue
            pid = str(it.get("_id") or it.get("id") or "")
            ptype = str(it.get("type", ""))
            programs.append(Program(
                name=name,
                url=f"{self.ADMIN}/program/{pid}",
                platform="bughunt",
                program_id=pid,
                scope=[],
                program_type=ptype,
                reward_type=ptype or "bounty",
            ))
        return programs

    # ── Main fetch ───────────────────────────────────────
    def fetch(self) -> list[Program]:
        if not self.is_configured():
            logger.warning("[BH-SCRAPER] Credentials not set — skipping")
            return []

        logger.info("[BH-SCRAPER] Logging in...")
        token = self._login()
        if not token:
            return []

        raw_items = self._fetch_programs(token)
        programs = self._to_programs(raw_items)

        # Fetch scope details for each program
        logger.info("[BH-SCRAPER] Fetching scope details...")
        for prog in programs:
            if not prog.program_id:
                continue
            scope = self._fetch_scope(token, prog.program_id)
            if scope:
                prog.scope = [s.strip() for s in scope.split(",") if s.strip()]

        logger.info("[BH-SCRAPER] %d programs fetched", len(programs))
        return programs


# ═══════════════════════════════════════════════════════════════
# Scraper Registry
# ═══════════════════════════════════════════════════════════════

SCRAPERS: dict[str, type[BaseScraper]] = {
    "hackerone": HackerOneScraper,
    "bugcrowd": BugcrowdScraper,
    "intigriti": IntigritiScraper,
    "yeswehack": YesWeHackScraper,
    "bughunt": BugHuntScraper,
}


# ═══════════════════════════════════════════════════════════════
# Watcher — change detection & persistence
# ═══════════════════════════════════════════════════════════════

_watcher_stats: dict[str, Any] = {
    "last_check": None,
    "total_checks": 0,
    "programs_found": {},
    "new_programs": 0,
    "scope_changes": 0,
    "errors": 0,
    "running": False,
}
_watcher_lock = threading.Lock()


def get_watcher_stats() -> dict[str, Any]:
    with _watcher_lock:
        return dict(_watcher_stats)


def _inc_watcher(key: str, n: int = 1) -> None:
    with _watcher_lock:
        _watcher_stats[key] = _watcher_stats.get(key, 0) + n


def _cache_programs(platform: str, programs: list[Program]) -> None:
    """Cache scraped program list in Redis (TTL 2h)."""
    try:
        r = get_redis()
        if r is None:
            return
        data = [p.to_dict() for p in programs]
        r.setex(
            f"watcher:programs:{platform}",
            7200,
            json.dumps(data, default=str),
        )
    except Exception as e:
        logger.debug("[WATCHER] Cache write error: %s", e)


def _get_cached_programs(platform: str) -> list[dict] | None:
    """Read cached programs from Redis."""
    try:
        r = get_redis()
        if r is None:
            return None
        raw = r.get(f"watcher:programs:{platform}")
        if raw:
            return json.loads(raw)
        return None
    except Exception:
        return None


def _detect_changes(
    platform: str,
    new_programs: list[Program],
    old_programs: list[dict] | None,
) -> dict[str, Any]:
    """
    Compare new programs with cached ones to detect:
      - New programs (not in cache)
      - Scope changes (scope hash differs)
      - Removed programs
    """
    changes: dict[str, Any] = {
        "new": [],
        "scope_changed": [],
        "removed": [],
    }

    if old_programs is None:
        # First run — all programs are "new" conceptually, but don't alert
        return changes

    old_map: dict[str, dict] = {}
    for op in old_programs:
        key = op.get("program_id") or op.get("name", "")
        if key:
            old_map[key] = op

    new_keys: set[str] = set()
    for prog in new_programs:
        key = prog.program_id or prog.name
        new_keys.add(key)

        if key not in old_map:
            changes["new"].append(prog.to_dict())
        else:
            old_scope = set(old_map[key].get("scope", []))
            new_scope = set(prog.scope)
            if old_scope != new_scope:
                changes["scope_changed"].append({
                    "program": prog.to_dict(),
                    "added_scope": list(new_scope - old_scope),
                    "removed_scope": list(old_scope - new_scope),
                })

    for old_key in old_map:
        if old_key not in new_keys:
            changes["removed"].append(old_map[old_key])

    return changes


def _persist_programs(programs: list[Program]) -> dict[str, int]:
    """Upsert programs into bounty_programs collection."""
    col = get_bounty_programs()
    imported = 0
    updated = 0

    for prog in programs:
        existing = col.find_one({
            "name": prog.name,
            "platform": prog.platform,
        })

        doc: dict[str, Any] = {
            "name": prog.name,
            "platform": prog.platform,
            "url": prog.url,
            "program_id": prog.program_id,
            "in_scope": prog.scope,
            "out_of_scope": prog.out_of_scope,
            "has_bounty": prog.reward_type == "bounty",
            "bounty_max": prog.max_bounty,
            "bounty_min": prog.min_bounty,
            "reward_type": prog.reward_type,
            "program_type": prog.program_type,
            "submission_state": prog.submission_state,
            "source": "platform-scraper",
            "last_api_sync": datetime.utcnow().isoformat(),
        }

        if existing:
            old_scope = set(existing.get("in_scope", []))
            new_scope = set(prog.scope)
            if old_scope != new_scope:
                doc["scope_changed"] = True
                doc["scope_change_detected"] = datetime.utcnow().isoformat()
                doc["previous_scope_count"] = len(old_scope)
            col.update_one({"_id": existing["_id"]}, {"$set": doc})
            updated += 1
        else:
            doc["status"] = "active"
            doc["created_at"] = datetime.utcnow().isoformat()
            doc["first_seen"] = prog.first_seen or datetime.utcnow().isoformat()
            doc["stats"] = {}
            col.insert_one(doc)
            imported += 1

    return {"imported": imported, "updated": updated}


def _record_changes(platform: str, changes: dict[str, Any]) -> None:
    """Record changes in bounty_changes collection."""
    col = get_bounty_changes()
    now = datetime.utcnow().isoformat()

    for new_prog in changes.get("new", []):
        col.insert_one({
            "platform": platform,
            "type": "new_program",
            "program": new_prog,
            "timestamp": now,
        })

    for sc in changes.get("scope_changed", []):
        col.insert_one({
            "platform": platform,
            "type": "scope_change",
            "program": sc["program"],
            "added_scope": sc["added_scope"],
            "removed_scope": sc["removed_scope"],
            "timestamp": now,
        })

    for removed in changes.get("removed", []):
        col.insert_one({
            "platform": platform,
            "type": "program_removed",
            "program": removed,
            "timestamp": now,
        })


def _notify(platform: str, changes: dict[str, Any]) -> None:
    """Send notifications for detected changes."""
    new_count = len(changes.get("new", []))
    scope_count = len(changes.get("scope_changed", []))
    removed_count = len(changes.get("removed", []))

    if new_count == 0 and scope_count == 0 and removed_count == 0:
        return

    msg_lines = [f"🔔 **Platform Watcher — {platform.upper()}**"]
    if new_count:
        msg_lines.append(f"  ✅ {new_count} new program(s)")
        for p in changes["new"][:5]:
            msg_lines.append(f"    • {p['name']} — {p.get('url', '')}")
    if scope_count:
        msg_lines.append(f"  🔄 {scope_count} scope change(s)")
        for sc in changes["scope_changed"][:3]:
            name = sc["program"]["name"]
            added = len(sc.get("added_scope", []))
            removed = len(sc.get("removed_scope", []))
            msg_lines.append(f"    • {name}: +{added}/-{removed} scopes")
    if removed_count:
        msg_lines.append(f"  ❌ {removed_count} removed program(s)")

    message = "\n".join(msg_lines)
    logger.info("[WATCHER] %s", message)

    # Discord
    if DISCORD_WEBHOOK:
        try:
            requests.post(
                DISCORD_WEBHOOK,
                json={"content": message},
                timeout=10,
            )
        except Exception as e:
            logger.debug("[WATCHER] Discord notify error: %s", e)

    # Slack
    if SLACK_WEBHOOK:
        try:
            requests.post(
                SLACK_WEBHOOK,
                json={"text": message},
                timeout=10,
            )
        except Exception as e:
            logger.debug("[WATCHER] Slack notify error: %s", e)


# ═══════════════════════════════════════════════════════════════
# Public API — run checks
# ═══════════════════════════════════════════════════════════════

def run_check(
    platforms: list[str] | None = None,
    program_filter: ProgramFilter | None = None,
) -> dict[str, Any]:
    """
    Run a full check across all configured platforms.
    Returns summary of findings and changes.
    """
    platforms = platforms or WATCHER_PLATFORMS
    pf = program_filter or ProgramFilter()
    results: dict[str, Any] = {}

    for platform_name in platforms:
        scraper_cls = SCRAPERS.get(platform_name)
        if not scraper_cls:
            logger.warning("[WATCHER] Unknown platform: %s", platform_name)
            continue

        scraper = scraper_cls()
        if not scraper.is_configured():
            logger.info("[WATCHER] %s not configured — skipping", platform_name)
            results[platform_name] = {"status": "skipped", "reason": "not_configured"}
            continue

        t0 = time.time()
        try:
            programs = scraper.fetch()
        except Exception as e:
            logger.error("[WATCHER] %s fetch error: %s", platform_name, e)
            _inc_watcher("errors")
            results[platform_name] = {"status": "error", "error": str(e)}
            continue

        # Apply filter
        if pf:
            programs = [p for p in programs if pf.matches(p)]

        elapsed = time.time() - t0

        # Detect changes
        old_cached = _get_cached_programs(platform_name)
        changes = _detect_changes(platform_name, programs, old_cached)

        # Cache new results
        _cache_programs(platform_name, programs)

        # Persist to DB
        persist_result = _persist_programs(programs)

        # Record changes
        _record_changes(platform_name, changes)

        # Notify
        _notify(platform_name, changes)

        # Update stats
        with _watcher_lock:
            _watcher_stats["programs_found"][platform_name] = len(programs)
        _inc_watcher("new_programs", len(changes.get("new", [])))
        _inc_watcher("scope_changes", len(changes.get("scope_changed", [])))

        results[platform_name] = {
            "status": "ok",
            "programs": len(programs),
            "new": len(changes.get("new", [])),
            "scope_changed": len(changes.get("scope_changed", [])),
            "removed": len(changes.get("removed", [])),
            "imported": persist_result["imported"],
            "updated": persist_result["updated"],
            "elapsed_seconds": round(elapsed, 1),
        }

        logger.info(
            "[WATCHER] %s: %d programs, %d new, %d scope changes (%.1fs)",
            platform_name, len(programs),
            len(changes.get("new", [])),
            len(changes.get("scope_changed", [])),
            elapsed,
        )

    with _watcher_lock:
        _watcher_stats["last_check"] = datetime.utcnow().isoformat()
        _watcher_stats["total_checks"] += 1

    return results


def run_check_single(platform_name: str) -> dict[str, Any]:
    """Run check on a single platform."""
    return run_check(platforms=[platform_name])


def get_cached_platform_programs(platform: str) -> list[dict]:
    """Get cached programs for a platform (for API)."""
    cached = _get_cached_programs(platform)
    return cached or []


def get_all_cached_programs() -> dict[str, list[dict]]:
    """Get all cached programs across platforms."""
    result: dict[str, list[dict]] = {}
    for platform_name in SCRAPERS:
        cached = _get_cached_programs(platform_name)
        if cached:
            result[platform_name] = cached
    return result


def get_configured_platforms() -> list[dict[str, Any]]:
    """Return list of platforms with their configuration status."""
    platforms = []
    for name, cls in SCRAPERS.items():
        scraper = cls()
        platforms.append({
            "name": name,
            "configured": scraper.is_configured(),
            "enabled": name in WATCHER_PLATFORMS,
        })
    return platforms


# ═══════════════════════════════════════════════════════════════
# Background watcher loop
# ═══════════════════════════════════════════════════════════════

def _watcher_loop() -> None:
    """Background loop that periodically runs the platform check."""
    time.sleep(60)  # Wait for other services to start
    logger.info(
        "[WATCHER] Background loop started (interval=%ds, platforms=%s)",
        WATCHER_INTERVAL, ",".join(WATCHER_PLATFORMS),
    )

    with _watcher_lock:
        _watcher_stats["running"] = True

    while True:
        try:
            run_check()
        except Exception as e:
            logger.error("[WATCHER] Loop error: %s", e)
            _inc_watcher("errors")

        time.sleep(WATCHER_INTERVAL)


def start_platform_watcher() -> None:
    """Start the background platform watcher thread."""
    if not WATCHER_ENABLED:
        logger.info("[WATCHER] Disabled (PLATFORM_WATCHER_ENABLED=false)")
        return

    # Check if at least one platform is configured
    any_configured = False
    for name in WATCHER_PLATFORMS:
        cls = SCRAPERS.get(name)
        if cls and cls().is_configured():
            any_configured = True
            break

    if not any_configured:
        logger.info("[WATCHER] No platforms configured — watcher idle (will check passively)")

    t = threading.Thread(target=_watcher_loop, daemon=True)
    t.start()
    logger.info("[WATCHER] Platform watcher active")
