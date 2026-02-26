"""
Integração com Bug Scraper (HackerOne / Bugcrowd) para descoberta automática
de programas de bug bounty.

Este módulo é opcional e só roda se BUG_SCRAPER_PATH estiver configurado
ou o caminho padrão existir (/opt/Bug_Scraper/bug-scraper.py).

Esperamos que a ferramenta produza uma saída em JSON (uma linha por programa).
Como cada instalação pode ser diferente, ajuste:
  - BUG_SCRAPER_PATH
  - BUG_SCRAPER_ARGS
para combinar com a sua CLI real do Bug Scraper.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from datetime import datetime
from typing import Any

from app.database import get_bounty_programs

logger = logging.getLogger("scanner.bug_scraper")


BUG_SCRAPER_PATH = os.getenv("BUG_SCRAPER_PATH", "/opt/Bug_Scraper/bug-scraper.py")
BUG_SCRAPER_ARGS = os.getenv("BUG_SCRAPER_ARGS", "--mode discovery --output json")
BUG_SCRAPER_TIMEOUT = int(os.getenv("BUG_SCRAPER_TIMEOUT", "300"))


def _normalize_scope_items(items: list[str]) -> list[str]:
    """
    Normaliza ativos de escopo coletados (domínios / CIDRs) em uma lista
    deduplicada e limpa. Implementação equivalente à usada no main.py.
    """
    out: list[str] = []
    seen: set[str] = set()
    for raw in items:
        s = (raw or "").strip().lower()
        if not s:
            continue
        s = s.split("#", 1)[0].strip()
        if not s:
            continue

        if "://" in s:
            try:
                from urllib.parse import urlparse

                s = urlparse(s).hostname or s
            except Exception:
                pass
        s = s.split("/", 1)[0].strip()

        wildcard_prefix = ""
        if s.startswith("*."):
            wildcard_prefix = "*."
            s = s[2:]

        if not s:
            continue
        try:
            import ipaddress

            net = ipaddress.ip_network(s, strict=False)
            normalized = str(net)
        except ValueError:
            import re

            if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", s):
                continue
            normalized = wildcard_prefix + s

        if normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


def _build_bug_scraper_cmd() -> list[str] | None:
    if not BUG_SCRAPER_PATH:
        logger.info("[BugScraper] BUG_SCRAPER_PATH não configurado; integração desabilitada.")
        return None
    if not os.path.exists(BUG_SCRAPER_PATH):
        logger.warning("[BugScraper] Caminho não encontrado: %s", BUG_SCRAPER_PATH)
        return None
    args = [a for a in BUG_SCRAPER_ARGS.split(" ") if a]
    return ["python3", BUG_SCRAPER_PATH, *args]


def fetch_new_programs_from_bug_scraper() -> list[dict[str, Any]]:
    """
    Executa o Bug Scraper e retorna uma lista de programas em formato
    aproximado ao schema da collection bounty_programs.

    A saída esperada é uma linha por programa em JSON. Caso o formato
    seja diferente, ajuste este parser à sua realidade.
    """
    cmd = _build_bug_scraper_cmd()
    if not cmd:
        return []

    logger.info("[BugScraper] Executando: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=BUG_SCRAPER_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        logger.error("[BugScraper] Timeout após %ss", BUG_SCRAPER_TIMEOUT)
        return []
    except FileNotFoundError:
        logger.error("[BugScraper] python3 ou script não encontrado.")
        return []
    except Exception as e:
        logger.error("[BugScraper] Falha ao executar: %s", e)
        return []

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        logger.error("[BugScraper] retorno=%s stderr=%s", result.returncode, stderr[:500])
        return []

    programs: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            # Se não for JSON por linha, você pode adaptar aqui para outro formato.
            continue

        name = (data.get("name") or "").strip()
        url = (data.get("url") or "").strip()
        if not name and not url:
            continue

        platform = (data.get("platform") or "hackerone").strip().lower()
        raw_in_scope = data.get("in_scope") or data.get("in-scope") or []
        raw_out_scope = data.get("out_of_scope") or data.get("out-of-scope") or []
        if isinstance(raw_in_scope, str):
            raw_in_scope = [raw_in_scope]
        if isinstance(raw_out_scope, str):
            raw_out_scope = [raw_out_scope]

        in_scope = _normalize_scope_items([str(x) for x in raw_in_scope])
        out_of_scope = _normalize_scope_items([str(x) for x in raw_out_scope])

        program_doc: dict[str, Any] = {
            "name": name or url,
            "platform": platform,
            "url": url,
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "status": "active",
            "created_at": datetime.utcnow(),
            "stats": {},
        }
        programs.append(program_doc)

    logger.info("[BugScraper] %d programas coletados da saída.", len(programs))
    return programs


def sync_bug_scraper_programs() -> int:
    """
    Busca novos programas via Bug Scraper e insere no MongoDB
    se ainda não existirem (match por name+url).

    Retorna a quantidade de programas inseridos.
    """
    novos = fetch_new_programs_from_bug_scraper()
    if not novos:
        return 0

    col = get_bounty_programs()
    inseridos = 0
    for prog in novos:
        name = prog.get("name") or ""
        url = prog.get("url") or ""
        existing = None
        if name and url:
            existing = col.find_one({"name": name, "url": url})
        elif name:
            existing = col.find_one({"name": name})
        elif url:
            existing = col.find_one({"url": url})

        if existing:
            continue
        col.insert_one(prog)
        inseridos += 1

    logger.info("[BugScraper] %d novos programas inseridos no bounty_programs", inseridos)
    return inseridos

