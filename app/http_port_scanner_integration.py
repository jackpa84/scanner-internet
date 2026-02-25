"""
Integração opcional com HTTP Port Scanner (HackerOne Edition).

Este módulo NÃO é obrigatório para o funcionamento do sistema.
Ele só roda se HTTP_PORT_SCANNER_ENABLED=true e o caminho do script existir.

Por padrão, assume o repositório:
  /opt/HTTP-Port-Scanner-HackerOne-Edition/scanner.py

e que a ferramenta consiga produzir saída em JSON (uma linha por porta).
Adapte HTTP_PORT_SCANNER_ARGS conforme a CLI real.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Any

logger = logging.getLogger("scanner.http_port_scanner")


HTTP_PORT_SCANNER_PATH = os.getenv(
    "HTTP_PORT_SCANNER_PATH",
    "/opt/HTTP-Port-Scanner-HackerOne-Edition/scanner.py",
)
HTTP_PORT_SCANNER_ARGS = os.getenv(
    "HTTP_PORT_SCANNER_ARGS",
    "--json --threads 30",
)
HTTP_PORT_SCANNER_TIMEOUT = int(os.getenv("HTTP_PORT_SCANNER_TIMEOUT", "70"))
HTTP_PORT_SCANNER_ENABLED = os.getenv("HTTP_PORT_SCANNER_ENABLED", "false").lower() in (
    "1",
    "true",
    "yes",
)


def _build_http_scanner_cmd(target: str) -> list[str] | None:
    if not HTTP_PORT_SCANNER_ENABLED:
        return None
    if not HTTP_PORT_SCANNER_PATH:
        logger.debug("[HTTP-Scanner] Caminho não configurado; desabilitado.")
        return None
    if not os.path.exists(HTTP_PORT_SCANNER_PATH):
        logger.warning("[HTTP-Scanner] Caminho não encontrado: %s", HTTP_PORT_SCANNER_PATH)
        return None

    base_args = [a for a in HTTP_PORT_SCANNER_ARGS.split(" ") if a]
    # Muitas CLIs usam algo como "--target" ou "-t"; aqui assumimos argumento posicional simples.
    return ["python3", HTTP_PORT_SCANNER_PATH, *base_args, target]


def run_http_port_scanner(target: str, timeout: int | None = None) -> list[dict[str, Any]]:
    """
    Executa o HTTP Port Scanner em um alvo (IP ou domínio).
    Retorna lista de dicionários com informações por porta.

    Se desabilitado ou se algo falhar, retorna lista vazia.
    """
    cmd = _build_http_scanner_cmd(target)
    if not cmd:
        return []

    eff_timeout = timeout or HTTP_PORT_SCANNER_TIMEOUT
    logger.info("[HTTP-Scanner] target=%s cmd=%s", target, " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=eff_timeout,
        )
    except subprocess.TimeoutExpired:
        logger.warning("[HTTP-Scanner] timeout em %ss para %s", eff_timeout, target)
        return []
    except FileNotFoundError:
        logger.error("[HTTP-Scanner] python3 ou script não encontrado.")
        return []
    except Exception as e:
        logger.error("[HTTP-Scanner] erro ao executar em %s: %s", target, e)
        return []

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        logger.warning(
            "[HTTP-Scanner] retorno=%s para %s stderr=%s",
            result.returncode,
            target,
            stderr[:300],
        )
        # Ainda assim tentamos parsear stdout se existir.

    findings: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        findings.append(obj)

    logger.info("[HTTP-Scanner] %d entradas para %s", len(findings), target)
    return findings

