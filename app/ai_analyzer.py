"""
AI-powered analysis for bug bounty hunting.

Supports multiple LLM providers:
  - OpenAI (GPT-4o, GPT-4o-mini)
  - Anthropic (Claude 3.5 Sonnet)
  - Ollama (local, free — llama3, mistral, etc.)

Use cases:
  1. Report Writer: professional H1 reports from raw findings
  2. Finding Classifier: true positive vs false positive
  3. Response Analyzer: detect vulns in HTTP responses
  4. Scope Parser: understand program scope from text
  5. JS Code Analyzer: find secrets and logic flaws in JS
"""

import json
import logging
import os
import re
import time
from typing import Any

import requests

logger = logging.getLogger("scanner.ai")

AI_PROVIDER = os.getenv("AI_PROVIDER", "").strip().lower()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "").strip()
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6").strip()
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434").strip()
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3").strip()

AI_ENABLED = AI_PROVIDER in ("openai", "anthropic", "ollama")
AI_MAX_TOKENS = int(os.getenv("AI_MAX_TOKENS", "4000"))
AI_TEMPERATURE = float(os.getenv("AI_TEMPERATURE", "0.3"))


def _extract_json(text: str, expect_array: bool = False) -> Any:
    """Robustly extract JSON from LLM output.

    Handles:
     - <think>...</think> blocks (DeepSeek-R1)
     - ```json ... ``` markdown fences
     - Trailing commas
     - Text before/after the JSON
    """
    if not text:
        return None

    # 1. Strip <think>...</think> blocks (DeepSeek-R1)
    cleaned = re.sub(r'<think>[\s\S]*?</think>', '', text, flags=re.IGNORECASE).strip()

    # 2. Strip markdown code fences
    fence_match = re.search(r'```(?:json)?\s*\n?([\s\S]*?)\n?\s*```', cleaned)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    # 3. Try direct parse first
    try:
        parsed = json.loads(cleaned)
        if expect_array and isinstance(parsed, list):
            return parsed
        if not expect_array and isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, (dict, list)):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass

    # 4. Extract first JSON object or array
    if expect_array:
        patterns = [r'\[[\s\S]*\]', r'\{[\s\S]*\}']
    else:
        patterns = [r'\{[\s\S]*\}', r'\[[\s\S]*\]']

    for pattern in patterns:
        match = re.search(pattern, cleaned)
        if match:
            candidate = match.group()
            # Fix trailing commas before } or ]
            candidate = re.sub(r',\s*([}\]])', r'\1', candidate)
            try:
                parsed = json.loads(candidate)
                if expect_array and isinstance(parsed, list):
                    return parsed
                if not expect_array and isinstance(parsed, dict):
                    return parsed
                return parsed
            except (json.JSONDecodeError, ValueError):
                continue

    logger.warning("[AI] Failed to extract JSON from response (%d chars): %s...", len(text), text[:200])
    return None


_stats = {
    "requests": 0,
    "tokens_used": 0,
    "errors": 0,
    "reports_generated": 0,
    "findings_classified": 0,
    "responses_analyzed": 0,
    "targets_prioritized": 0,
    "program_reports_generated": 0,
}

# ── In-memory history of all AI operations (ring-buffer, max 200) ──
_history: list[dict[str, Any]] = []
_MAX_HISTORY = 200
_history_id = 0


def _record(op_type: str, input_summary: str, result: Any, status: str, duration_ms: int) -> None:
    """Append an entry to the AI operations history."""
    global _history_id
    _history_id += 1
    entry = {
        "id": _history_id,
        "type": op_type,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": status,
        "input": input_summary,
        "result": result,
        "duration_ms": duration_ms,
        "model": _get_model(),
    }
    _history.append(entry)
    if len(_history) > _MAX_HISTORY:
        _history[:] = _history[-_MAX_HISTORY:]


def get_ai_history(limit: int = 50) -> list[dict[str, Any]]:
    """Return recent AI operation history, newest first."""
    return list(reversed(_history[-limit:]))


def get_ai_stats() -> dict[str, Any]:
    return {**_stats, "provider": AI_PROVIDER, "model": _get_model(), "enabled": AI_ENABLED}


def _get_model() -> str:
    if AI_PROVIDER == "openai":
        return OPENAI_MODEL
    if AI_PROVIDER == "anthropic":
        return ANTHROPIC_MODEL
    if AI_PROVIDER == "ollama":
        return OLLAMA_MODEL
    return ""


def _call_llm(system_prompt: str, user_prompt: str, max_tokens: int = 0) -> str | None:
    """Call the configured LLM provider and return the text response."""
    if not AI_ENABLED:
        return None

    if not max_tokens:
        max_tokens = AI_MAX_TOKENS

    _stats["requests"] += 1

    try:
        if AI_PROVIDER == "openai":
            return _call_openai(system_prompt, user_prompt, max_tokens)
        if AI_PROVIDER == "anthropic":
            return _call_anthropic(system_prompt, user_prompt, max_tokens)
        if AI_PROVIDER == "ollama":
            return _call_ollama(system_prompt, user_prompt, max_tokens)
    except Exception as e:
        logger.error("[AI] LLM call failed (%s): %s", AI_PROVIDER, e)
        _stats["errors"] += 1

    return None


def _call_openai(system: str, user: str, max_tokens: int) -> str | None:
    if not OPENAI_API_KEY:
        return None

    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": OPENAI_MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": AI_TEMPERATURE,
        },
        timeout=60,
    )
    if resp.status_code != 200:
        logger.warning("[AI] OpenAI %d: %s", resp.status_code, resp.text[:200])
        _stats["errors"] += 1
        return None

    data = resp.json()
    usage = data.get("usage", {})
    _stats["tokens_used"] += usage.get("total_tokens", 0)
    return data["choices"][0]["message"]["content"]


def _call_anthropic(system: str, user: str, max_tokens: int) -> str | None:
    if not ANTHROPIC_API_KEY:
        return None

    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        json={
            "model": ANTHROPIC_MODEL,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "temperature": AI_TEMPERATURE,
        },
        timeout=60,
    )
    if resp.status_code != 200:
        logger.warning("[AI] Anthropic %d: %s", resp.status_code, resp.text[:200])
        _stats["errors"] += 1
        return None

    data = resp.json()
    usage = data.get("usage", {})
    _stats["tokens_used"] += usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
    content = data.get("content", [])
    return content[0]["text"] if content else None


def _call_ollama(system: str, user: str, max_tokens: int) -> str | None:
    resp = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json={
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": AI_TEMPERATURE,
            },
        },
        timeout=120,
    )
    if resp.status_code != 200:
        logger.warning("[AI] Ollama %d: %s", resp.status_code, resp.text[:200])
        _stats["errors"] += 1
        return None

    data = resp.json()
    return data.get("message", {}).get("content")


# ═══════════════════════════════════════════════════════════════
# 1. AI Report Writer
# ═══════════════════════════════════════════════════════════════

def ai_write_report(
    domain: str,
    findings: list[dict],
    program_name: str = "",
    program_url: str = "",
) -> dict[str, str] | None:
    """Use AI to generate a professional HackerOne report from raw findings."""
    if not AI_ENABLED or not findings:
        return None
    _t0 = time.time()

    system = """You are an expert bug bounty hunter writing a report for HackerOne.
Write professional, clear, and impactful vulnerability reports that maximize bounty payouts.
Your reports should include:
- A clear, specific title
- Detailed vulnerability description with technical context
- Step-by-step reproduction instructions
- Business impact analysis explaining real-world consequences
- CVSS 3.1 vector string
- Specific remediation recommendations
Keep the tone professional. Use Markdown formatting.
Write in English."""

    findings_text = "\n".join([
        f"- [{f.get('severity', 'medium').upper()}] {f.get('title', '?')}"
        f"{' | Evidence: ' + f['evidence'][:150] if f.get('evidence') else ''}"
        for f in findings[:10]
    ])

    user = f"""Write a HackerOne vulnerability report for these findings:

Target: {domain}
Program: {program_name}
Program URL: {program_url}

Findings:
{findings_text}

Generate a JSON response with these fields:
- "title": report title (max 200 chars)
- "vulnerability_information": full report body in Markdown
- "impact": business impact paragraph
- "severity_rating": one of critical/high/medium/low
- "cvss_vector": CVSS 3.1 vector string

Return ONLY valid JSON, no other text."""

    response = _call_llm(system, user, max_tokens=3000)
    if not response:
        return None

    _stats["reports_generated"] += 1
    _dur = int((time.time() - _t0) * 1000)

    result = _extract_json(response, expect_array=False)
    if isinstance(result, dict) and "title" in result:
        _record("write_report", f"{domain} ({len(findings)} findings)", {"title": result.get("title"), "severity": result.get("severity_rating")}, "success", _dur)
        return result

    fallback = {
        "title": f"Security findings on {domain}",
        "vulnerability_information": response,
        "impact": "See report body for impact analysis.",
        "severity_rating": findings[0].get("severity", "medium"),
    }
    _record("write_report", f"{domain} ({len(findings)} findings)", {"title": fallback["title"], "severity": fallback["severity_rating"], "fallback": True}, "partial", _dur)
    return fallback


# ═══════════════════════════════════════════════════════════════
# 2. AI Finding Classifier (true positive vs false positive)
# ═══════════════════════════════════════════════════════════════

def ai_classify_finding(finding: dict, response_data: dict | None = None) -> dict[str, Any] | None:
    """Use AI to classify a finding as true/false positive and assess severity."""
    if not AI_ENABLED:
        return None
    _t0 = time.time()

    system = """You are a senior security researcher. Analyze vulnerability findings and determine:
1. Is this a TRUE POSITIVE or FALSE POSITIVE?
2. What is the real severity? (critical/high/medium/low/info)
3. Is this worth reporting to a bug bounty program?
4. Confidence level (0-100)

Be skeptical — many automated findings are false positives.
Missing security headers alone are usually NOT worth reporting.
Focus on exploitable vulnerabilities with real impact."""

    finding_text = json.dumps(finding, indent=2, default=str)[:2000]
    context = ""
    if response_data:
        context = f"\nHTTP Response context:\n{json.dumps(response_data, indent=2, default=str)[:1000]}"

    user = f"""Classify this security finding:

{finding_text}
{context}

Return JSON with:
- "classification": "true_positive" or "false_positive"
- "real_severity": actual severity
- "worth_reporting": true/false
- "confidence": 0-100
- "reasoning": brief explanation
- "suggested_title": improved title if worth reporting

Return ONLY valid JSON."""

    response = _call_llm(system, user, max_tokens=500)
    if not response:
        return None

    _stats["findings_classified"] += 1
    _dur = int((time.time() - _t0) * 1000)

    result = _extract_json(response, expect_array=False)
    if isinstance(result, dict) and "classification" in result:
        _record("classify_finding", f"{finding.get('code', '?')} — {finding.get('title', '?')[:60]}", {"classification": result.get("classification"), "severity": result.get("real_severity"), "confidence": result.get("confidence"), "worth": result.get("worth_reporting")}, "success", _dur)
        return result
    _record("classify_finding", f"{finding.get('code', '?')} — {finding.get('title', '?')[:60]}", None, "error", _dur)
    logger.warning("[AI] classify_finding: could not parse JSON from response")
    return None


def ai_classify_findings_batch(findings: list[dict]) -> list[dict]:
    """Classify multiple findings, filtering out false positives."""
    if not AI_ENABLED or not findings:
        return findings

    classified = []
    for finding in findings[:20]:
        result = ai_classify_finding(finding)
        if result:
            finding["ai_classification"] = result
            if result.get("classification") == "true_positive" and result.get("worth_reporting"):
                finding["ai_confidence"] = result.get("confidence", 50)
                if result.get("suggested_title"):
                    finding["ai_title"] = result["suggested_title"]
                classified.append(finding)
            else:
                logger.debug("[AI] Filtered out: %s (reason: %s)",
                             finding.get("title", "?"), result.get("reasoning", "?"))
        else:
            classified.append(finding)

        time.sleep(0.5)

    return classified


# ═══════════════════════════════════════════════════════════════
# 3. AI Response Analyzer
# ═══════════════════════════════════════════════════════════════

def ai_analyze_response(
    url: str,
    status_code: int,
    headers: dict[str, str],
    body: str,
    context: str = "",
) -> list[dict] | None:
    """Use AI to analyze an HTTP response for security issues."""
    if not AI_ENABLED:
        return None
    _t0 = time.time()

    system = """You are a web security expert analyzing HTTP responses for vulnerabilities.
Look for:
- Sensitive data leaks (API keys, tokens, passwords, PII)
- Error messages revealing internal details (stack traces, SQL errors, file paths)
- Authentication/authorization issues
- Insecure configurations
- Information disclosure
- Business logic issues
Only report REAL, EXPLOITABLE issues — not theoretical concerns."""

    headers_text = "\n".join(f"  {k}: {v}" for k, v in list(headers.items())[:30])

    user = f"""Analyze this HTTP response for security issues:

URL: {url}
Status: {status_code}
{f'Context: {context}' if context else ''}

Headers:
{headers_text}

Body (first 3000 chars):
{body[:3000]}

If you find security issues, return a JSON array of findings:
[{{"severity": "high", "code": "issue_code", "title": "Issue title", "evidence": "specific evidence"}}]

If no issues found, return: []
Return ONLY valid JSON array."""

    response = _call_llm(system, user, max_tokens=1000)
    if not response:
        return None

    _stats["responses_analyzed"] += 1
    _dur = int((time.time() - _t0) * 1000)

    result = _extract_json(response, expect_array=True)
    if isinstance(result, list):
        _record("analyze_response", f"{url} (HTTP {status_code})", {"findings_count": len(result), "findings": [f.get("title", f.get("code", "?")) for f in result[:5]]}, "success", _dur)
        return result
    _record("analyze_response", f"{url} (HTTP {status_code})", None, "error", _dur)
    return []


# ═══════════════════════════════════════════════════════════════
# 4. AI Scope Parser
# ═══════════════════════════════════════════════════════════════

def ai_parse_scope(program_description: str, policy_text: str = "") -> dict[str, Any] | None:
    """Use AI to parse a bounty program description and extract scope details."""
    if not AI_ENABLED:
        return None
    _t0 = time.time()

    system = """You are a bug bounty expert. Parse program descriptions and policies to extract:
- In-scope domains and assets
- Out-of-scope items
- Vulnerability types they care about
- Special rules or restrictions
- Bounty ranges
- Priority areas (what they want tested most)"""

    user = f"""Parse this bug bounty program and extract scope information:

Description:
{program_description[:3000]}

{f'Policy:{chr(10)}{policy_text[:2000]}' if policy_text else ''}

Return JSON with:
- "in_scope": list of in-scope domains/assets
- "out_of_scope": list of out-of-scope items
- "priority_vulns": list of vulnerability types they prioritize
- "restrictions": list of testing restrictions
- "bounty_range": {{"min": number, "max": number, "currency": "USD"}}
- "tips": list of tips for maximizing payout on this program

Return ONLY valid JSON."""

    response = _call_llm(system, user, max_tokens=1500)
    if not response:
        _record("parse_scope", f"desc={len(program_description)} chars", None, "error", int((time.time() - _t0) * 1000))
        return None
    _dur = int((time.time() - _t0) * 1000)

    result = _extract_json(response, expect_array=False)
    if isinstance(result, dict):
        _record("parse_scope", f"desc={len(program_description)} chars", {"in_scope": len(result.get("in_scope", [])), "out_of_scope": len(result.get("out_of_scope", []))}, "success", _dur)
        return result
    _record("parse_scope", f"desc={len(program_description)} chars", None, "error", _dur)
    return None


# ═══════════════════════════════════════════════════════════════
# 5. AI JavaScript Analyzer
# ═══════════════════════════════════════════════════════════════

def ai_analyze_javascript(js_code: str, source_url: str = "") -> list[dict] | None:
    """Use AI to analyze JavaScript code for secrets and vulnerabilities."""
    if not AI_ENABLED or not js_code:
        return None
    _t0 = time.time()

    system = """You are a security researcher analyzing JavaScript source code.
Look for:
- Hardcoded API keys, tokens, passwords, and secrets
- Internal API endpoints and URLs
- Authentication bypass opportunities
- Insecure data handling
- Debug/admin functionality
- Hardcoded credentials
- Sensitive business logic

Only report findings with HIGH confidence — actual secrets, not variable names."""

    user = f"""Analyze this JavaScript code for security issues:

Source: {source_url}

```javascript
{js_code[:8000]}
```

Return a JSON array of findings:
[{{"severity": "high", "code": "js_secret_type", "title": "Description", "evidence": "the actual secret or code snippet"}}]

If nothing found, return: []
Return ONLY valid JSON array."""

    response = _call_llm(system, user, max_tokens=1000)
    if not response:
        _record("analyze_js", f"{source_url or 'inline'} ({len(js_code)} chars)", None, "error", int((time.time() - _t0) * 1000))
        return None
    _dur = int((time.time() - _t0) * 1000)

    result = _extract_json(response, expect_array=True)
    if isinstance(result, list):
        _record("analyze_js", f"{source_url or 'inline'} ({len(js_code)} chars)", {"findings_count": len(result)}, "success", _dur)
        return result
    _record("analyze_js", f"{source_url or 'inline'} ({len(js_code)} chars)", None, "error", _dur)
    return []


# ═══════════════════════════════════════════════════════════════
# 6. AI Vulnerability Chain Analyzer
# ═══════════════════════════════════════════════════════════════

def ai_find_vuln_chains(findings: list[dict], domain: str) -> list[dict] | None:
    """Use AI to identify vulnerability chains that increase severity."""
    if not AI_ENABLED or len(findings) < 2:
        return None
    _t0 = time.time()

    system = """You are an expert bug bounty hunter specializing in vulnerability chaining.
Analyze multiple findings on the same target and identify how they can be CHAINED
together to create higher-impact attacks.

Examples:
- Open redirect + OAuth = token theft (medium -> critical)
- CORS misconfiguration + authenticated endpoint = data theft
- SSRF + cloud metadata = RCE
- XSS + CSRF = account takeover
- Info disclosure + brute force = unauthorized access"""

    findings_text = json.dumps(findings[:15], indent=2, default=str)[:3000]

    user = f"""Analyze these findings on {domain} for possible vulnerability chains:

{findings_text}

For each chain found, return JSON array:
[{{
  "chain_name": "descriptive name",
  "severity": "combined severity",
  "steps": ["step 1", "step 2", ...],
  "impact": "what the chain achieves",
  "findings_used": ["code1", "code2"]
}}]

If no chains possible, return: []
Return ONLY valid JSON array."""

    response = _call_llm(system, user, max_tokens=1500)
    if not response:
        _record("find_chains", f"{domain} ({len(findings)} findings)", None, "error", int((time.time() - _t0) * 1000))
        return None
    _dur = int((time.time() - _t0) * 1000)

    result = _extract_json(response, expect_array=True)
    if isinstance(result, list):
        _record("find_chains", f"{domain} ({len(findings)} findings)", {"chains_count": len(result), "chains": [c.get("chain_name") for c in result[:5]]}, "success", _dur)
        return result
    _record("find_chains", f"{domain} ({len(findings)} findings)", None, "error", _dur)
    return []


# ═══════════════════════════════════════════════════════════════
# 7. AI Recon Analysis
# ═══════════════════════════════════════════════════════════════

def ai_prioritize_targets(targets: list[dict], program_name: str = "") -> list[dict] | None:
    """Rank alive recon targets by attack priority using AI."""
    if not AI_ENABLED or not targets:
        return None

    system = """You are an expert bug bounty hunter deciding which targets to attack first.
Prioritize based on: number and severity of security findings, presence of high-value endpoints
(login, API, admin, payment), attack surface richness (parameterized URLs, wayback history,
crawled endpoints), technology stack signals in HTTP headers, and likelihood of real exploitability."""

    target_summaries = []
    for t in targets[:30]:
        rc = t.get("recon_checks") or {}
        findings = rc.get("findings", [])[:3]
        summary = {
            "domain": t.get("domain"),
            "risk_score": rc.get("risk_score", 0),
            "finding_count": rc.get("total_findings", 0),
            "top_findings": [{"severity": f.get("severity"), "code": f.get("code")} for f in findings],
            "wayback_count": len(t.get("wayback_urls") or []),
            "crawled_count": len(t.get("crawled_urls") or []),
            "param_count": len((t.get("paramspider") or {}).get("params", [])),
            "httpx_title": (t.get("httpx") or {}).get("title", ""),
            "status_code": (t.get("httpx") or {}).get("status_code"),
        }
        target_summaries.append(summary)

    user = f"""Prioritize these targets for bug bounty attacks on program "{program_name}":

{json.dumps(target_summaries, indent=2, default=str)[:4000]}

Return a JSON array ranked from highest to lowest priority:
[{{
  "domain": "domain.com",
  "priority_rank": 1,
  "attack_angle": "Why this is the best target",
  "key_findings": ["finding_code1"],
  "reasoning": "Brief justification"
}}]

Return ONLY valid JSON array."""

    response = _call_llm(system, user, max_tokens=2000)
    if not response:
        return None

    _stats["targets_prioritized"] += 1
    result = _extract_json(response, expect_array=True)
    if isinstance(result, list):
        return result
    return []


def ai_analyze_findings(findings: list[dict], domain: str) -> list[dict] | None:
    """Enrich recon findings with AI-generated impact and exploitation guidance."""
    if not AI_ENABLED or not findings:
        return None

    system = """You are a senior application security engineer explaining vulnerabilities to a bug bounty hunter.
For each finding, explain the real-world attack scenario and provide specific exploitation guidance.
Be concise and actionable."""

    compact = [
        {
            "code": f.get("code"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "evidence": (f.get("evidence") or "")[:150],
        }
        for f in findings[:15]
    ]

    user = f"""Analyze these security findings on {domain}:

{json.dumps(compact, indent=2, default=str)[:3500]}

For each finding return a JSON array:
[{{
  "code": "finding_code",
  "ai_impact": "Real-world attack scenario an attacker could execute",
  "ai_guidance": "Specific steps to test and exploit this finding"
}}]

Return ONLY valid JSON array."""

    response = _call_llm(system, user, max_tokens=2000)
    if not response:
        return None

    result = _extract_json(response, expect_array=True)
    if isinstance(result, list):
        return result
    return []


# ═══════════════════════════════════════════════════════════════
# 8. BugHunt AI — Scope Analysis, Vuln Suggestions & Report Writer
# ═══════════════════════════════════════════════════════════════

def ai_bughunt_analyze_scope(program: dict) -> dict | None:
    """Analyze a BugHunt program's scope and attack surface using AI (Portuguese)."""
    if not AI_ENABLED:
        return None
    _t0 = time.time()

    name = program.get("name", "Desconhecido")
    scope = program.get("scope", [])
    bounty = program.get("max_bounty", 0)
    reward_type = program.get("reward_type", "")

    system = """Você é um especialista em bug bounty analisando programas da plataforma BugHunt (Brasil).
Analise o escopo do programa e forneça uma análise detalhada da superfície de ataque.
Responda SEMPRE em Português do Brasil. Seja técnico e direto."""

    user = f"""Analise o seguinte programa da BugHunt:

**Programa:** {name}
**Tipo de Recompensa:** {reward_type or 'Não especificado'}
**Bounty Máximo:** R$ {bounty}
**Escopo ({len(scope)} alvos):**
{chr(10).join(f'  - {s}' for s in scope[:50]) if scope else '  Nenhum alvo listado'}

Forneça uma análise JSON com:
- "superficie_ataque": descrição geral da superfície de ataque (2-3 parágrafos)
- "tipo_aplicacao": tipo de aplicação (webapp, api, mobile, etc)
- "tecnologias_provaveis": lista de tecnologias prováveis
- "top_5_vulnerabilidades": lista com as 5 vulnerabilidades mais prováveis neste tipo de alvo, cada uma com "nome", "severidade", "justificativa"
- "vetores_especificos": lista de vetores de ataque específicos para este programa
- "subdominios_interessantes": lista dos domínios/subdomínios mais interessantes do scope e por quê
- "dicas_recompensa": dicas para maximizar a recompensa neste programa
- "risco_geral": "critico" | "alto" | "medio" | "baixo"
- "estimativa_horas": tempo estimado em horas para um pentest completo

Retorne APENAS JSON válido."""

    response = _call_llm(system, user, max_tokens=3000)
    if not response:
        _record("bughunt_analyze_scope", f"{name} ({len(scope)} alvos)", None, "error", int((time.time() - _t0) * 1000))
        return None
    _dur = int((time.time() - _t0) * 1000)

    result = _extract_json(response, expect_array=False)
    if isinstance(result, dict):
        result["programa"] = name
        result["alvos_analisados"] = len(scope)
        _record("bughunt_analyze_scope", f"{name} ({len(scope)} alvos)", {"risco": result.get("risco_geral"), "vulns": len(result.get("top_5_vulnerabilidades", []))}, "success", _dur)
        return result
    _record("bughunt_analyze_scope", f"{name} ({len(scope)} alvos)", None, "error", _dur)
    return None


def ai_bughunt_suggest_vulns(program: dict) -> dict | None:
    """Suggest vulnerabilities and attack strategies for a BugHunt program (Portuguese)."""
    if not AI_ENABLED:
        return None
    _t0 = time.time()

    name = program.get("name", "Desconhecido")
    scope = program.get("scope", [])
    bounty = program.get("max_bounty", 0)

    system = """Você é um hunter experiente da plataforma BugHunt com vasto conhecimento em segurança ofensiva.
Sugira vulnerabilidades e estratégias de ataque específicas para o programa.
Responda SEMPRE em Português do Brasil. Seja prático e acionável."""

    user = f"""Programa BugHunt: {name}
Bounty Máximo: R$ {bounty}
Escopo: {', '.join(scope[:30]) if scope else 'Não especificado'}

Sugira vulnerabilidades e estratégias. Retorne JSON com:
- "quick_wins": lista de bugs rápidos de encontrar, cada um com "vulnerabilidade", "onde_testar", "ferramenta", "tempo_estimado"
- "bugs_comuns": lista de bugs comuns para este tipo de aplicação, cada um com "tipo", "descricao", "impacto", "severidade"
- "cadeias_avancadas": lista de cadeias de vulnerabilidades para maximizar severidade, cada uma com "cadeia", "passos", "impacto_final", "severidade_resultante"
- "checklist": lista de itens para verificar (strings simples) — mínimo 10 itens
- "ferramentas_recomendadas": lista de ferramentas com "nome" e "uso"
- "estimativa_recompensa": objeto com "minima", "media", "maxima" (valores em R$)
- "prioridade_ataque": lista ordenada de alvos do scope por prioridade com "alvo" e "motivo"

Retorne APENAS JSON válido."""

    response = _call_llm(system, user, max_tokens=3500)
    if not response:
        _record("bughunt_suggest_vulns", name, None, "error", int((time.time() - _t0) * 1000))
        return None
    _dur = int((time.time() - _t0) * 1000)

    result = _extract_json(response, expect_array=False)
    if isinstance(result, dict):
        result["programa"] = name
        _record("bughunt_suggest_vulns", name, {"quick_wins": len(result.get("quick_wins", [])), "bugs_comuns": len(result.get("bugs_comuns", []))}, "success", _dur)
        return result
    _record("bughunt_suggest_vulns", name, None, "error", _dur)
    return None


def ai_bughunt_write_report(program: dict, vuln_type: str, details: str = "") -> dict | None:
    """Generate a professional BugHunt submission report using AI (Portuguese).

    Follows BugHunt report format: Título, Resumo Executivo, Severidade,
    Passos para Reproduzir, PoC, Impacto, Remediação, Referências.
    """
    if not AI_ENABLED:
        return None
    _t0 = time.time()

    name = program.get("name", "Desconhecido")
    scope = program.get("scope", [])

    system = """Você é um pesquisador de segurança sênior escrevendo relatórios profissionais para a plataforma BugHunt.
Seus relatórios devem ser excepcionais — claros, técnicos e com alto impacto.
Um bom relatório aumenta significativamente o valor da recompensa.
Escreva SEMPRE em Português do Brasil.
Use formatação Markdown."""

    scope_text = "\n".join(f"  - {s}" for s in scope[:20]) if scope else "  Não especificado"

    user = f"""Escreva um relatório de vulnerabilidade profissional para submissão na BugHunt.

**Programa:** {name}
**Escopo:** 
{scope_text}

**Tipo de Vulnerabilidade:** {vuln_type}
{f'**Detalhes adicionais:** {details}' if details else ''}

Gere um relatório completo em JSON com:
- "titulo": título descritivo e profissional (max 150 chars)
- "resumo_executivo": resumo da vulnerabilidade (2-3 parágrafos em Markdown)
- "severidade": "Crítica" | "Alta" | "Média" | "Baixa"
- "cvss_score": score CVSS 3.1 numérico (ex: 8.5)
- "cvss_vector": vetor CVSS 3.1 completo
- "passos_reproducao": lista de passos detalhados para reproduzir (strings em Markdown, com comandos curl/HTTP)
- "poc": código/comandos de Proof of Concept em Markdown (com code blocks)
- "impacto": análise detalhada do impacto ao negócio (2 parágrafos, mencionar LGPD se aplicável)
- "remediacao": recomendações de correção (lista de strings)
- "referencias": lista de URLs/referências (CWE, OWASP, CVE se aplicável)
- "cwe": código CWE principal (ex: "CWE-79")
- "owasp_category": categoria OWASP Top 10 (ex: "A03:2021 – Injection")

O relatório deve ser suficientemente detalhado para submissão imediata.
Use exemplos realistas baseados no escopo do programa.
Retorne APENAS JSON válido."""

    response = _call_llm(system, user, max_tokens=4000)
    if not response:
        _record("bughunt_write_report", f"{name} - {vuln_type}", None, "error", int((time.time() - _t0) * 1000))
        return None
    _dur = int((time.time() - _t0) * 1000)

    result = _extract_json(response, expect_array=False)
    if isinstance(result, dict) and "titulo" in result:
        result["programa"] = name
        result["tipo_vulnerabilidade"] = vuln_type
        result["gerado_em"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        _stats["reports_generated"] += 1
        _record("bughunt_write_report", f"{name} - {vuln_type}", {"titulo": result.get("titulo"), "severidade": result.get("severidade")}, "success", _dur)
        return result

    # Fallback: return raw response as markdown
    fallback = {
        "titulo": f"Vulnerabilidade {vuln_type} em {name}",
        "resumo_executivo": response,
        "severidade": "Média",
        "programa": name,
        "tipo_vulnerabilidade": vuln_type,
        "gerado_em": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "fallback": True,
    }
    _record("bughunt_write_report", f"{name} - {vuln_type}", {"titulo": fallback["titulo"], "fallback": True}, "partial", _dur)
    return fallback


def ai_generate_program_report(program: dict, targets: list[dict]) -> dict | None:
    """Generate a consolidated AI executive summary for a bug bounty program's recon results."""
    if not AI_ENABLED or not targets:
        return None

    system = """You are a senior penetration tester writing an executive summary of reconnaissance results
for a bug bounty program. Summarize the overall attack surface, highlight the most impactful findings,
and recommend the top 3 concrete attack strategies."""

    # Build severity breakdown and top targets
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    top_targets = []
    for t in sorted(targets, key=lambda x: (x.get("recon_checks") or {}).get("risk_score", 0), reverse=True)[:10]:
        rc = t.get("recon_checks") or {}
        for f in rc.get("findings", []):
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        top_targets.append({
            "domain": t.get("domain"),
            "risk_score": rc.get("risk_score", 0),
            "top_findings": [
                {"code": f.get("code"), "severity": f.get("severity")}
                for f in rc.get("findings", [])[:3]
            ],
        })

    user = f"""Program: {program.get("name", "Unknown")}
Total alive targets: {len(targets)}
Severity breakdown: {json.dumps(severity_counts)}

Top 10 highest-risk targets:
{json.dumps(top_targets, indent=2, default=str)[:3000]}

Generate a consolidated executive summary. Return JSON:
{{
  "executive_summary": "2-3 sentence overview",
  "overall_risk": "critical|high|medium|low",
  "total_targets": {len(targets)},
  "total_findings": {sum(severity_counts.values())},
  "critical_assets": ["most important domains"],
  "top_attack_strategies": ["strategy 1", "strategy 2", "strategy 3"],
  "severity_breakdown": {json.dumps(severity_counts)},
  "recommended_next_steps": ["actionable step 1", "actionable step 2"]
}}

Return ONLY valid JSON object."""

    response = _call_llm(system, user, max_tokens=3000)
    if not response:
        return None

    _stats["program_reports_generated"] += 1
    result = _extract_json(response, expect_array=False)
    if isinstance(result, dict):
        return result
    return None
