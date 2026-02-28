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
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514").strip()
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434").strip()
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3").strip()

AI_ENABLED = AI_PROVIDER in ("openai", "anthropic", "ollama")
AI_MAX_TOKENS = int(os.getenv("AI_MAX_TOKENS", "2000"))
AI_TEMPERATURE = float(os.getenv("AI_TEMPERATURE", "0.3"))

_stats = {
    "requests": 0,
    "tokens_used": 0,
    "errors": 0,
    "reports_generated": 0,
    "findings_classified": 0,
    "responses_analyzed": 0,
}


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

    try:
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            return json.loads(json_match.group())
    except json.JSONDecodeError:
        pass

    return {
        "title": f"Security findings on {domain}",
        "vulnerability_information": response,
        "impact": "See report body for impact analysis.",
        "severity_rating": findings[0].get("severity", "medium"),
    }


# ═══════════════════════════════════════════════════════════════
# 2. AI Finding Classifier (true positive vs false positive)
# ═══════════════════════════════════════════════════════════════

def ai_classify_finding(finding: dict, response_data: dict | None = None) -> dict[str, Any] | None:
    """Use AI to classify a finding as true/false positive and assess severity."""
    if not AI_ENABLED:
        return None

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

    try:
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            return json.loads(json_match.group())
    except json.JSONDecodeError:
        pass
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

    try:
        json_match = re.search(r'\[[\s\S]*\]', response)
        if json_match:
            results = json.loads(json_match.group())
            if isinstance(results, list):
                return results
    except json.JSONDecodeError:
        pass
    return []


# ═══════════════════════════════════════════════════════════════
# 4. AI Scope Parser
# ═══════════════════════════════════════════════════════════════

def ai_parse_scope(program_description: str, policy_text: str = "") -> dict[str, Any] | None:
    """Use AI to parse a bounty program description and extract scope details."""
    if not AI_ENABLED:
        return None

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
        return None

    try:
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            return json.loads(json_match.group())
    except json.JSONDecodeError:
        pass
    return None


# ═══════════════════════════════════════════════════════════════
# 5. AI JavaScript Analyzer
# ═══════════════════════════════════════════════════════════════

def ai_analyze_javascript(js_code: str, source_url: str = "") -> list[dict] | None:
    """Use AI to analyze JavaScript code for secrets and vulnerabilities."""
    if not AI_ENABLED or not js_code:
        return None

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
        return None

    try:
        json_match = re.search(r'\[[\s\S]*\]', response)
        if json_match:
            results = json.loads(json_match.group())
            if isinstance(results, list):
                return results
    except json.JSONDecodeError:
        pass
    return []


# ═══════════════════════════════════════════════════════════════
# 6. AI Vulnerability Chain Analyzer
# ═══════════════════════════════════════════════════════════════

def ai_find_vuln_chains(findings: list[dict], domain: str) -> list[dict] | None:
    """Use AI to identify vulnerability chains that increase severity."""
    if not AI_ENABLED or len(findings) < 2:
        return None

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
        return None

    try:
        json_match = re.search(r'\[[\s\S]*\]', response)
        if json_match:
            results = json.loads(json_match.group())
            if isinstance(results, list):
                return results
    except json.JSONDecodeError:
        pass
    return []
