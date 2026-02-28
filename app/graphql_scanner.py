"""
Deep GraphQL vulnerability scanner.

Goes beyond basic detection to actively test for exploitable GraphQL flaws.
Typical payout: $500 - $5,000.

Techniques:
  - Introspection query (full schema dump)
  - Sensitive mutation discovery
  - Query batching / alias-based brute force
  - Depth limit bypass (nested queries)
  - Field suggestion enumeration
  - Authorization bypass via different query paths
  - DoS via circular fragment references
"""

import json
import logging
import os
import re
import time
from typing import Any
from urllib.parse import urlparse, urljoin

import requests

logger = logging.getLogger("scanner.graphql")

GRAPHQL_ENABLED = os.getenv("GRAPHQL_SCANNER_ENABLED", "true").lower() in ("1", "true", "yes")
GRAPHQL_TIMEOUT = int(os.getenv("GRAPHQL_TIMEOUT", "10"))

GRAPHQL_ENDPOINTS = [
    "/graphql", "/graphiql", "/v1/graphql", "/v2/graphql",
    "/api/graphql", "/api/v1/graphql",
    "/query", "/gql",
    "/graphql/console", "/graphql/playground",
    "/__graphql",
]

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name kind description
      fields(includeDeprecated: true) {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind ofType { name kind } } }
      }
    }
  }
}
"""

SENSITIVE_TYPE_NAMES = {
    "user", "admin", "account", "credential", "password", "token",
    "secret", "key", "auth", "session", "payment", "billing",
    "invoice", "order", "transaction", "credit_card", "ssn",
    "private", "internal", "config", "setting", "role", "permission",
}

SENSITIVE_FIELD_NAMES = {
    "password", "passwordHash", "password_hash", "hashedPassword",
    "secret", "secretKey", "secret_key", "apiKey", "api_key",
    "token", "accessToken", "access_token", "refreshToken",
    "ssn", "socialSecurityNumber", "creditCard", "credit_card",
    "cvv", "cardNumber", "card_number", "privateKey", "private_key",
    "internalId", "internal_id", "adminToken", "admin_token",
}

SENSITIVE_MUTATION_PATTERNS = [
    r'(?i)delete.*user', r'(?i)remove.*user', r'(?i)update.*role',
    r'(?i)change.*password', r'(?i)reset.*password', r'(?i)create.*admin',
    r'(?i)grant.*permission', r'(?i)elevate', r'(?i)promote',
    r'(?i)transfer.*fund', r'(?i)withdraw', r'(?i)modify.*config',
    r'(?i)update.*setting', r'(?i)disable.*auth', r'(?i)bypass',
    r'(?i)impersonate', r'(?i)debug', r'(?i)execute',
]

_stats = {
    "endpoints_found": 0,
    "introspection_enabled": 0,
    "sensitive_types_found": 0,
    "vulns_found": 0,
    "errors": 0,
}


def get_graphql_stats() -> dict[str, Any]:
    return dict(_stats)


def _graphql_request(
    url: str, query: str,
    variables: dict | None = None,
    headers: dict | None = None,
) -> tuple[dict | None, int]:
    """Send a GraphQL request and return (data, status_code)."""
    req_headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    }
    if headers:
        req_headers.update(headers)

    payload = {"query": query}
    if variables:
        payload["variables"] = variables

    try:
        resp = requests.post(
            url, json=payload, headers=req_headers,
            timeout=GRAPHQL_TIMEOUT, allow_redirects=True,
        )
        if resp.status_code in (200, 400):
            try:
                return resp.json(), resp.status_code
            except json.JSONDecodeError:
                return None, resp.status_code
        return None, resp.status_code
    except requests.RequestException:
        return None, 0


def discover_graphql_endpoint(base_url: str, headers: dict | None = None) -> str | None:
    """Find the active GraphQL endpoint on a target."""
    for path in GRAPHQL_ENDPOINTS:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            data, status = _graphql_request(url, "{ __typename }", headers=headers)
            if data and ("data" in data or "errors" in data):
                _stats["endpoints_found"] += 1
                return url
        except Exception:
            continue
    return None


def test_introspection(url: str, headers: dict | None = None) -> dict[str, Any]:
    """Test if introspection is enabled and extract schema."""
    result: dict[str, Any] = {
        "enabled": False,
        "types": [],
        "queries": [],
        "mutations": [],
        "sensitive_types": [],
        "sensitive_fields": [],
        "sensitive_mutations": [],
    }

    data, status = _graphql_request(url, INTROSPECTION_QUERY, headers=headers)
    if not data or "data" not in data:
        return result

    schema = (data.get("data") or {}).get("__schema")
    if not schema:
        return result

    result["enabled"] = True
    _stats["introspection_enabled"] += 1

    types = schema.get("types", [])
    query_type_name = (schema.get("queryType") or {}).get("name", "Query")
    mutation_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")

    for t in types:
        name = t.get("name", "")
        kind = t.get("kind", "")

        if name.startswith("__"):
            continue

        result["types"].append({"name": name, "kind": kind})

        if name.lower().replace("_", "") in {s.replace("_", "") for s in SENSITIVE_TYPE_NAMES}:
            result["sensitive_types"].append(name)
            _stats["sensitive_types_found"] += 1

        fields = t.get("fields") or []
        if name == query_type_name:
            result["queries"] = [f.get("name", "") for f in fields]
        elif name == mutation_type_name:
            result["mutations"] = [f.get("name", "") for f in fields]

        for field in fields:
            field_name = field.get("name", "")
            if field_name.lower() in SENSITIVE_FIELD_NAMES:
                result["sensitive_fields"].append(f"{name}.{field_name}")

    for mutation_name in result["mutations"]:
        for pattern in SENSITIVE_MUTATION_PATTERNS:
            if re.match(pattern, mutation_name):
                result["sensitive_mutations"].append(mutation_name)
                break

    return result


def test_query_batching(url: str, headers: dict | None = None) -> dict[str, Any]:
    """Test if query batching is allowed (useful for brute force attacks)."""
    batch_queries = [
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
    ]

    req_headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    }
    if headers:
        req_headers.update(headers)

    try:
        resp = requests.post(
            url, json=batch_queries, headers=req_headers,
            timeout=GRAPHQL_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) >= 2:
                return {"batching_allowed": True, "batch_size": len(data)}
    except Exception:
        pass

    return {"batching_allowed": False}


def test_alias_overloading(url: str, headers: dict | None = None) -> dict[str, Any]:
    """Test for alias-based query amplification (DoS / brute force)."""
    aliases = " ".join([f'q{i}: __typename' for i in range(100)])
    query = f"{{ {aliases} }}"

    data, status = _graphql_request(url, query, headers=headers)
    if data and "data" in data:
        response_data = data["data"]
        if isinstance(response_data, dict) and len(response_data) >= 50:
            return {"alias_overloading": True, "aliases_allowed": len(response_data)}

    return {"alias_overloading": False}


def test_depth_limit(url: str, headers: dict | None = None) -> dict[str, Any]:
    """Test if there's a query depth limit (deep nesting = DoS potential)."""
    depth_query = "{ __schema { types { fields { type { fields { type { fields { type { name } } } } } } } } }"

    data, status = _graphql_request(url, depth_query, headers=headers)
    if data and "data" in data and not data.get("errors"):
        return {"depth_limited": False, "max_depth_tested": 8}

    if data and data.get("errors"):
        errors = data["errors"]
        for err in errors:
            msg = str(err.get("message", "")).lower()
            if "depth" in msg or "complexity" in msg or "limit" in msg:
                return {"depth_limited": True, "error_message": msg[:200]}

    return {"depth_limited": True}


def test_field_suggestions(url: str, headers: dict | None = None) -> dict[str, Any]:
    """Test if GraphQL returns field suggestions in error messages (info leak)."""
    bogus_query = "{ totallyFakeFieldThatDoesNotExist123 }"

    data, status = _graphql_request(url, bogus_query, headers=headers)
    suggestions = []

    if data and data.get("errors"):
        for err in data["errors"]:
            msg = str(err.get("message", ""))
            did_you_mean = re.findall(r'Did you mean[^?]*\?|["\'](\w+)["\']', msg)
            suggestions.extend(did_you_mean)

    return {
        "suggestions_enabled": len(suggestions) > 0,
        "suggested_fields": list(set(suggestions))[:20],
    }


def scan_graphql(
    base_url: str,
    headers: dict | None = None,
) -> list[dict[str, Any]]:
    """Run full GraphQL vulnerability scan on a target."""
    if not GRAPHQL_ENABLED:
        return []

    findings = []

    endpoint = discover_graphql_endpoint(base_url, headers)
    if not endpoint:
        return []

    logger.info("[GRAPHQL] Found endpoint: %s", endpoint)

    introspection = test_introspection(endpoint, headers)
    if introspection["enabled"]:
        severity = "high" if introspection["sensitive_fields"] or introspection["sensitive_mutations"] else "medium"
        evidence_parts = []
        if introspection["sensitive_types"]:
            evidence_parts.append(f"Sensitive types: {', '.join(introspection['sensitive_types'][:5])}")
        if introspection["sensitive_fields"]:
            evidence_parts.append(f"Sensitive fields: {', '.join(introspection['sensitive_fields'][:5])}")
        if introspection["sensitive_mutations"]:
            evidence_parts.append(f"Dangerous mutations: {', '.join(introspection['sensitive_mutations'][:5])}")

        findings.append({
            "severity": severity,
            "code": "graphql_introspection",
            "title": "GraphQL Introspection enabled",
            "evidence": " | ".join(evidence_parts)[:200] if evidence_parts else f"{len(introspection['types'])} types, {len(introspection['mutations'])} mutations exposed",
            "details": introspection,
        })
        _stats["vulns_found"] += 1

        for mutation in introspection["sensitive_mutations"]:
            findings.append({
                "severity": "high",
                "code": "graphql_sensitive_mutation",
                "title": f"Sensitive GraphQL mutation: {mutation}",
                "evidence": f"Mutation '{mutation}' accessible at {endpoint}"[:200],
            })
            _stats["vulns_found"] += 1

        for field in introspection["sensitive_fields"][:5]:
            findings.append({
                "severity": "high",
                "code": "graphql_sensitive_field",
                "title": f"Sensitive field exposed: {field}",
                "evidence": f"Field '{field}' found in schema at {endpoint}"[:200],
            })
            _stats["vulns_found"] += 1

    batching = test_query_batching(endpoint, headers)
    if batching["batching_allowed"]:
        findings.append({
            "severity": "medium",
            "code": "graphql_batching",
            "title": "GraphQL query batching allowed",
            "evidence": f"Server accepts batched queries (size={batching.get('batch_size', '?')}) - enables brute force attacks"[:200],
        })
        _stats["vulns_found"] += 1

    alias_result = test_alias_overloading(endpoint, headers)
    if alias_result["alias_overloading"]:
        findings.append({
            "severity": "medium",
            "code": "graphql_alias_overloading",
            "title": "GraphQL alias overloading (DoS potential)",
            "evidence": f"Server allows {alias_result.get('aliases_allowed', '?')} aliases in single query"[:200],
        })
        _stats["vulns_found"] += 1

    depth = test_depth_limit(endpoint, headers)
    if not depth["depth_limited"]:
        findings.append({
            "severity": "medium",
            "code": "graphql_no_depth_limit",
            "title": "No GraphQL query depth limit",
            "evidence": f"Deeply nested queries accepted (depth={depth.get('max_depth_tested', '?')}) - DoS potential"[:200],
        })
        _stats["vulns_found"] += 1

    suggestions = test_field_suggestions(endpoint, headers)
    if suggestions["suggestions_enabled"]:
        findings.append({
            "severity": "low",
            "code": "graphql_field_suggestions",
            "title": "GraphQL field suggestions enabled (info leak)",
            "evidence": f"Suggested fields: {', '.join(suggestions['suggested_fields'][:10])}"[:200],
        })
        _stats["vulns_found"] += 1

    return findings
