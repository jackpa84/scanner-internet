"""
Integration examples for bugbounty-cheatsheet payloads with existing scanners.

This module demonstrates how to use the payloads.py in your vulnerability scanners.
"""

from app.payloads import (
    XSS_PAYLOADS,
    SQLI_PAYLOADS,
    SSRF_PAYLOADS,
    LFI_PAYLOADS,
    OPEN_REDIRECT_PAYLOADS,
    RCE_PAYLOADS,
    COMMON_REDIRECT_PARAMS,
    COMMON_SSRF_PARAMS,
    COMMON_LFI_PARAMS,
)


def get_xss_test_payloads(bypass_waf: bool = False) -> list[str]:
    """
    Get XSS payloads for testing.
    
    Args:
        bypass_waf: Include WAF bypass payloads
    
    Returns:
        List of XSS payloads to test
    """
    payloads = (
        XSS_PAYLOADS["basic"] +
        XSS_PAYLOADS["chrome_bypass"] +
        XSS_PAYLOADS["safari"]
    )
    
    if bypass_waf:
        payloads += XSS_PAYLOADS["waf_bypass"]
    
    return payloads


def get_sqli_test_payloads(technique: str = "all") -> list[str]:
    """
    Get SQL injection payloads for testing.
    
    Args:
        technique: Type of SQL injection to test
                  (basic, union_based, blind, all)
    
    Returns:
        List of SQL injection payloads
    """
    if technique == "all":
        return sum(SQLI_PAYLOADS.values(), [])
    elif technique in SQLI_PAYLOADS:
        return SQLI_PAYLOADS[technique]
    else:
        return SQLI_PAYLOADS["basic"]


def get_ssrf_test_payloads(target_type: str = "all") -> list[str]:
    """
    Get SSRF payloads for testing.
    
    Args:
        target_type: Type of SSRF test
                    (localhost, aws_metadata, wildcard_dns, exotic_handlers, ipv6, all)
    
    Returns:
        List of SSRF payloads
    """
    if target_type == "all":
        return sum(SSRF_PAYLOADS.values(), [])
    elif target_type in SSRF_PAYLOADS:
        return SSRF_PAYLOADS[target_type]
    else:
        return SSRF_PAYLOADS["localhost"]


def get_lfi_test_payloads(include_log_files: bool = False) -> list[str]:
    """
    Get LFI payloads for testing.
    
    Args:
        include_log_files: Include common log file paths
    
    Returns:
        List of LFI payloads
    """
    payloads = (
        LFI_PAYLOADS["basic"] +
        LFI_PAYLOADS["filter_bypass"] +
        LFI_PAYLOADS["common_files"]
    )
    
    if include_log_files:
        payloads += LFI_PAYLOADS["log_files"]
    
    return payloads


def get_redirect_test_payloads() -> list[str]:
    """Get Open Redirect payloads for testing."""
    return (
        OPEN_REDIRECT_PAYLOADS["basic"] +
        OPEN_REDIRECT_PAYLOADS["encoding"] +
        OPEN_REDIRECT_PAYLOADS["paths"]
    )


def get_rce_test_payloads(include_bypass: bool = False) -> list[str]:
    """
    Get RCE payloads for testing.
    
    Args:
        include_bypass: Include obfuscation/bypass payloads
    
    Returns:
        List of RCE payloads
    """
    payloads = RCE_PAYLOADS["basic"]
    
    if include_bypass:
        payloads += RCE_PAYLOADS["bypass"]
    
    return payloads


def test_parameter_with_payload(
    base_url: str,
    param_name: str,
    payload: str,
    method: str = "GET"
) -> dict:
    """
    Test a parameter with a specific payload.
    
    Args:
        base_url: Base URL to test
        param_name: Parameter name to inject into
        payload: Payload to inject
        method: HTTP method (GET or POST)
    
    Returns:
        Dictionary with test results
    """
    import requests
    from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
    
    try:
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        
        # Inject payload
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        
        if method == "GET":
            response = requests.get(test_url, timeout=5)
        else:
            response = requests.post(test_url, timeout=5)
        
        return {
            "parameter": param_name,
            "payload": payload,
            "status_code": response.status_code,
            "response_length": len(response.text),
            "content_type": response.headers.get("content-type", ""),
            "success": response.status_code < 400
        }
    except Exception as e:
        return {
            "parameter": param_name,
            "payload": payload,
            "error": str(e),
            "success": False
        }


def test_xss_in_parameters(base_url: str, parameters: list[str]) -> list[dict]:
    """
    Test XSS in a list of parameters.
    
    Args:
        base_url: Base URL to test
        parameters: List of parameter names to test
    
    Returns:
        List of test results
    """
    results = []
    payloads = get_xss_test_payloads(bypass_waf=False)
    
    for param in parameters:
        for payload in payloads[:3]:  # Limit to first 3 payloads per param
            result = test_parameter_with_payload(base_url, param, payload)
            results.append(result)
    
    return results


def test_sqli_in_parameters(base_url: str, parameters: list[str]) -> list[dict]:
    """
    Test SQL injection in a list of parameters.
    
    Args:
        base_url: Base URL to test
        parameters: List of parameter names to test
    
    Returns:
        List of test results
    """
    results = []
    payloads = get_sqli_test_payloads("basic")
    
    for param in parameters:
        for payload in payloads[:2]:  # Limit to first 2 payloads per param
            result = test_parameter_with_payload(base_url, param, payload)
            results.append(result)
    
    return results


def get_redirect_parameters() -> list[str]:
    """Get common parameter names for redirect testing."""
    return COMMON_REDIRECT_PARAMS


def get_ssrf_parameters() -> list[str]:
    """Get common parameter names for SSRF testing."""
    return list(COMMON_SSRF_PARAMS)


def get_lfi_parameters() -> list[str]:
    """Get common parameter names for LFI testing."""
    return list(COMMON_LFI_PARAMS)
