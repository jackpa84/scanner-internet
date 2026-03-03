"""
Example: How to use bugbounty-cheatsheet payloads with SSRF Scanner

This example demonstrates how to enhance your existing SSRF scanner
with payloads from the bugbounty-cheatsheet integration.
"""

from typing import Any
from app.payloads_integration import (
    get_ssrf_test_payloads,
    get_ssrf_parameters,
)


def example_enhanced_ssrf_scan():
    """
    Example: Enhanced SSRF scan using bugbounty-cheatsheet payloads.
    
    This shows how you can extend your existing ssrf_scanner.py
    to use the integrated payloads.
    """
    
    # Get all common SSRF parameters from the cheatsheet
    parameters = get_ssrf_parameters()
    print("SSRF Parameters to test:")
    print(parameters)
    print()
    
    # Get SSRF payloads by category
    localhost_payloads = get_ssrf_test_payloads(target_type="localhost")
    print(f"Localhost payloads ({len(localhost_payloads)}):")
    for payload in localhost_payloads[:3]:
        print(f"  - {payload}")
    print()
    
    aws_metadata_payloads = get_ssrf_test_payloads(target_type="aws_metadata")
    print(f"AWS Metadata payloads ({len(aws_metadata_payloads)}):")
    for payload in aws_metadata_payloads[:3]:
        print(f"  - {payload}")
    print()
    
    wildcard_dns_payloads = get_ssrf_test_payloads(target_type="wildcard_dns")
    print(f"Wildcard DNS payloads ({len(wildcard_dns_payloads)}):")
    for payload in wildcard_dns_payloads[:3]:
        print(f"  - {payload}")
    print()
    
    exotic_handlers = get_ssrf_test_payloads(target_type="exotic_handlers")
    print(f"Exotic handlers ({len(exotic_handlers)}):")
    for payload in exotic_handlers[:3]:
        print(f"  - {payload}")
    print()
    
    ipv6_payloads = get_ssrf_test_payloads(target_type="ipv6")
    print(f"IPv6 payloads ({len(ipv6_payloads)}):")
    for payload in ipv6_payloads:
        print(f"  - {payload}")
    print()


def example_targeted_ssrf_scan(target_url: str, target_type: str = "aws_metadata"):
    """
    Example: Targeted SSRF scan against a specific target.
    
    Args:
        target_url: URL to scan (e.g., "https://api.example.com/fetch")
        target_type: Type of SSRF to test (localhost, aws_metadata, wildcard_dns, etc.)
    """
    import requests
    from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
    
    # Get payloads for the specific target type
    payloads = get_ssrf_test_payloads(target_type=target_type)
    parameters = get_ssrf_parameters()
    
    results = []
    
    # Test each parameter with the payloads
    for param in parameters:
        for payload in payloads:
            try:
                # Build test URL with payload injection
                parsed = urlparse(target_url)
                test_params = parse_qs(parsed.query) if parsed.query else {}
                test_params[param] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    test_query,
                    parsed.fragment
                ))
                
                # Send request with timeout
                response = requests.get(test_url, timeout=5)
                
                # Log results
                result = {
                    "parameter": param,
                    "payload": payload,
                    "status_code": response.status_code,
                    "response_size": len(response.text),
                    "indicators": detect_ssrf_indicators(response.text)
                }
                
                if result["indicators"]:
                    results.append(result)
                    print(f"✓ Potential SSRF found in {param}: {payload}")
                    print(f"  Indicators: {result['indicators']}")
                
            except Exception as e:
                print(f"✗ Error testing {param} with payload: {str(e)}")
    
    return results


def detect_ssrf_indicators(response_text: str) -> list[str]:
    """
    Detect common SSRF indicators in response.
    
    Args:
        response_text: Response body to analyze
    
    Returns:
        List of indicators found
    """
    indicators = [
        "root:", "daemon:", "[boot]",  # /etc/passwd indicators
        "AWS", "ami-id", "instance-id", "iam",  # AWS metadata
        "compute.internal", "metadata.google",  # Google Cloud
        "169.254.169.254",  # AWS metadata IP
        "localhost", "127.0.0.1",  # Localhost
    ]
    
    found = []
    for indicator in indicators:
        if indicator.lower() in response_text.lower():
            found.append(indicator)
    
    return found


def example_ssrf_with_callbacks():
    """
    Example: SSRF testing with OOB (out-of-band) callbacks.
    
    For blind SSRF detection, you would integrate with a callback service like:
    - Interactsh
    - RequestBin
    - Burp Collaborator
    - Custom webhook
    """
    
    print("""
    For blind SSRF detection, you can use:
    
    1. Interactsh (built-in to your project):
       - Generate unique callback URL
       - Inject callback URL in parameters
       - Monitor for DNS/HTTP requests
    
    2. RequestBin / Webhook.site:
       - Create temporary request listener
       - Inject listener URL in parameters
       - Check for incoming requests
    
    3. Burp Collaborator:
       - Generate unique subdomain
       - Monitor for interactions
       - High reliability
    
    Your project already has interactsh_client.py integrated!
    """)


def example_integration_with_existing_scanner():
    """
    Example: How to integrate with your existing ssrf_scanner.py
    
    In your ssrf_scanner.py, you could add:
    """
    
    code_example = """
    # In ssrf_scanner.py
    from app.payloads_integration import (
        get_ssrf_test_payloads,
        get_ssrf_parameters
    )
    
    class EnhancedSSRFScanner:
        def __init__(self):
            self.payloads = get_ssrf_test_payloads()
            self.parameters = get_ssrf_parameters()
        
        def scan_url(self, url: str):
            # Your existing code...
            # Add payload-based testing
            for param in self.parameters:
                for payload in self.payloads:
                    # Test payload injection
                    result = self._test_ssrf(url, param, payload)
                    if result["vulnerable"]:
                        self.report_vulnerability(result)
    """
    
    print(code_example)


if __name__ == "__main__":
    print("=" * 60)
    print("SSRF Scanner Enhancement Examples")
    print("=" * 60)
    print()
    
    # Example 1: Show available payloads
    example_enhanced_ssrf_scan()
    
    print("=" * 60)
    print("Example: Using payloads against a target")
    print("=" * 60)
    print()
    
    # Example 2: Show how to use with a real target (commented out)
    print("# To test against a real target, uncomment and modify:")
    print("# results = example_targeted_ssrf_scan(")
    print("#     target_url='https://api.example.com/fetch',")
    print("#     target_type='aws_metadata'")
    print("# )")
    print()
    
    # Example 3: OOB callback explanation
    example_ssrf_with_callbacks()
    
    print()
    print("=" * 60)
    print("Integration Example")
    print("=" * 60)
    example_integration_with_existing_scanner()
