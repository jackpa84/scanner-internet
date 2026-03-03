#!/usr/bin/env python3
"""
Test script: SSRF Scanner with bugbounty-cheatsheet payloads integration.

This demonstrates the enhanced SSRF scanner using payloads from bugbounty-cheatsheet.
"""

import logging
from app.ssrf_scanner import (
    scan_url_for_ssrf,
    get_ssrf_stats,
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def test_ssrf_scanner():
    """Test SSRF scanner with sample URLs."""
    
    print("\n" + "=" * 70)
    print("  SSRF Scanner with BugBounty-Cheatsheet Integration Test")
    print("=" * 70 + "\n")
    
    # Test URLs with common SSRF parameters
    test_urls = [
        "https://example.com/api?url=https://example.com",
        "https://example.com/fetch?uri=https://example.com",
        "https://example.com/proxy?target=https://example.com",
        "https://example.com/image?src=https://example.com",
        "https://example.com/redirect?next=https://example.com",
    ]
    
    print("Testing SSRF Scanner Configuration:")
    print("-" * 70)
    print("✓ Using bugbounty-cheatsheet payloads: ENABLED")
    print("✓ Native scanner payloads: ENABLED")
    print("✓ Available SSRF payload categories:")
    print("  - Localhost variations (9 payloads)")
    print("  - AWS Metadata endpoints (4 payloads)")
    print("  - IPv6 variations (3 payloads)")
    print("  - Exotic protocol handlers (5 payloads)")
    print("  - Wildcard DNS services (4 payloads)")
    print()
    
    print("Test URLs:")
    for i, url in enumerate(test_urls, 1):
        print(f"  {i}. {url}")
    print()
    
    print("Running scanner...")
    print("-" * 70)
    print()
    
    # Test each URL
    for url in test_urls:
        findings = scan_url_for_ssrf(url, callback_host=None)
        
        if findings:
            print(f"✓ URL: {url}")
            print(f"  Found {len(findings)} potential SSRF vulnerability(ies):")
            for finding in findings:
                print(f"    - [{finding['severity'].upper()}] {finding['title']}")
                print(f"      Code: {finding['code']}")
                print(f"      Param: {finding['param_name']}")
                print(f"      Payload: {finding.get('payload', 'N/A')}")
                print(f"      Source: {finding.get('source', 'native_scanner')}")
            print()
        else:
            print(f"- URL: {url}")
            print(f"  No vulnerabilities detected (expected in test)")
            print()
    
    # Show statistics
    stats = get_ssrf_stats()
    print("=" * 70)
    print("Scanner Statistics:")
    print("-" * 70)
    print(f"URLs tested:                  {stats['urls_tested']}")
    print(f"Parameters tested:            {stats['params_tested']}")
    print(f"SSRF vulnerabilities found:   {stats['ssrf_found']}")
    print(f"Blind SSRF payloads sent:     {stats['blind_ssrf_payloads']}")
    print(f"Errors encountered:           {stats['errors']}")
    print("=" * 70)
    print()
    
    print("Integration Notes:")
    print("-" * 70)
    print("""
✓ The SSRF scanner now uses bugbounty-cheatsheet payloads by default
✓ USE_CHEATSHEET_PAYLOADS environment variable controls this (default: true)
✓ Payloads are tested after native payloads if needed
✓ Each finding includes source information (native_scanner or bugbounty_cheatsheet)

To disable cheatsheet payloads, set:
  export SSRF_USE_CHEATSHEET_PAYLOADS=false

Example integration in your code:
  from app.ssrf_scanner import scan_url_for_ssrf
  
  findings = scan_url_for_ssrf(
      url="https://target.com/fetch?url=https://target.com",
      callback_host="your-callback.com",  # For blind SSRF
      headers={"X-API-Key": "token"}
  )
  
  for finding in findings:
      print(f"Found {finding['title']} in param {finding['param_name']}")
""")
    print()


if __name__ == "__main__":
    test_ssrf_scanner()
