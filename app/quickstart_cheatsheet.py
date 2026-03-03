#!/usr/bin/env python3
"""
Quick Start: Usando bugbounty-cheatsheet payloads no seu projeto

Este script demonstra como usar os payloads integrados.
"""

from app.payloads_integration import (
    get_xss_test_payloads,
    get_sqli_test_payloads,
    get_ssrf_test_payloads,
    get_lfi_test_payloads,
    get_redirect_test_payloads,
    get_rce_test_payloads,
    get_redirect_parameters,
    get_ssrf_parameters,
    get_lfi_parameters,
)


def print_section(title: str):
    """Print a formatted section header."""
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)
    print()


def show_xss_payloads():
    """Show XSS payload examples."""
    print_section("XSS (Cross-Site Scripting)")
    
    # Basic payloads
    payloads = get_xss_test_payloads(bypass_waf=False)
    print(f"Total payloads available: {len(payloads)}")
    print("\nExamples (first 5):")
    for i, payload in enumerate(payloads[:5], 1):
        print(f"  {i}. {payload}")
    
    # With WAF bypass
    payloads_waf = get_xss_test_payloads(bypass_waf=True)
    print(f"\nWith WAF bypasses: {len(payloads_waf)} payloads")
    print("WAF Bypass Examples:")
    for i, payload in enumerate(payloads[len(payloads):len(payloads)+3], 1):
        print(f"  {i}. {payload}")


def show_sqli_payloads():
    """Show SQL Injection payload examples."""
    print_section("SQL Injection (SQLi)")
    
    techniques = ["basic", "union_based", "blind", "akamai_bypass"]
    for technique in techniques:
        payloads = get_sqli_test_payloads(technique=technique)
        print(f"\n{technique.title()} ({len(payloads)} payloads):")
        for payload in payloads[:2]:
            print(f"  • {payload}")


def show_ssrf_payloads():
    """Show SSRF payload examples."""
    print_section("SSRF (Server-Side Request Forgery)")
    
    categories = ["localhost", "aws_metadata", "wildcard_dns", "exotic_handlers", "ipv6"]
    
    print(f"Common parameters to test ({len(get_ssrf_parameters())}):")
    for param in list(get_ssrf_parameters())[:10]:
        print(f"  • {param}")
    
    print("\nPayload categories:")
    for category in categories:
        payloads = get_ssrf_test_payloads(target_type=category)
        print(f"\n{category.replace('_', ' ').title()} ({len(payloads)} payloads):")
        for payload in payloads[:2]:
            print(f"  • {payload}")


def show_lfi_payloads():
    """Show LFI payload examples."""
    print_section("LFI (Local File Inclusion)")
    
    payloads = get_lfi_test_payloads(include_log_files=False)
    print(f"Total payloads available: {len(payloads)}")
    print("\nExamples:")
    for i, payload in enumerate(payloads[:8], 1):
        print(f"  {i}. {payload}")
    
    print(f"\nCommon parameters ({len(get_lfi_parameters())}):")
    for param in list(get_lfi_parameters())[:8]:
        print(f"  • {param}")


def show_redirect_payloads():
    """Show Open Redirect payload examples."""
    print_section("Open Redirect")
    
    payloads = get_redirect_test_payloads()
    print(f"Total payloads available: {len(payloads)}")
    
    print("\nBasic redirects:")
    for payload in payloads[:3]:
        print(f"  • {payload}")
    
    print(f"\nCommon redirect parameters ({len(get_redirect_parameters())}):")
    for param in list(get_redirect_parameters())[:10]:
        print(f"  • {param}")


def show_rce_payloads():
    """Show RCE payload examples."""
    print_section("RCE (Remote Code Execution)")
    
    basic = get_rce_test_payloads(include_bypass=False)
    print(f"Basic commands ({len(basic)}):")
    for cmd in basic:
        print(f"  • {cmd}")
    
    advanced = get_rce_test_payloads(include_bypass=True)
    print(f"\nWith bypass techniques ({len(advanced)} total):")
    for payload in advanced[len(basic):len(basic)+3]:
        print(f"  • {payload}")


def show_integration_examples():
    """Show code integration examples."""
    print_section("Integration Examples")
    
    examples = {
        "Import payloads": """
from app.payloads_integration import (
    get_xss_test_payloads,
    get_sqli_test_payloads,
    get_ssrf_test_payloads,
)
""",
        "Use in scanner": """
def scan_param_for_xss(url, param_name):
    payloads = get_xss_test_payloads(bypass_waf=True)
    for payload in payloads:
        test_url = f"{url}?{param_name}={payload}"
        # Test the payload...
""",
        "Get parameters": """
from app.payloads_integration import get_ssrf_parameters

params = get_ssrf_parameters()  # List of common SSRF params
""",
        "Test utilities": """
from app.payloads_integration import test_parameter_with_payload

result = test_parameter_with_payload(
    base_url="https://example.com/search",
    param_name="url",
    payload="http://127.0.0.1/",
    method="GET"
)
"""
    }
    
    for title, code in examples.items():
        print(f"\n{title}:")
        print(code)


def show_summary():
    """Show summary of integration."""
    print_section("Summary")
    
    print("""
✓ Payloads integrados com sucesso!

Arquivos criados:
  1. app/payloads.py
     - Dicionários com payloads organizados por vulnerabilidade
     - XSS, SQLi, SSRF, LFI, Open Redirect, RCE
  
  2. app/payloads_integration.py
     - Funções auxiliares para usar os payloads
     - Funções de teste e detecção
  
  3. app/example_ssrf_integration.py
     - Exemplos práticos de integração
     - Demonstração com SSRF scanner
  
  4. BUGBOUNTY_CHEATSHEET_INTEGRATION.md
     - Documentação completa
     - Referência de payloads
     - Guia de integração

Próximos passos:
  1. Revisar BUGBOUNTY_CHEATSHEET_INTEGRATION.md
  2. Executar: python app/example_ssrf_integration.py
  3. Integrar gradualmente com seus scanners
  4. Testar com URLs conhecidas (teste em ambiente controlado!)

Informações:
  • Repositório original: https://github.com/EdOverflow/bugbounty-cheatsheet
  • Clone local: cheatsheet-ref/
  • Licença: CC-BY-SA-4.0
""")


if __name__ == "__main__":
    print("\n")
    print("""
    ╔═════════════════════════════════════════════════════════════════════╗
    ║         BugBounty Cheatsheet Integration - Quick Start              ║
    ╚═════════════════════════════════════════════════════════════════════╝
    """)
    
    # Show all payloads
    show_xss_payloads()
    show_sqli_payloads()
    show_ssrf_payloads()
    show_lfi_payloads()
    show_redirect_payloads()
    show_rce_payloads()
    
    # Show integration examples
    show_integration_examples()
    
    # Show summary
    show_summary()
    
    print("\n")
