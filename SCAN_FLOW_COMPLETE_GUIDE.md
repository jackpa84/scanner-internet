# 📊 FLUXO COMPLETO: SCAN → REPORT → HACKERONE

## Situação Atual

```
✅ Dados Coletados:  300 IPs escaneados, 3533 vulnerabilidades detectadas
❌ Reports Gerados:  0 reports
❌ Reports Enviados: 0 enviados
```

---

## 🔄 As 6 Etapas do Pipeline

### **1️⃣ STAGE 1: DISCOVERY (Network Scanner)**
**Status:** ✅ **FUNCIONANDO** 

```
SHODAN + Nmap → IPs, Portas, Hostnames
         ↓
    scan_results (300 docs)
    {
      "ip": "193.26.157.52",
      "ports": [80, 110, 143, 443, ...],
      "hostnames": ["mail.fafuse.de", ...],
      "geo": { "country": "DE", ... }
    }
```

**Saída:** 300 IPs mapeados com informações de infraestrutura

---

### **2️⃣ STAGE 2: VULNERABILITY SCANNING (Nuclei + NSE)**
**Status:** ✅ **FUNCIONANDO**

```
Nuclei Templates + Nmap NSE → Detecta vulns
         ↓
    scan_results.vulns (3533 vulns)
    {
      "title": "SSL Certificate Expired",
      "severity": "high",
      "type": "tls",
      "confidence": 95
    }
```

**Saída:** 3533 vulnerabilidades detectadas em 92 IPs
- ⚪ 3533 vulnerabilidades (severidade não classificada)

**⚠️ Problema**: Severidade aparece como "unknown" - precisa de validation

---

### **3️⃣ STAGE 3: BOUNTY TARGETING (Associar IPs a Programas)**
**Status:** ❌ **NÃO IMPLEMENTADO**

```
bounty_programs (scope) + discovery → Associates IPs
         ↓
    bounty_targets (EMPTY - 0 docs)
    {
      "program_id": "...",
      "domain": "example.com",
      "ips": ["1.2.3.4", "5.6.7.8"],
      "is_in_scope": true
    }
```

**Gap:** Os 300 IPs NÃO foram associados a programas de bug bounty.

**Solução:**
```bash
# 1. Importar programas HackerOne
curl -X POST http://localhost:8000/api/bounty/programs/sync

# 2. Executar recon para mapear domínios
curl -X POST http://localhost:8000/api/bounty/recon/manual

# 3. Correlacionar IPs com programa scope
# (automático no bounty pipeline)
```

---

### **4️⃣ STAGE 4: VULNERABILITY ASSESSMENT**
**Status:** ❌ **NÃO EXECUTADO**

```
scan_results.vulns + bounty_targets confirmação
         ↓
    vuln_results (EMPTY - 0 docs)
    {
      "ip": "1.2.3.4",
      "domain": "target.com",
      "program_id": "...",
      "title": "XSS Vulnerability",
      "severity": "high",
      "cvss_score": 7.5,
      "poc": "curl ... --data '<script>alert(1)</script>'",
      "remediation": "Sanitize user input..."
    }
```

**Gap:** As 3533 vulnerabilidades NÃO foram confirmadas ou preparadas para reporting.

**Solução:**
```python
# Em app/main.py ou via API:
for vuln in scan_results.find({"vulns": {"$not": {"$size": 0}}}):
    # Validar e enrichir vulnerabilidade
    # Confirmar severidade
    # Calcular CVSS score
    # Gerar PoC
    vuln_results.insert_one(confirmed_vuln)
```

---

### **5️⃣ STAGE 5: REPORT GENERATION**
**Status:** ❌ **NÃO EXECUTADO**

```
vuln_results + program context → HackerOne report
         ↓
    reports (EMPTY - 0 docs)
    {
      "program_id": "...",
      "title": "Security Vulnerabilities Report",
      "vulnerability_information": "...",
      "impact": "...",
      "steps_to_reproduce": "...",
      "remediation": "...",
      "severity_rating": "high",
      "timestamp": "2026-03-02T..."
    }
```

**Gap:** Nenhum report foi gerado para HackerOne.

**Solução:**
```python
from app.report_generator import generate_h1_report

for program in bounty_programs.find():
    vulns = vuln_results.find({"program_id": program["_id"]})
    if vulns:
        report = generate_h1_report(
            domain=program["domain"],
            findings=vulns,
            program_name=program["name"]
        )
        reports.insert_one(report)
```

---

### **6️⃣ STAGE 6: HACKERONE SUBMISSION**
**Status:** ❌ **SEM DADOS**

```
reports → HackerOne API (com credentials)
         ↓
    submitted_reports (0 docs)
    {
      "report_id": "...",
      "h1_id": "1234567",
      "program_id": "...",
      "status": "submitted",
      "timestamp": "2026-03-02T...",
      "response": {...}
    }
```

**Gap:** Sem reports para enviar.

**Solução (após ter reports):**
```bash
curl -X POST http://localhost:8000/api/bounty/programs/{program_id}/submit_hackerone \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Security Report",
    "vulnerability_information": "...",
    "severity_rating": "high"
  }'
```

---

## 🎯 Fluxo Resumido

```
┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐
│ Discovery│      │  Vulns   │      │  Assess  │      │  Report  │      │   H1     │
│  Scanner │ ───→ │ Scanning │ ───→ │ Vulns    │ ───→ │Generate  │ ───→ │ Submit   │
│          │      │          │      │ Results  │      │          │      │          │
└──────────┘      └──────────┘      └──────────┘      └──────────┘      └──────────┘
   ✅ 300 IPs        ✅ 3533         ❌ 0 docs        ❌ 0 docs       ❌ Não pronto
  escaneados         vulns           armazenados      gerados
  
   **⚠️ O fluxo está quebrado em 3 pontos críticos**
```

---

## 📋 Checklist para Funcionar Completamente

**PRIORIDADE ALTA:**

- [ ] **GAP 1**: Importar programas HackerOne (bounty_programs)
  - Rodar: `POST /api/bounty/programs/sync`
  - Resultado esperado: Lista de programas com scope

- [ ] **GAP 2**: Correlacionar IPs descobertos com programas
  - Rodar: `POST /api/bounty/recon/manual` (por programa)
  - Resultado esperado: bounty_targets com IPs associados

- [ ] **GAP 3**: Processar vulnerabilidades em vuln_results
  - Script Python para migrar scan_results.vulns → vuln_results
  - Enriquecer com CVSS, PoC, remediation
  - Resultado esperado: 3533 vulns em vuln_results

- [ ] **GAP 4**: Gerar reports formatados para H1
  - Rodar: `POST /api/bounty/report/{program_id}` para cada programa
  - Armazenar em collection 'reports'
  - Resultado esperado: N reports prontos

- [ ] **GAP 5**: Enviar reports a HackerOne
  - Usar: `POST /api/bounty/programs/{program_id}/submit_hackerone`
  - Requer: HACKERONE_API_USERNAME + HACKERONE_API_TOKEN
  - Resultado esperado: Reports com status "submitted"

---

## 🔧 Próximos Passos Recomendados

### Curto Prazo (1-2 horas):
```bash
# 1. Verificar se há programas importados
curl http://localhost:8000/api/bounty/programs

# 2. Se vazio, importar programas via web UI ou API
curl -X POST http://localhost:8000/api/bounty/programs/import \
  -H "Content-Type: application/json" \
  -d '{"url": "https://hackerone.com/company"}'

# 3. Executar recon em um programa
curl -X POST http://localhost:8000/api/bounty/programs/{id}/recon

# 4. Verificar bounty_targets depois
curl http://localhost:8000/api/bounty/targets
```

### Médio Prazo (2-4 horas):
```python
# Script para migrar vulns para vuln_results
# File: migrate_vulns_to_assessment.py
from app.database import get_scan_results, get_vuln_results
from app.report_generator import calculate_confidence, deduplicate_findings

scan_col = get_scan_results()
vuln_col = get_vuln_results()

for scan in scan_col.find({"vulns": {"$not": {"$size": 0}}}):
    for vuln in scan["vulns"]:
        # Enriquecer vulnerabilidade
        vuln["ip"] = scan["ip"]
        vuln["confidence"] = calculate_confidence(vuln)
        
        # Armazenar
        vuln_col.insert_one(vuln)

print(f"✅ Migradas {vuln_col.count_documents({})} vulnerabilidades")
```

### Longo Prazo (4+ horas):
```bash
# Automação completa via dashboar web ou scheduler
# Configure em production:
# - Recon scheduling (6h em 6h)
# - Auto-scanning de novos targets
# - Auto-generation de reports
# - Auto-submit a HackerOne (with approval)
```

---

## 📊 Métricas Esperadas Após Completo

```
Etapa                  Atual    Esperado
─────────────────────────────────────────
Scan Results           300      300+ (conforme novos IPs descobertos)
Vulnerabilidades       3533     3533+ (confirmadas e enriquecidas)
Bounty Targets         0        100+ (1 por domínio/programa)
Vuln Results           0        3533+ (confirmadas e formatadas)
Reports                0        10-50 (1 por programa com vulns)
Submitted to H1        0        5-20 (conforme aprovação)
Earnings               $0       $1,000+ (por report aceito)
```

---

## 🚀 Conclusão

O sistema tem uma **infraestrutura sólida** para descobrir vulnerabilidades, mas **falta a integração com o pipeline de bug bounty**. Os 3 gaps principais são:

1. **Bounty Program Mapping** - Associar descobertas a programas
2. **Vulnerability Assessment** - Confirmar e enriquecer vulns
3. **Report Generation & Submission** - Gerar reports H1 e enviar

Uma vez completado este pipeline, o sistema poderá gerar **reports de qualidade alta** e **submeter automaticamente para HackerOne**.

