#!/usr/bin/env python3
"""
Script para mostrar o fluxo completo de scan -> report na base de dados.
Mapeia como os dados fluem e identifica gapings.
"""

import os
from pymongo import MongoClient
from pymongo.errors import OperationFailure

MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://admin:admin%40321@34.193.59.58:27017/admin?authSource=admin",
)

def print_separator(title="", char="=", width=80):
    if title:
        print(f"\n{char * width}")
        print(f" {title}")
        print(char * width)
    else:
        print(char * width)

try:
    client = MongoClient(
        MONGODB_URI,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=3000,
        socketTimeoutMS=10000,
    )
    
    client.admin.command('ping')
    db = client.get_default_database()
    
    print_separator("FLUXO DE SCAN -> REPORT")
    print()
    
    # ═══════════════════════════════════════════════════════════════════════
    # ETAPA 1: DISCOVERY (scan_results)
    # ═══════════════════════════════════════════════════════════════════════
    
    print("1️⃣  ETAPA 1: DISCOVERY (Network Scanner)")
    print("-" * 80)
    
    col_scan = db["scan_results"]
    count_scan = col_scan.count_documents({})
    
    print(f"   Collection: scan_results")
    print(f"   Total de IPs escaneados: {count_scan}")
    print(f"   Origem: Network scanner (SHODAN + Nmap)")
    print(f"   O que contém: IPs, portas abertas, hostnames, dados geográficos")
    
    if count_scan > 0:
        # Dados de exemplo
        sample = col_scan.find_one()
        print(f"\n   Estrutura de um documento:")
        print(f"     {{")
        print(f"       _id: {sample['_id']}")
        print(f"       ip: {sample.get('ip')}")
        print(f"       ports: {sample.get('ports')}")
        print(f"       hostnames: {len(sample.get('hostnames', []))} items")
        print(f"       vulns: {len(sample.get('vulns', []))} items")
        print(f"       timestamp: {sample.get('timestamp')}")
        print(f"     }}")
    
    print()
    
    # ═══════════════════════════════════════════════════════════════════════
    # ETAPA 2: VULNERABILITY SCANNING (vuln_scanner adds to scan_results.vulns)
    # ═══════════════════════════════════════════════════════════════════════
    
    print("2️⃣  ETAPA 2: VULNERABILITY SCANNING (Nuclei + Nmap NSE)")
    print("-" * 80)
    
    # Contar vulnerabilidades detectadas
    total_vulns = 0
    ips_with_vulns = 0
    pipeline = [
        {"$match": {"vulns": {"$not": {"$size": 0}}}},
        {"$count": "total"}
    ]
    result = list(col_scan.aggregate(pipeline))
    ips_with_vulns = result[0]["total"] if result else 0
    
    pipeline = [
        {"$unwind": "$vulns"},
        {"$group": {"_id": None, "total": {"$sum": 1}}}
    ]
    result = list(col_scan.aggregate(pipeline))
    total_vulns = result[0]["total"] if result else 0
    
    print(f"   Collection: scan_results (campo vulns)")
    print(f"   IPs com vulnerabilidades: {ips_with_vulns}")
    print(f"   Total de vulnerabilidades: {total_vulns}")
    print(f"   Origem: Nuclei (testes de seg) + Nmap NSE scripts")
    print(f"   Severidade: critical, high, medium, low, info")
    
    if total_vulns > 0:
        # Distribuição de severidade
        print(f"\n   Distribuição de severidade:")
        pipeline = [
            {"$unwind": "$vulns"},
            {"$group": {"_id": "$vulns.severity", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        for doc in col_scan.aggregate(pipeline):
            sev = doc["_id"] or "unknown"
            cnt = doc["count"]
            pct = (cnt / total_vulns * 100)
            emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
                "info": "🔵"
            }.get(sev, "⚪")
            print(f"     {emoji} {sev:.<20} {cnt:>6} ({pct:>5.1f}%)")
    
    print()
    
    # ═══════════════════════════════════════════════════════════════════════
    # ETAPA 3: BOUNTY TARGETING (bounty_targets)
    # ═══════════════════════════════════════════════════════════════════════
    
    print("3️⃣  ETAPA 3: BOUNTY PROGRAM TARGETING (bounty_targets)")
    print("-" * 80)
    
    col_targets = db["bounty_targets"]
    count_targets = col_targets.count_documents({})
    
    print(f"   Collection: bounty_targets")
    print(f"   Total de targets: {count_targets}")
    print(f"   Propósito: Mapear IPs/domínios para programas de bug bounty")
    print(f"   Origem: bounty_programs (scope) -> Discovery -> Recon")
    
    if count_targets == 0:
        print(f"   ⚠️  AVISO: Collection vazia!")
        print(f"      Isso significa que os IPs descobertos NÃO foram associados a programas.")
        print(f"      Gap: Discovery -> Bounty Targeting")
    
    print()
    
    # ═══════════════════════════════════════════════════════════════════════
    # ETAPA 4: FINAL VULNERABILITY ASSESSMENT (vuln_results)
    # ═══════════════════════════════════════════════════════════════════════
    
    print("4️⃣  ETAPA 4: VULNERABILITY ASSESSMENT (vuln_results)")
    print("-" * 80)
    
    col_vulns = db["vuln_results"]
    count_vulns = col_vulns.count_documents({})
    
    print(f"   Collection: vuln_results")
    print(f"   Total de vulnerabilidades: {count_vulns}")
    print(f"   Propósito: Confirmação final de vulnerabilidades para reporting")
    print(f"   Origem: scan_results.vulns + análise adicional")
    
    if count_vulns == 0:
        print(f"   ⚠️  AVISO: Collection vazia!")
        print(f"      Isso significa que as vulnerabilidades NÃO foram processadas/confirmadas.")
        print(f"      Gap: Vulnerability Scanning -> Assessment")
    
    print()
    
    # ═══════════════════════════════════════════════════════════════════════
    # ETAPA 5: REPORT GENERATION (reports)
    # ═══════════════════════════════════════════════════════════════════════
    
    print("5️⃣  ETAPA 5: REPORT GENERATION (reports)")
    print("-" * 80)
    
    col_reports = db["reports"]
    count_reports = col_reports.count_documents({})
    
    print(f"   Collection: reports")
    print(f"   Total de reports: {count_reports}")
    print(f"   Propósito: Reports formatados para HackerOne")
    print(f"   Origem: vuln_results -> generate_h1_report()")
    
    if count_reports == 0:
        print(f"   ❌ CRÍTICO: Collection vazia!")
        print(f"      Isso significa que NÃO há reports prontos para serem enviados a HackerOne.")
        print(f"      Gap: Assessment -> Report Generation")
    
    print()
    
    # ═══════════════════════════════════════════════════════════════════════
    # ETAPA 6: HACKERONE SUBMISSION (submitted_reports)
    # ═══════════════════════════════════════════════════════════════════════
    
    print("6️⃣  ETAPA 6: HACKERONE SUBMISSION (submitted_reports)")
    print("-" * 80)
    
    try:
        col_submitted = db["submitted_reports"]
        count_submitted = col_submitted.count_documents({})
        print(f"   Collection: submitted_reports")
        print(f"   Total de reports enviados: {count_submitted}")
        print(f"   Propósito: Controlar reports já submetidos a HackerOne")
        print(f"   Origem: reports -> HackerOne API")
    except Exception as e:
        print(f"   Collection: submitted_reports")
        print(f"   Status: AINDA NÃO EXISTE")
    
    print()
    print()
    
    # ═══════════════════════════════════════════════════════════════════════
    # ANÁLISE DOS GAPS
    # ═══════════════════════════════════════════════════════════════════════
    
    print_separator("ANÁLISE DOS GAPS NO FLUXO")
    
    print("\n🔴 PROBLEMA 1: Discovery -> Bounty Targeting")
    print("-" * 80)
    print(f"   IPs descobertos (scan_results):   {count_scan}")
    print(f"   Targets associados (bounty_targets): {count_targets}")
    print(f"   Status: {'✅ OK' if count_targets > 0 else '❌ SEM DADOS'}")
    if count_targets == 0:
        print(f"\n   💡 Solução:")
        print(f"      1. Importar programas de bug bounty (HackerOne)")
        print(f"      2. Mapear escopos dos programas (domínios in-scope)")
        print(f"      3. Executar recon pipeline (bounty.run_recon())")
        print(f"      4. Associar IPs descobertos aos programas")
    
    print()
    print("🔴 PROBLEMA 2: Vulnerability Scanning -> Assessment")
    print("-" * 80)
    print(f"   Vulnerabilidades encontradas (scan_results.vulns): {total_vulns}")
    print(f"   Vulnerabilidades confirmadas (vuln_results): {count_vulns}")
    print(f"   Status: {'✅ OK' if count_vulns > 0 else '❌ SEM DADOS'}")
    if count_vulns == 0:
        print(f"\n   💡 Solução:")
        print(f"      1. Executar scan de vulnerabilidades APÓS mapping de targets")
        print(f"      2. Nuclei scanning (incluir templates personalizadas)")
        print(f"      3. SSRF, IDOR, GraphQL scanning")
        print(f"      4. Armazenar resultados em vuln_results")
    
    print()
    print("🔴 PROBLEMA 3: Assessment -> Report Generation")
    print("-" * 80)
    print(f"   Vulnerabilidades confirmadas (vuln_results): {count_vulns}")
    print(f"   Reports gerados (reports): {count_reports}")
    print(f"   Status: {'✅ OK' if count_reports > 0 else '❌ SEM DADOS'}")
    if count_reports == 0:
        print(f"\n   💡 Solução:")
        print(f"      1. Para cada programa com vulns:")
        print(f"      2. Chamar generate_h1_report() com base em vuln_results")
        print(f"      3. Armazenar report formatado em collection 'reports'")
        print(f"      4. Incluir CVSS score, PoC, remediation")
    
    print()
    print("🔴 PROBLEMA 4: Report Generation -> HackerOne Submission")
    print("-" * 80)
    print(f"   Reports gerados (reports): {count_reports}")
    print(f"   Reports enviados? Desconhecido (verificar API)")
    if count_reports > 0:
        print(f"   Status: ⚠️  Reports esperando envio")
        print(f"\n   💡 Solução:")
        print(f"      1. Chamar POST /api/bounty/programs/{{id}}/submit_hackerone")
        print(f"      2. Usar HACKERONE_API_USERNAME + HACKERONE_API_TOKEN")
        print(f"      3. Registrar em submitted_reports para evitar duplicatas")
    else:
        print(f"   Status: ❌ Nenhum report disponível ainda")
    
    print()
    print()
    
    # ═══════════════════════════════════════════════════════════════════════
    # FLUXO VISUAL
    # ═══════════════════════════════════════════════════════════════════════
    
    print_separator("FLUXO VISUAL COMPLETO")
    
    flow = f"""
    Network Discovery           Vulnerability Scan          Assessment
    ─────────────────          ────────────────────        ──────────
    
         SHODAN                      Nuclei                vuln_results
         Nmap                        SSRF Scanner               DB
           ↓                           IDOR Scan               ↓
           │                         GraphQL Scan             │
           │                           ↓                      │
           └──→ scan_results ────→ scan_results.vulns ──→ [Assessment]
               (300 docs)              (3533 vulns)        (0 docs stored)
                                                                ↓
    
    Report Generation             HackerOne Submission
    ──────────────────            ────────────────────
    
    Bounty Program                     API Request
    Matching                           with Token
         ↓                                ↓
    vuln_results                   submitted_reports
    (0 docs)                            (? docs)
         ↓                                ↑
    generate_h1_report() ──→ reports ────→ HackerOne
                            (0 docs)
    
    Status: ❌ Fluxo INTERROMPIDO em 3 pontos críticos
    
    Próxima ação: Completar o pipeline iniciando com bounty program mapping.
    """
    
    print(flow)
    
    print()
    print_separator("RESUMO DE AÇÕES NECESSÁRIAS")
    
    print("""
    URGENTE:
    1. ✅ Scan já funcionando (300 IPs, 3533 vulns)
    2. ⚠️  Gap 1: Associar IPs a programas de bug bounty
    3. ⚠️  Gap 2: Confirmar vulnerabilidades (vuln_results)
    4. ⚠️  Gap 3: Gerar reports formatados para H1
    5. ⚠️  Gap 4: Enviar para HackerOne API
    
    Para iniciar o fluxo completo:
    
    # 1. Importar programas HackerOne
    curl -X POST http://localhost:8000/api/bounty/programs/sync
    
    # 2. Executar recon para encontrar domínios
    curl -X POST http://localhost:8000/api/bounty/recon/manual
    
    # 3. Executar scanning de vulns nos domínios encontrados
    curl -X POST http://localhost:8000/api/bounty/vulnerability-scan
    
    # 4. Gerar report
    curl http://localhost:8000/api/bounty/report/{program_id}
    
    # 5. Enviar para HackerOne
    curl -X POST http://localhost:8000/api/bounty/programs/{program_id}/submit_hackerone
    """)
    
    print()
    
    client.close()
    
except Exception as e:
    print(f"❌ Erro: {e}")
    import traceback
    traceback.print_exc()
