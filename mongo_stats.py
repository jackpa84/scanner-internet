#!/usr/bin/env python3
"""
Script para obter resumo completo da base MongoDB.
"""

import os
from pymongo import MongoClient
from datetime import datetime

MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://admin:admin%40321@34.193.59.58:27017/admin?authSource=admin",
)

try:
    client = MongoClient(
        MONGODB_URI,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=3000,
        socketTimeoutMS=10000,
    )
    
    client.admin.command('ping')
    print("\n✓ MongoDB conectado com sucesso\n")
    
    db = client.get_default_database()
    
    print("=" * 70)
    print(" 📊 ESTATÍSTICAS DAS COLLECTIONS")
    print("=" * 70)
    print()
    
    # ── COLLECTION: scan_results ──
    col_scan = db["scan_results"]
    count_scan = col_scan.count_documents({})
    
    print(f"📍 SCAN_RESULTS")
    print("-" * 70)
    print(f"   Total de documentos: {count_scan}")
    
    if count_scan > 0:
        # IPs com vulnerabilidades
        vulns_pipeline = [
            {"$match": {"vulns": {"$not": {"$size": 0}}}},
            {"$count": "total"}
        ]
        result = list(col_scan.aggregate(vulns_pipeline))
        ips_with_vulns = result[0]["total"] if result else 0
        
        print(f"   IPs com vulnerabilidades: {ips_with_vulns}")
        
        # Total de vulnerabilidades
        total_vulns_pipeline = [
            {"$unwind": "$vulns"},
            {"$group": {"_id": None, "total": {"$sum": 1}}}
        ]
        result = list(col_scan.aggregate(total_vulns_pipeline))
        total_vulns = result[0]["total"] if result else 0
        
        print(f"   Total de vulnerabilidades detectadas: {total_vulns}")
        
        # Data mais recente
        latest = col_scan.find_one(sort=[("timestamp", -1)])
        if latest:
            ts = latest.get("timestamp")
            if ts:
                print(f"   Último scan: {ts.strftime('%d/%m/%Y %H:%M:%S')}")
        
        # Data mais antiga
        oldest = col_scan.find_one(sort=[("timestamp", 1)])
        if oldest:
            ts = oldest.get("timestamp")
            if ts:
                print(f"   Primeiro scan: {ts.strftime('%d/%m/%Y %H:%M:%S')}")
        
        # Top 5 vulnerabilidades
        print(f"\n   Top 5 vulnerabilidades mais encontradas:")
        vulns_top = col_scan.aggregate([
            {"$unwind": "$vulns"},
            {"$group": {"_id": "$vulns.title", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5}
        ])
        
        for i, doc in enumerate(vulns_top, 1):
            title = doc["_id"] if doc["_id"] else "sem_título"
            if len(str(title)) > 50:
                title = str(title)[:50] + "..."
            count = doc["count"]
            print(f"     {i}. {title:.<50} {count:>5}")
        
        # Top 5 IPs
        print(f"\n   Top 5 IPs escaneados:")
        ips_top = col_scan.find().limit(5)
        
        for i, doc in enumerate(ips_top, 1):
            ip = doc.get("ip", "desconhecido")
            vulns_count = len(doc.get("vulns", []))
            print(f"     {i}. {ip:.<35} {vulns_count:>5} vulns")
    
    print()
    
    # ── COLLECTION: reports ──
    col_reports = db["reports"]
    count_reports = col_reports.count_documents({})
    
    print(f"📋 REPORTS")
    print("-" * 70)
    print(f"   Total de documentos: {count_reports}")
    
    if count_reports == 0:
        print(f"   ⚠️  Nenhum report persistido ainda (collection vazia)")
    else:
        # Estatísticas dos reports
        print(f"   Status:")
        status_pipeline = [
            {"$group": {"_id": "$status", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        for doc in col_reports.aggregate(status_pipeline):
            status = doc["_id"] or "sem_status"
            count = doc["count"]
            pct = (count / count_reports * 100)
            print(f"     • {status:.<30} {count:>5} ({pct:>5.1f}%)")
    
    print()
    
    # ── COLLECTION: vuln_results ──
    col_vulns = db["vuln_results"]
    count_vulns = col_vulns.count_documents({})
    
    print(f"🔴 VULN_RESULTS")
    print("-" * 70)
    print(f"   Total de documentos: {count_vulns}")
    
    print()
    print("=" * 70)
    print(f"📈 RESUMO GERAL")
    print("=" * 70)
    print(f"   Scan Results:    {count_scan:>10} docs")
    print(f"   Reports:         {count_reports:>10} docs")
    print(f"   Vuln Results:    {count_vulns:>10} docs")
    print(f"   TOTAL:           {count_scan + count_reports + count_vulns:>10} docs")
    print("=" * 70)
    print()
    
    client.close()
    
except Exception as e:
    print(f"❌ Erro: {e}")
    import traceback
    traceback.print_exc()
