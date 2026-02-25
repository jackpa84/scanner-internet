#!/bin/bash
# Script: generate_project.sh
# Descrição: Gera a estrutura completa do projeto scanner-internet com detecção de roteadores e dashboard.
# Uso: chmod +x generate_project.sh && ./generate_project.sh

set -e  # interrompe em caso de erro

echo "Criando diretórios..."
mkdir -p app/templates

echo "Criando pyproject.toml..."
cat > pyproject.toml << 'EOF'
[tool.poetry]
name = "scanner-internet"
version = "0.1.0"
description = "Varredura aleatória de IPs com armazenamento em banco e dashboard"
authors = ["Seu Nome <email@example.com>"]

[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.31.0"
sqlalchemy = "^2.0.23"
psycopg2-binary = "^2.9.9"
flask = "^3.0.0"
flask-sqlalchemy = "^3.1.1"
python-dotenv = "^1.0.0"
schedule = "^1.2.0"

[tool.poetry.dev-dependencies]
pytest = "^7.4.0"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
EOF

echo "Criando Dockerfile..."
cat > Dockerfile << 'EOF'
FROM python:3.10-slim AS builder

WORKDIR /app

RUN pip install poetry

COPY pyproject.toml poetry.lock* ./

RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root

FROM python:3.10-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY app/ ./app/

ENV DATABASE_URL=postgresql://user:password@db:5432/scanner_db

EXPOSE 5000

CMD ["python", "-m", "app.dashboard"]
EOF

echo "Criando docker-compose.yml..."
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  db:
    image: postgres:15
    container_name: scanner_db
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
      POSTGRES_DB: scanner_db
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user -d scanner_db"]
      interval: 10s
      timeout: 5s
      retries: 5

  app:
    build: .
    container_name: scanner_app
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "5000:5000"
    environment:
      DATABASE_URL: postgresql://user:password@db:5432/scanner_db
    volumes:
      - ./app:/app/app
    restart: unless-stopped

volumes:
  postgres_data:
EOF

echo "Criando app/__init__.py (vazio)..."
touch app/__init__.py

echo "Criando app/models.py..."
cat > app/models.py << 'EOF'
from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class ScanResult(Base):
    __tablename__ = 'scan_results'

    id = Column(Integer, primary_key=True)
    ip = Column(String(15), nullable=False)
    ports = Column(JSON)
    vulns = Column(JSON)
    hostnames = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)

    router_info = relationship("RouterInfo", back_populates="scan_result", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ScanResult(ip='{self.ip}', ports={self.ports})>"

class RouterInfo(Base):
    __tablename__ = 'router_info'

    id = Column(Integer, primary_key=True)
    scan_result_id = Column(Integer, ForeignKey('scan_results.id'))
    ip = Column(String(15))
    port = Column(Integer)
    service = Column(String(50))
    banner = Column(String(500))
    title = Column(String(200))
    server = Column(String(200))
    device_type = Column(String(100))
    timestamp = Column(DateTime, default=datetime.utcnow)

    scan_result = relationship("ScanResult", back_populates="router_info")
EOF

echo "Criando app/database.py..."
cat > app/database.py << 'EOF'
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/scanner_db")

engine = create_engine(DATABASE_URL)
SessionLocal = scoped_session(sessionmaker(bind=engine))

def init_db():
    from app.models import Base
    Base.metadata.create_all(bind=engine)
EOF

echo "Criando app/scanner.py..."
cat > app/scanner.py << 'EOF'
import random
import requests
import time
import logging
import socket
from urllib.parse import urlparse
from app.database import SessionLocal
from app.models import ScanResult, RouterInfo

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Desabilitar warnings de SSL para requisições simples
requests.packages.urllib3.disable_warnings()

def generate_random_ip():
    """Gera um IP público aleatório (primeiro octeto 1-223)"""
    first = random.randint(1, 223)
    rest = [random.randint(0, 255) for _ in range(3)]
    return f"{first}.{rest[0]}.{rest[1]}.{rest[2]}"

def query_internetdb(ip):
    """Consulta o InternetDB (Shodan) e retorna os dados ou None"""
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return None
        else:
            logger.warning(f"Erro na consulta de {ip}: HTTP {resp.status_code}")
            return None
    except Exception as e:
        logger.error(f"Exceção ao consultar {ip}: {e}")
        return None

def probe_http(ip, port, ssl_flag=False):
    """Tenta obter título e servidor de uma página web"""
    protocol = "https" if ssl_flag else "http"
    url = f"{protocol}://{ip}:{port}"
    try:
        resp = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        server = resp.headers.get('Server', '')
        title = ''
        if '<title>' in resp.text:
            start = resp.text.find('<title>') + 7
            end = resp.text.find('</title>', start)
            if end > start:
                title = resp.text[start:end].strip()
        return {'service': protocol, 'port': port, 'server': server[:200], 'title': title[:200]}
    except Exception as e:
        return None

def probe_ssh(ip, port=22):
    """Tenta obter banner SSH"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return {'service': 'ssh', 'port': port, 'banner': banner[:500]}
    except Exception:
        return None

def probe_telnet(ip, port=23):
    """Tenta obter banner Telnet"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return {'service': 'telnet', 'port': port, 'banner': banner[:500]}
    except Exception:
        return None

def probe_router_services(ip, ports):
    """Varre serviços comuns em roteadores e retorna lista de dict com informações"""
    results = []
    # HTTP/HTTPS
    if 80 in ports:
        res = probe_http(ip, 80, ssl_flag=False)
        if res:
            results.append(res)
    if 443 in ports:
        res = probe_http(ip, 443, ssl_flag=True)
        if res:
            results.append(res)
    if 8080 in ports:
        res = probe_http(ip, 8080, ssl_flag=False)
        if res:
            results.append(res)
    if 8443 in ports:
        res = probe_http(ip, 8443, ssl_flag=True)
        if res:
            results.append(res)
    # SSH
    if 22 in ports:
        res = probe_ssh(ip, 22)
        if res:
            results.append(res)
    # Telnet
    if 23 in ports:
        res = probe_telnet(ip, 23)
        if res:
            results.append(res)
    return results

def scan_and_save():
    """Gera um IP, consulta e salva no banco se houver dados"""
    ip = generate_random_ip()
    logger.info(f"Testando IP: {ip}")
    data = query_internetdb(ip)
    if data and (data.get("ports") or data.get("vulns")):
        session = SessionLocal()
        result = ScanResult(
            ip=ip,
            ports=data.get("ports", []),
            vulns=data.get("vulns", []),
            hostnames=data.get("hostnames", [])
        )
        session.add(result)
        session.flush()  # para obter o id do scan_result

        # Tentar detectar serviços de roteador
        router_info_list = probe_router_services(ip, data.get("ports", []))
        for info in router_info_list:
            router_info = RouterInfo(
                scan_result_id=result.id,
                ip=ip,
                port=info.get('port'),
                service=info.get('service'),
                banner=info.get('banner', ''),
                title=info.get('title', ''),
                server=info.get('server', ''),
                device_type=''  # pode ser inferido depois
            )
            session.add(router_info)

        session.commit()
        session.close()
        logger.info(f"  -> ENCONTRADO: {ip} | Portas: {data.get('ports')} | Router services: {len(router_info_list)}")
    else:
        logger.info(f"  -> Nada encontrado para {ip}")

def run_scanner(interval=5):
    """Executa varredura infinita com pausa de 'interval' segundos"""
    logger.info("Iniciando varredura aleatória... Pressione CTRL+C para parar.")
    try:
        while True:
            scan_and_save()
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Varredura interrompida pelo usuário.")
EOF

echo "Criando app/dashboard.py..."
cat > app/dashboard.py << 'EOF'
from flask import Flask, render_template, jsonify
from app.database import SessionLocal, init_db
from app.models import ScanResult, RouterInfo
from app.scanner import run_scanner
import threading
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/results')
def api_results():
    session = SessionLocal()
    results = session.query(ScanResult).order_by(ScanResult.timestamp.desc()).limit(100).all()
    data = []
    for r in results:
        # contar quantos router_info tem
        router_count = len(r.router_info) if r.router_info else 0
        data.append({
            'id': r.id,
            'ip': r.ip,
            'ports': r.ports,
            'vulns': r.vulns,
            'hostnames': r.hostnames,
            'timestamp': r.timestamp.isoformat() if r.timestamp else None,
            'router_count': router_count
        })
    session.close()
    return jsonify(data)

@app.route('/api/router_info/<int:scan_id>')
def api_router_info(scan_id):
    session = SessionLocal()
    infos = session.query(RouterInfo).filter(RouterInfo.scan_result_id == scan_id).all()
    data = [
        {
            'port': i.port,
            'service': i.service,
            'banner': i.banner,
            'title': i.title,
            'server': i.server,
            'timestamp': i.timestamp.isoformat() if i.timestamp else None
        }
        for i in infos
    ]
    session.close()
    return jsonify(data)

@app.route('/api/stats')
def api_stats():
    session = SessionLocal()
    total = session.query(ScanResult).count()
    with_ports = session.query(ScanResult).filter(ScanResult.ports != []).count()
    with_vulns = session.query(ScanResult).filter(ScanResult.vulns != []).count()
    with_router_info = session.query(RouterInfo).distinct(RouterInfo.scan_result_id).count()
    session.close()
    return jsonify({'total': total, 'with_ports': with_ports, 'with_vulns': with_vulns, 'with_router_info': with_router_info})

def start_scanner_thread():
    t = threading.Thread(target=run_scanner, args=(5,), daemon=True)
    t.start()

if __name__ == '__main__':
    init_db()
    start_scanner_thread()
    app.run(host='0.0.0.0', port=5000, debug=False)
EOF

echo "Criando app/templates/index.html..."
cat > app/templates/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Scanner Internet - Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .router-icon { cursor: pointer; color: blue; text-decoration: underline; }
        .modal { display: none; position: fixed; z-index: 1; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4); }
        .modal-content { background-color: #fefefe; margin: 15% auto; padding: 20px; border: 1px solid #888; width: 80%; }
        .close { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Scanner de Internet - Resultados</h1>
    <div style="width: 400px; height: 400px;">
        <canvas id="statsChart"></canvas>
    </div>
    <h2>Últimos 100 IPs encontrados</h2>
    <table id="resultsTable">
        <thead>
            <tr>
                <th>IP</th>
                <th>Portas</th>
                <th>Vulnerabilidades</th>
                <th>Hostnames</th>
                <th>Router Info</th>
                <th>Timestamp</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>

    <!-- Modal para detalhes do roteador -->
    <div id="routerModal" class="modal">
        <div class="modal-content">
            <span class="close">&times;</span>
            <h3>Informações do Roteador</h3>
            <div id="routerDetails"></div>
        </div>
    </div>

    <script>
        let currentScanId = null;

        async function loadStats() {
            const res = await fetch('/api/stats');
            const data = await res.json();
            const ctx = document.getElementById('statsChart').getContext('2d');
            new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: ['Com portas', 'Com vulns', 'Com info roteador', 'Total'],
                    datasets: [{
                        data: [data.with_ports, data.with_vulns, data.with_router_info, data.total],
                        backgroundColor: ['#36a2eb', '#ff6384', '#ffcd56', '#4bc0c0']
                    }]
                }
            });
        }

        async function loadResults() {
            const res = await fetch('/api/results');
            const results = await res.json();
            const tbody = document.querySelector('#resultsTable tbody');
            tbody.innerHTML = '';
            results.forEach(r => {
                const row = tbody.insertRow();
                row.insertCell().textContent = r.ip;
                row.insertCell().textContent = r.ports.join(', ') || 'Nenhuma';
                row.insertCell().textContent = r.vulns.join(', ') || 'Nenhuma';
                row.insertCell().textContent = r.hostnames.join(', ') || 'Nenhum';
                
                const routerCell = row.insertCell();
                if (r.router_count > 0) {
                    const link = document.createElement('span');
                    link.className = 'router-icon';
                    link.textContent = `Ver (${r.router_count})`;
                    link.onclick = () => showRouterInfo(r.id);
                    routerCell.appendChild(link);
                } else {
                    routerCell.textContent = 'Nenhum';
                }
                
                row.insertCell().textContent = new Date(r.timestamp).toLocaleString();
            });
        }

        async function showRouterInfo(scanId) {
            currentScanId = scanId;
            const res = await fetch(`/api/router_info/${scanId}`);
            const data = await res.json();
            const detailsDiv = document.getElementById('routerDetails');
            if (data.length === 0) {
                detailsDiv.innerHTML = '<p>Nenhuma informação adicional.</p>';
            } else {
                let html = '<table><tr><th>Porta</th><th>Serviço</th><th>Banner/Título</th><th>Server</th></tr>';
                data.forEach(i => {
                    let bannerOrTitle = i.title || i.banner || '';
                    html += `<tr>
                        <td>${i.port}</td>
                        <td>${i.service}</td>
                        <td>${bannerOrTitle}</td>
                        <td>${i.server || ''}</td>
                    </tr>`;
                });
                html += '</table>';
                detailsDiv.innerHTML = html;
            }
            document.getElementById('routerModal').style.display = 'block';
        }

        // Fechar modal
        document.querySelector('.close').onclick = function() {
            document.getElementById('routerModal').style.display = 'none';
        }
        window.onclick = function(event) {
            const modal = document.getElementById('routerModal');
            if (event.target == modal) {
                modal.style.display = 'none';
            }
        }

        loadStats();
        loadResults();
        setInterval(loadResults, 30000);
    </script>
</body>
</html>
EOF

echo "Criando README.md..."
cat > README.md << 'EOF'
# Scanner de Internet

Este projeto realiza varreduras aleatórias de IPs públicos, consulta o serviço gratuito InternetDB (Shodan) para obter portas abertas e vulnerabilidades, e armazena os resultados em um banco de dados PostgreSQL. Além disso, para IPs com portas comuns, tenta identificar serviços de roteadores (HTTP, HTTPS, SSH, Telnet) e exibe as informações em um dashboard web.

## Funcionalidades

- Geração aleatória de IPs públicos.
- Consulta ao InternetDB (https://internetdb.shodan.io) para cada IP.
- Armazenamento de IPs com portas ou vulnerabilidades em banco PostgreSQL.
- Detecção adicional de serviços em portas comuns de roteadores (80,443,8080,8443,22,23) com captura de banners/títulos.
- Dashboard web com estatísticas e listagem dos últimos 100 IPs encontrados, com detalhes dos serviços de roteador.

## Tecnologias

- Python 3.10
- Poetry para gerenciamento de dependências
- Flask (dashboard)
- SQLAlchemy (ORM)
- PostgreSQL
- Docker / Docker Compose

## Como executar

1. Certifique-se de ter Docker e Docker Compose instalados.
2. Clone este repositório ou gere os arquivos com o script `generate_project.sh`.
3. No diretório raiz, execute:

   ```bash
   docker-compose up --build
