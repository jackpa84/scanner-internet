#!/bin/bash
set -euo pipefail

BACKEND_IP="3.219.167.54"
KEY_FILE="scanner-key-2.pem"

echo "==> Configurando BACKEND ($BACKEND_IP)..."

ssh -i "$KEY_FILE" -o StrictHostKeyChecking=no ubuntu@"$BACKEND_IP" bash <<'REMOTE'
set -e
cd /home/ubuntu/app

# Criar docker-compose.yml apenas com backend essencial
cat > docker-compose.yml << 'EOF'
services:
  redis:
    image: redis:7-alpine
    platform: linux/amd64
    container_name: scanner_redis
    ports:
      - "6379:6379"
    command: redis-server --maxmemory 100mb --maxmemory-policy allkeys-lru
    restart: unless-stopped

  mongo:
    image: mongo:7
    platform: linux/amd64
    container_name: scanner_mongo
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: admin123
    restart: unless-stopped
    volumes:
      - mongo_data:/data/db

  app:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        - BUILDKIT_INLINE_CACHE=1
    platform: linux/amd64
    container_name: scanner_app
    depends_on:
      - redis
      - mongo
    ports:
      - "5001:5000"
    environment:
      MONGODB_URL: "mongodb://admin:admin123@mongo:27017/scanner"
      REDIS_URL: "redis://redis:6379/0"
      NUM_WORKERS: "2"
      MAX_CONCURRENT_CONNS: "20"
    restart: unless-stopped
    volumes:
      - ./app:/app/app

volumes:
  mongo_data:

networks:
  default:
    name: scanner_net
EOF

echo "✅ Aguardando Docker..."
for i in $(seq 1 30); do
  if sudo docker info >/dev/null 2>&1; then 
    echo "✅ Docker pronto"
    break
  fi
  sleep 3
done

echo "✅ Limpando containers antigos..."
sudo docker compose down -v 2>/dev/null || true

echo "📥 Fazendo pull de imagens..."
sudo docker compose pull redis mongo 2>&1 | grep -E 'Pulling|Downloaded|Digest' | tail -10

echo "🚀 Iniciando Redis e MongoDB..."
sudo docker compose up -d redis mongo 2>&1 | tail -5
sleep 20

echo "🔨 Build da aplicação..."
sudo docker compose build app 2>&1 | tail -30 || echo "Build com warnings (OK)"

echo "🚀 Iniciando aplicação..."
sudo docker compose up -d app 2>&1 | tail -5

echo ""
echo "=== CONTAINERS RODANDO ==="
sudo docker compose ps

REMOTE

echo ""
echo "✅ Backend configurado na AWS!"
echo "   API: http://3.219.167.54:5001"
echo "   API Docs: http://3.219.167.54:5001/docs"
