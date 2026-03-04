#!/usr/bin/env bash
set -euo pipefail
export AWS_PAGER=""

# ─── Config ──────────────────────────────────────────────────────────
REGION="us-east-1"
INSTANCE_TYPE="t3.micro"    # 1 vCPU, 1GB RAM — Free Tier
KEY_NAME="scanner-key"
SG_NAME="scanner-sg"
APP_NAME="scanner-internet"

echo "==> Deploy $APP_NAME para AWS EC2 ($REGION)"

# ─── 1. Criar key pair (se não existe) ───────────────────────────────
if ! aws ec2 describe-key-pairs --key-names "$KEY_NAME" --region "$REGION" >/dev/null 2>&1; then
  echo "==> Criando key pair: $KEY_NAME"
  aws ec2 create-key-pair \
    --key-name "$KEY_NAME" \
    --region "$REGION" \
    --query 'KeyMaterial' \
    --output text > "${KEY_NAME}.pem"
  chmod 400 "${KEY_NAME}.pem"
  echo "    Chave salva em ${KEY_NAME}.pem"
else
  echo "==> Key pair $KEY_NAME já existe"
fi

# ─── 2. Criar Security Group ────────────────────────────────────────
VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" \
  --filters "Name=is-default,Values=true" \
  --query 'Vpcs[0].VpcId' --output text)

if ! aws ec2 describe-security-groups --group-names "$SG_NAME" --region "$REGION" >/dev/null 2>&1; then
  echo "==> Criando security group: $SG_NAME"
  SG_ID=$(aws ec2 create-security-group \
    --group-name "$SG_NAME" \
    --description "Scanner Internet - SSH, App, Frontend, MongoDB" \
    --vpc-id "$VPC_ID" \
    --region "$REGION" \
    --query 'GroupId' --output text)

  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 22 --cidr 0.0.0.0/0
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 5001 --cidr 0.0.0.0/0
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 3000 --cidr 0.0.0.0/0
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 27017 --cidr 0.0.0.0/0

  echo "    SG criado: $SG_ID"
else
  SG_ID=$(aws ec2 describe-security-groups --group-names "$SG_NAME" --region "$REGION" \
    --query 'SecurityGroups[0].GroupId' --output text)
  echo "==> Security group já existe: $SG_ID"
fi

# ─── 3. Buscar AMI Ubuntu 22.04 ─────────────────────────────────────
AMI_ID=$(aws ec2 describe-images --region "$REGION" \
  --owners 099720109477 \
  --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" \
             "Name=state,Values=available" \
  --query 'Images | sort_by(@,&CreationDate) | [-1].ImageId' \
  --output text)

echo "==> AMI: $AMI_ID"

# ─── 4. User data (instala Docker) ──────────────────────────────────
USER_DATA=$(cat <<'USERDATA'
#!/bin/bash
set -e
# Swap de 4GB para compensar RAM limitada
fallocate -l 4G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
# Tuning
sysctl -w vm.swappiness=10
sysctl -w net.core.somaxconn=4096
sysctl -w net.ipv4.tcp_tw_reuse=1
echo 'vm.swappiness=10' >> /etc/sysctl.conf

apt-get update -y
apt-get install -y docker.io docker-compose-v2
systemctl enable docker
systemctl start docker
usermod -aG docker ubuntu
echo "Docker + swap instalados" > /home/ubuntu/setup.log
USERDATA
)

# ─── 5. Lançar instância ────────────────────────────────────────────
echo "==> Lançando EC2 ($INSTANCE_TYPE, 30GB gp3)..."
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --security-group-ids "$SG_ID" \
  --user-data "$USER_DATA" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$APP_NAME}]" \
  --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=30,VolumeType=gp3}" \
  --region "$REGION" \
  --query 'Instances[0].InstanceId' --output text)

echo "    Instância: $INSTANCE_ID"
echo "==> Aguardando instância ficar running..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"

PUBLIC_IP=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

echo "==> IP Público: $PUBLIC_IP"

# ─── 6. Esperar SSH ficar disponível ────────────────────────────────
echo "==> Aguardando SSH ficar pronto (~60s)..."
sleep 60

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=5 -i ${KEY_NAME}.pem"

for i in $(seq 1 10); do
  if ssh $SSH_OPTS "ubuntu@${PUBLIC_IP}" "echo ok" 2>/dev/null; then
    break
  fi
  echo "    Tentativa $i/10..."
  sleep 10
done

# ─── 7. Copiar arquivos do projeto (deploy filtrado) ─────────────────
echo "==> Copiando projeto para EC2..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_IGNORE_FILE="${SCRIPT_DIR}/.deployignore"

ssh $SSH_OPTS "ubuntu@${PUBLIC_IP}" "mkdir -p ~/app"

if ! command -v rsync >/dev/null 2>&1; then
  echo "[ERRO] rsync não encontrado localmente. Instale rsync para deploy filtrado."
  exit 1
fi

rsync -az --delete \
  --exclude-from="${DEPLOY_IGNORE_FILE}" \
  -e "ssh ${SSH_OPTS}" \
  "${SCRIPT_DIR}/" "ubuntu@${PUBLIC_IP}:~/app/"

# Limpar artefatos de dev do frontend
ssh $SSH_OPTS "ubuntu@${PUBLIC_IP}" \
  "rm -rf ~/app/frontend/node_modules ~/app/frontend/.next"

# ─── 8. Ajustar configs para EC2 e subir ────────────────────────────
echo "==> Ajustando configurações para EC2..."
ssh $SSH_OPTS "ubuntu@${PUBLIC_IP}" bash <<REMOTE
set -e
cd ~/app

# Aguardar Docker ficar pronto (user-data pode estar rodando)
for i in \$(seq 1 30); do
  if sudo docker info >/dev/null 2>&1; then break; fi
  echo "  Docker ainda não pronto, aguardando... (\$i/30)"
  sleep 5
done

# ── Ajustar docker-compose.yml para EC2 t2.micro (1 vCPU, 1GB RAM) ──

# Frontend: apontar para IP público
sed -i 's|NEXT_PUBLIC_API_URL: ""|NEXT_PUBLIC_API_URL: "http://${PUBLIC_IP}:5001"|' docker-compose.yml

# Redis: MUITO agressivo (128MB max, 1 thread)
sed -i 's|--maxmemory 2gb|--maxmemory 128mb|' docker-compose.yml
sed -i 's|--io-threads 8|--io-threads 1|' docker-compose.yml
sed -i 's|--hz 100|--hz 10|' docker-compose.yml

# Redis limits
sed -i 's|cpus: "2.0"|cpus: "0.3"|' docker-compose.yml
sed -i 's|memory: 2.5g|memory: 256m|' docker-compose.yml

# App: MUITO reduzido
sed -i 's|NUM_WORKERS: "500"|NUM_WORKERS: "2"|' docker-compose.yml
sed -i 's|MAX_CONCURRENT_CONNS: "80000"|MAX_CONCURRENT_CONNS: "20"|' docker-compose.yml
sed -i 's|MASSCAN_RATE: "300000"|MASSCAN_RATE: "100"|' docker-compose.yml
sed -i 's|VULN_WORKERS: "30"|VULN_WORKERS: "1"|' docker-compose.yml
sed -i 's|BOUNTY_RECON_WORKERS: "30"|BOUNTY_RECON_WORKERS: "1"|' docker-compose.yml
sed -i 's|HTTPX_THREADS: "250"|HTTPX_THREADS: "2"|' docker-compose.yml
sed -i 's|NUCLEI_RATE_LIMIT: "1200"|NUCLEI_RATE_LIMIT: "10"|' docker-compose.yml
sed -i 's|NUCLEI_BULK_SIZE: "200"|NUCLEI_BULK_SIZE: "5"|' docker-compose.yml
sed -i 's|NUCLEI_CONCURRENCY: "100"|NUCLEI_CONCURRENCY: "2"|' docker-compose.yml
sed -i 's|KATANA_CONCURRENCY: "60"|KATANA_CONCURRENCY: "2"|' docker-compose.yml
sed -i 's|UV_THREADPOOL_SIZE: "64"|UV_THREADPOOL_SIZE: "2"|' docker-compose.yml
sed -i 's|BATCH_SIZE: "1000"|BATCH_SIZE: "10"|' docker-compose.yml
sed -i 's|--limit-concurrency=1000|--limit-concurrency=50|' docker-compose.yml
sed -i 's|--backlog=8192|--backlog=256|' docker-compose.yml

# App resource limits (máximo 0.7 CPU, 400MB)
sed -i 's|cpus: "11.0"|cpus: "0.7"|' docker-compose.yml
sed -i 's|memory: 5g|memory: 400m|' docker-compose.yml
sed -i 's|cpus: "6.0"|cpus: "0.2"|' docker-compose.yml
sed -i 's|memory: 2g|memory: 200m|' docker-compose.yml

# Frontend resource limits (128MB max)
sed -i 's|NODE_OPTIONS: "--max-old-space-size=1536"|NODE_OPTIONS: "--max-old-space-size=128"|' docker-compose.yml

# Ulimits MUITO pequenos para t2.micro
sed -i 's|soft: 131072|soft: 1024|g' docker-compose.yml
sed -i 's|hard: 131072|hard: 2048|g' docker-compose.yml
sed -i 's|soft: 65536|soft: 512|g' docker-compose.yml
sed -i 's|hard: 65536|hard: 1024|g' docker-compose.yml

# Remover platform linux/arm64 (EC2 é amd64)
sed -i '/platform: linux\/arm64/d' docker-compose.yml

echo "==> Configurações ajustadas para EC2"

# ── Build e start ──
echo "==> Fazendo build e start..."
sudo docker compose up -d --build 2>&1 | tail -20

echo ""
echo "==> Containers:"
sudo docker compose ps
REMOTE

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Deploy concluído!"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "  Instância:   $INSTANCE_ID"
echo "  IP Público:  $PUBLIC_IP"
echo ""
echo "  Frontend:    http://${PUBLIC_IP}:3000"
echo "  API:         http://${PUBLIC_IP}:5001"
echo ""
echo "  SSH:         ssh -i ${KEY_NAME}.pem ubuntu@${PUBLIC_IP}"
echo "  Logs:        ssh -i ${KEY_NAME}.pem ubuntu@${PUBLIC_IP} 'cd ~/app && sudo docker compose logs -f'"
echo "  Rebuild:     ssh -i ${KEY_NAME}.pem ubuntu@${PUBLIC_IP} 'cd ~/app && sudo docker compose up -d --build'"
echo ""
echo "  Tipo: $INSTANCE_TYPE (~\$0.02/h = ~\$15/mês)"
echo ""
