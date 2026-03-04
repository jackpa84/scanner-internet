#!/usr/bin/env bash
set -euo pipefail
export AWS_PAGER=""

# ─── Config ──────────────────────────────────────────────────────────
REGION="us-east-1"
INSTANCE_TYPE="t3.micro"    # 1 vCPU, 1GB RAM — Free Tier
KEY_NAME="scanner-key-2"
SG_NAME="scanner-sg-2"
APP_NAME="scanner-internet"

echo "==> Deploy $APP_NAME para AWS EC2 (2x $INSTANCE_TYPE em $REGION)"
echo "    Frontend: instância 1"
echo "    Backend+DB: instância 2"

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
    --description "Scanner Internet 2-instances - SSH, Frontend, API, MongoDB" \
    --vpc-id "$VPC_ID" \
    --region "$REGION" \
    --query 'GroupId' --output text)

  # SSH
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 22 --cidr 0.0.0.0/0
  # Frontend
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 3000 --cidr 0.0.0.0/0
  # Backend API
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 5001 --cidr 0.0.0.0/0
  # MongoDB
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 27017 --cidr 0.0.0.0/0
  # Redis
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 6379 --cidr 0.0.0.0/0

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

# ─── 4. User data backend (instala Docker + MongoDB + Redis) ────────
BACKEND_USER_DATA=$(cat <<'USERDATA'
#!/bin/bash
set -e
# Swap
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
sysctl -w vm.swappiness=10

apt-get update -y
apt-get install -y docker.io docker-compose-v2
systemctl enable docker
systemctl start docker
usermod -aG docker ubuntu
echo "Backend: Docker instalado" > /home/ubuntu/setup.log
USERDATA
)

# ─── 5. User data frontend (instala Docker) ──────────────────────────
FRONTEND_USER_DATA=$(cat <<'USERDATA'
#!/bin/bash
set -e
# Swap (menor para frontend)
fallocate -l 1G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
sysctl -w vm.swappiness=20

apt-get update -y
apt-get install -y docker.io docker-compose-v2
systemctl enable docker
systemctl start docker
usermod -aG docker ubuntu
echo "Frontend: Docker instalado" > /home/ubuntu/setup.log
USERDATA
)

# ─── 6. Lançar BACKEND (instância 1) ────────────────────────────────
echo "==> Lançando BACKEND EC2 ($INSTANCE_TYPE, 20GB gp3)..."
BACKEND_ID=$(aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --security-group-ids "$SG_ID" \
  --user-data "$BACKEND_USER_DATA" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$APP_NAME-backend}]" \
  --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=20,VolumeType=gp3}" \
  --region "$REGION" \
  --query 'Instances[0].InstanceId' --output text)

echo "    Backend Instance ID: $BACKEND_ID"
echo "==> Aguardando backend ficar running..."
aws ec2 wait instance-running --instance-ids "$BACKEND_ID" --region "$REGION"

BACKEND_IP=$(aws ec2 describe-instances \
  --instance-ids "$BACKEND_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)

BACKEND_PUBLIC_IP=$(aws ec2 describe-instances \
  --instance-ids "$BACKEND_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

echo "    Backend Private IP: $BACKEND_IP"
echo "    Backend Public IP: $BACKEND_PUBLIC_IP"

# ─── 7. Lançar FRONTEND (instância 2) ───────────────────────────────
echo ""
echo "==> Lançando FRONTEND EC2 ($INSTANCE_TYPE, 15GB gp3)..."
FRONTEND_ID=$(aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --security-group-ids "$SG_ID" \
  --user-data "$FRONTEND_USER_DATA" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$APP_NAME-frontend}]" \
  --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=15,VolumeType=gp3}" \
  --region "$REGION" \
  --query 'Instances[0].InstanceId' --output text)

echo "    Frontend Instance ID: $FRONTEND_ID"
echo "==> Aguardando frontend ficar running..."
aws ec2 wait instance-running --instance-ids "$FRONTEND_ID" --region "$REGION"

FRONTEND_PUBLIC_IP=$(aws ec2 describe-instances \
  --instance-ids "$FRONTEND_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

echo "    Frontend Public IP: $FRONTEND_PUBLIC_IP"

# ─── 8. Esperar SSH ──────────────────────────────────────────────────
echo ""
echo "==> Aguardando SSH ficar pronto (~60s)..."
sleep 60

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=5 -i ${KEY_NAME}.pem"

for i in $(seq 1 10); do
  if ssh $SSH_OPTS "ubuntu@${BACKEND_PUBLIC_IP}" "echo ok" 2>/dev/null && \
     ssh $SSH_OPTS "ubuntu@${FRONTEND_PUBLIC_IP}" "echo ok" 2>/dev/null; then
    echo "    ✅ SSH pronto em ambas instâncias"
    break
  fi
  echo "    Tentativa $i/10..."
  sleep 10
done

# ─── 9. Deploy BACKEND ───────────────────────────────────────────────
echo ""
echo "==> Configurando BACKEND..."
ssh $SSH_OPTS "ubuntu@${BACKEND_PUBLIC_IP}" "mkdir -p ~/app"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_IGNORE_FILE="${SCRIPT_DIR}/.deployignore"

# Copiar projeto
rsync -az --delete \
  --exclude-from="${DEPLOY_IGNORE_FILE}" \
  --exclude='frontend' \
  -e "ssh ${SSH_OPTS}" \
  "${SCRIPT_DIR}/" "ubuntu@${BACKEND_PUBLIC_IP}:~/app/"

# Deploy backend
ssh $SSH_OPTS "ubuntu@${BACKEND_PUBLIC_IP}" bash <<REMOTE
set -e
cd ~/app

# Aguardar Docker
for i in \$(seq 1 30); do
  if sudo docker info >/dev/null 2>&1; then break; fi
  sleep 5
done

# Criar docker-compose apenas com backend
sudo docker compose up -d redis mongo 2>&1 | tail -5
sleep 10
sudo docker compose up -d app 2>&1 | tail -5

echo "✅ Backend rodando!"
sudo docker compose ps
REMOTE

echo "==> Backend deployado"

# ─── 10. Deploy FRONTEND ─────────────────────────────────────────────
echo ""
echo "==> Configurando FRONTEND..."
ssh $SSH_OPTS "ubuntu@${FRONTEND_PUBLIC_IP}" "mkdir -p ~/app"

# Copiar apenas frontend
rsync -az \
  -e "ssh ${SSH_OPTS}" \
  "${SCRIPT_DIR}/frontend/" "ubuntu@${FRONTEND_PUBLIC_IP}:~/app/frontend/"

rsync -az \
  -e "ssh ${SSH_OPTS}" \
  "${SCRIPT_DIR}/next.config.mjs" \
  "${SCRIPT_DIR}/docker-compose.yml" \
  "${SCRIPT_DIR}/Dockerfile" \
  "ubuntu@${FRONTEND_PUBLIC_IP}:~/app/" 2>/dev/null || true

# Deploy frontend
ssh $SSH_OPTS "ubuntu@${FRONTEND_PUBLIC_IP}" bash <<REMOTE
set -e
cd ~/app

# Aguardar Docker
for i in \$(seq 1 30); do
  if sudo docker info >/dev/null 2>&1; then break; fi
  sleep 5
done

# Ajustar docker-compose para apontar ao backend remoto
sed -i 's|http://app:5000|http://${BACKEND_IP}:5001|g' docker-compose.yml
sed -i 's|NEXT_PUBLIC_API_URL: ""|NEXT_PUBLIC_API_URL: "http://${FRONTEND_PUBLIC_IP}:3000"|' docker-compose.yml

# Build e start
sudo docker compose build frontend 2>&1 | tail -10
sudo docker compose up -d frontend 2>&1 | tail -5

echo "✅ Frontend rodando!"
sudo docker compose ps
REMOTE

echo "==> Frontend deployado"

# ─── 11. Status Final ────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo "  ✅ Deploy em 2 INSTÂNCIAS CONCLUÍDO!"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "  🖥️  BACKEND (MongoDB + Redis + API)"
echo "     Instância: $BACKEND_ID"
echo "     IP Público: $BACKEND_PUBLIC_IP"
echo "     SSH: ssh -i ${KEY_NAME}.pem ubuntu@${BACKEND_PUBLIC_IP}"
echo "     API: http://${BACKEND_PUBLIC_IP}:5001"
echo "     Docs: http://${BACKEND_PUBLIC_IP}:5001/docs"
echo ""
echo "  💻 FRONTEND (Next.js)"
echo "     Instância: $FRONTEND_ID"
echo "     IP Público: $FRONTEND_PUBLIC_IP"
echo "     SSH: ssh -i ${KEY_NAME}.pem ubuntu@${FRONTEND_PUBLIC_IP}"
echo "     URL: http://${FRONTEND_PUBLIC_IP}:3000"
echo ""
echo "  📊 Logs:"
echo "     Backend:  ssh -i ${KEY_NAME}.pem ubuntu@${BACKEND_PUBLIC_IP} 'cd ~/app && sudo docker compose logs -f'"
echo "     Frontend: ssh -i ${KEY_NAME}.pem ubuntu@${FRONTEND_PUBLIC_IP} 'cd ~/app && sudo docker compose logs -f'"
echo ""
echo "  ⚙️  Rebuild:"
echo "     Backend:  ssh -i ${KEY_NAME}.pem ubuntu@${BACKEND_PUBLIC_IP} 'cd ~/app && sudo docker compose up -d --build app'"
echo "     Frontend: ssh -i ${KEY_NAME}.pem ubuntu@${FRONTEND_PUBLIC_IP} 'cd ~/app && sudo docker compose up -d --build frontend'"
echo ""
echo "  💰 Custo: 2x t3.micro = ~$0.05/h = ~$35/mês (Free Tier: grátis)"
echo ""
