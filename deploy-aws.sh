#!/usr/bin/env bash
set -euo pipefail

# ─── Config ──────────────────────────────────────────────────────────
REGION="us-east-1"
INSTANCE_TYPE="t3.micro"
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
    --protocol tcp --port 5000 --cidr 0.0.0.0/0
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
# Swap de 2GB (t2.micro tem só 1GB RAM)
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab

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

for i in $(seq 1 10); do
  if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "${KEY_NAME}.pem" "ubuntu@${PUBLIC_IP}" "echo ok" 2>/dev/null; then
    break
  fi
  echo "    Tentativa $i/10..."
  sleep 10
done

# ─── 7. Copiar arquivos do projeto via SCP ───────────────────────────
echo "==> Copiando projeto para EC2..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" "ubuntu@${PUBLIC_IP}" "mkdir -p ~/app"

scp -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" -r \
  "${SCRIPT_DIR}/docker-compose.yml" \
  "${SCRIPT_DIR}/Dockerfile" \
  "${SCRIPT_DIR}/pyproject.toml" \
  "${SCRIPT_DIR}/app" \
  "${SCRIPT_DIR}/tools" \
  "ubuntu@${PUBLIC_IP}:~/app/"

# Copiar poetry.lock se existir
[ -f "${SCRIPT_DIR}/poetry.lock" ] && \
  scp -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" \
    "${SCRIPT_DIR}/poetry.lock" "ubuntu@${PUBLIC_IP}:~/app/"

# Copiar frontend
scp -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" -r \
  "${SCRIPT_DIR}/frontend" \
  "ubuntu@${PUBLIC_IP}:~/app/"

# Remover node_modules do frontend (será instalado no container)
ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" "ubuntu@${PUBLIC_IP}" \
  "rm -rf ~/app/frontend/node_modules ~/app/frontend/.next"

# ─── 8. Ajustar NEXT_PUBLIC_API_URL e subir ─────────────────────────
echo "==> Subindo containers..."
ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" "ubuntu@${PUBLIC_IP}" bash <<REMOTE
set -e
cd ~/app

# Apontar frontend para o IP público da EC2
# Criar .env se não existir
touch .env

# Ajustar para IP público e t3.micro (1GB RAM)
sed -i "s|NEXT_PUBLIC_API_URL:.*|NEXT_PUBLIC_API_URL: http://${PUBLIC_IP}:5000|" docker-compose.yml
sed -i 's|NUM_WORKERS: "200"|NUM_WORKERS: "20"|' docker-compose.yml
sed -i 's|VULN_WORKERS: "3"|VULN_WORKERS: "1"|' docker-compose.yml
sed -i 's|BOUNTY_RECON_WORKERS: "2"|BOUNTY_RECON_WORKERS: "1"|' docker-compose.yml

# Build e start
sudo docker compose up -d --build 2>&1 | tail -5

echo "Containers:"
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
echo "  API:         http://${PUBLIC_IP}:5000"
echo "  MongoDB:     mongodb://user:password@${PUBLIC_IP}:27017/scanner_db?authSource=admin"
echo ""
echo "  SSH:         ssh -i ${KEY_NAME}.pem ubuntu@${PUBLIC_IP}"
echo "  Logs:        ssh -i ${KEY_NAME}.pem ubuntu@${PUBLIC_IP} 'cd ~/app && sudo docker compose logs -f'"
echo ""
echo "  Custo estimado: Free Tier (t3.micro)"
echo ""
