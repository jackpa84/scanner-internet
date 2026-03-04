#!/usr/bin/env bash
set -euo pipefail

# ─── Worker Instance ─────────────────────────────────────────────────
# Deploys a bounty recon worker that connects to the main instance's MongoDB.
# The worker runs ONLY bounty recon (no frontend, no general scanner).
#
# Usage:
#   ./deploy-worker.sh <MAIN_INSTANCE_IP>
#
# Example:
#   ./deploy-worker.sh 54.123.45.67
# ─────────────────────────────────────────────────────────────────────

if [ $# -lt 1 ]; then
  echo "Uso: $0 <MAIN_INSTANCE_IP>"
  echo ""
  echo "  MAIN_INSTANCE_IP: IP público da instância principal (com MongoDB)"
  echo ""
  echo "Exemplo: $0 54.123.45.67"
  exit 1
fi

MAIN_IP="$1"
REGION="${AWS_REGION:-us-east-1}"
INSTANCE_TYPE="${WORKER_INSTANCE_TYPE:-t3.small}"
KEY_NAME="scanner-key"
SG_NAME="scanner-worker-sg"
APP_NAME="scanner-worker"

echo "═══════════════════════════════════════════════════════"
echo "  Deploy Worker → conectando ao main em $MAIN_IP"
echo "═══════════════════════════════════════════════════════"
echo "  Região:    $REGION"
echo "  Instância: $INSTANCE_TYPE"
echo ""

# ─── 1. Verificar key pair ───────────────────────────────────────────
if ! aws ec2 describe-key-pairs --key-names "$KEY_NAME" --region "$REGION" >/dev/null 2>&1; then
  echo "[ERRO] Key pair '$KEY_NAME' não encontrada."
  echo "       Execute deploy-aws.sh primeiro para criar a instância principal."
  exit 1
fi

# ─── 2. Security Group (worker só precisa de SSH) ────────────────────
VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" \
  --filters "Name=is-default,Values=true" \
  --query 'Vpcs[0].VpcId' --output text)

if ! aws ec2 describe-security-groups --group-names "$SG_NAME" --region "$REGION" >/dev/null 2>&1; then
  echo "==> Criando security group: $SG_NAME"
  SG_ID=$(aws ec2 create-security-group \
    --group-name "$SG_NAME" \
    --description "Scanner Worker - SSH only" \
    --vpc-id "$VPC_ID" \
    --region "$REGION" \
    --query 'GroupId' --output text)

  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 22 --cidr 0.0.0.0/0

  echo "    SG criado: $SG_ID (apenas SSH)"
else
  SG_ID=$(aws ec2 describe-security-groups --group-names "$SG_NAME" --region "$REGION" \
    --query 'SecurityGroups[0].GroupId' --output text)
  echo "==> Security group já existe: $SG_ID"
fi

# ─── 3. AMI Ubuntu 22.04 ────────────────────────────────────────────
AMI_ID=$(aws ec2 describe-images --region "$REGION" \
  --owners 099720109477 \
  --filters "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" \
           "Name=state,Values=available" \
  --query 'Images | sort_by(@,&CreationDate) | [-1].ImageId' \
  --output text)

echo "==> AMI: $AMI_ID"

# ─── 4. User data ───────────────────────────────────────────────────
USER_DATA=$(cat <<'USERDATA'
#!/bin/bash
set -e
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
echo "==> Lançando worker EC2 ($INSTANCE_TYPE, 20GB gp3)..."
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --security-group-ids "$SG_ID" \
  --user-data "$USER_DATA" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$APP_NAME},{Key=Role,Value=worker},{Key=MainIP,Value=$MAIN_IP}]" \
  --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=20,VolumeType=gp3}" \
  --region "$REGION" \
  --query 'Instances[0].InstanceId' --output text)

echo "    Instância: $INSTANCE_ID"
echo "==> Aguardando instância ficar running..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"

WORKER_IP=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

echo "==> Worker IP: $WORKER_IP"

# ─── 6. Esperar SSH ─────────────────────────────────────────────────
echo "==> Aguardando SSH (~60s)..."
sleep 60

for i in $(seq 1 10); do
  if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "${KEY_NAME}.pem" "ubuntu@${WORKER_IP}" "echo ok" 2>/dev/null; then
    break
  fi
  echo "    Tentativa $i/10..."
  sleep 10
done

# ─── 7. Copiar arquivos (sem frontend) ──────────────────────────────
echo "==> Copiando projeto para worker..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_IGNORE_FILE="${SCRIPT_DIR}/.deployignore"

ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" "ubuntu@${WORKER_IP}" "mkdir -p ~/app"

if ! command -v rsync >/dev/null 2>&1; then
  echo "[ERRO] rsync não encontrado localmente. Instale rsync para deploy filtrado."
  exit 1
fi

rsync -az --delete \
  --exclude-from="${DEPLOY_IGNORE_FILE}" \
  --exclude="frontend/" \
  -e "ssh -o StrictHostKeyChecking=no -i ${KEY_NAME}.pem" \
  "${SCRIPT_DIR}/" "ubuntu@${WORKER_IP}:~/app/"

# ─── 8. Configurar e subir ──────────────────────────────────────────
echo "==> Subindo worker container..."
ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" "ubuntu@${WORKER_IP}" bash <<REMOTE
set -e
cd ~/app

# Criar .env com IP do main
cat > .env <<EOF
MAIN_IP=${MAIN_IP}
HACKERONE_API_USERNAME=jackpa
HACKERONE_API_TOKEN=\${HACKERONE_API_TOKEN:-}
EOF

# Renomear compose file
cp docker-compose.worker.yml docker-compose.yml

# Build e start
sudo docker compose up -d --build 2>&1 | tail -5

echo ""
echo "Containers:"
sudo docker compose ps
REMOTE

# ─── 9. Verificar conexão com MongoDB ────────────────────────────────
echo "==> Verificando conexão com MongoDB no main..."
sleep 10
ssh -o StrictHostKeyChecking=no -i "${KEY_NAME}.pem" "ubuntu@${WORKER_IP}" \
  "sudo docker compose logs --tail=20 worker 2>&1 | grep -i 'mongo\|bounty\|recon\|feed\|startup' | head -10" || true

echo ""
echo "════════════════════════════════════════════════════════════"
echo "  Worker deploy concluído!"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "  Worker:      $INSTANCE_ID"
echo "  Worker IP:   $WORKER_IP"
echo "  Main IP:     $MAIN_IP"
echo ""
echo "  SSH:         ssh -i ${KEY_NAME}.pem ubuntu@${WORKER_IP}"
echo "  Logs:        ssh -i ${KEY_NAME}.pem ubuntu@${WORKER_IP} 'cd ~/app && sudo docker compose logs -f'"
echo ""
echo "  O worker conecta ao MongoDB em $MAIN_IP:27017"
echo "  e roda bounty recon automaticamente."
echo ""
echo "  Custo: ~\$0.02/hora ($INSTANCE_TYPE)"
echo ""
