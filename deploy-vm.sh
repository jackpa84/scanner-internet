#!/usr/bin/env bash
# =============================================================================
# deploy-vm.sh — Cria CVM TencentCloud de alto rendimento + deploy via docker-compose
# VM: SA5.4XLARGE32 (16 vCPU / 32 GB RAM) — ap-singapore
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[i]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }
step() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${NC}\n${BOLD}  $*${NC}\n${BOLD}${CYAN}══════════════════════════════════════${NC}"; }

# ── Configurações ─────────────────────────────────────────────────────────────
SECRET_ID="${TENCENT_SECRET_ID:-IKIDznNXYMwIPvUqxqW0GqNlxudppcEbjdHg}"
SECRET_KEY="${TENCENT_SECRET_KEY:-GJ7g2B7oJiwxjIemgaIm171iBSehrx9b}"
REGION="ap-singapore"
ZONE="ap-singapore-1"
VPC_ID="vpc-dzsvp8d9"
SUBNET_ID="subnet-ejd4pn0o"
INSTANCE_TYPE="SA5.4XLARGE32"    # 16 vCPU / 32 GB — suporta 90% da máquina
IMAGE_ID="img-487zeit5"           # Ubuntu Server 22.04 LTS 64bit
DISK_SIZE=100                     # GB SSD para Docker volumes
VM_NAME="scanner-internet"
VM_PASSWORD="Scanner2026!@#"
REPO_URL="https://github.com/$(git -C "$(dirname "$0")" remote get-url origin 2>/dev/null | sed 's|.*github.com[:/]||;s|\.git||' || echo 'USER/scanner-internet')"
PROJ_DIR="/opt/scanner-internet"

TC="tccli --secretId $SECRET_ID --secretKey $SECRET_KEY --region $REGION"

# ── 1. Security Group ─────────────────────────────────────────────────────────
step "1/4 — Security Group"

SG_RESP=$(tccli vpc CreateSecurityGroup \
  --GroupName "scanner-sg" \
  --GroupDescription "Scanner Internet firewall" \
  --secretId "$SECRET_ID" --secretKey "$SECRET_KEY" --region "$REGION" 2>&1)
SG_ID=$(echo "$SG_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['SecurityGroup']['SecurityGroupId'])" 2>/dev/null || true)

if [[ -z "$SG_ID" ]]; then
  # Já existe — buscar
  SG_ID=$(tccli vpc DescribeSecurityGroups \
    --Filters '[{"Name":"security-group-name","Values":["scanner-sg"]}]' \
    --secretId "$SECRET_ID" --secretKey "$SECRET_KEY" --region "$REGION" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['SecurityGroupSet'][0]['SecurityGroupId'])")
fi
log "Security Group: $SG_ID"

# Regras de entrada
tccli vpc ModifySecurityGroupPolicies \
  --SecurityGroupId "$SG_ID" \
  --SecurityGroupPolicySet '{
    "Ingress": [
      {"Protocol":"TCP","Port":"22",   "CidrBlock":"0.0.0.0/0","Action":"ACCEPT","PolicyDescription":"SSH"},
      {"Protocol":"TCP","Port":"80",   "CidrBlock":"0.0.0.0/0","Action":"ACCEPT","PolicyDescription":"HTTP frontend"},
      {"Protocol":"TCP","Port":"3000", "CidrBlock":"0.0.0.0/0","Action":"ACCEPT","PolicyDescription":"Next.js"},
      {"Protocol":"TCP","Port":"5001", "CidrBlock":"0.0.0.0/0","Action":"ACCEPT","PolicyDescription":"FastAPI"},
      {"Protocol":"ICMP","Port":"ALL", "CidrBlock":"0.0.0.0/0","Action":"ACCEPT","PolicyDescription":"Ping"}
    ],
    "Egress": [
      {"Protocol":"ALL","Port":"ALL","CidrBlock":"0.0.0.0/0","Action":"ACCEPT","PolicyDescription":"All out"}
    ]
  }' \
  --secretId "$SECRET_ID" --secretKey "$SECRET_KEY" --region "$REGION" >/dev/null 2>&1 || true
log "Regras de firewall configuradas (22, 80, 3000, 5001)"

# ── 2. Cloud-init (script de inicialização da VM) ─────────────────────────────
step "2/4 — Preparando cloud-init"

# Ler .env do projeto para embutir no cloud-init
ENV_CONTENT=$(cat "$(dirname "$0")/.env" 2>/dev/null | grep -v '^#' | grep -v '^$' || true)

CLOUD_INIT=$(cat <<CLOUDINIT
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

# ── Atualizar sistema ──────────────────────────────────────────────────────────
apt-get update -qq
apt-get upgrade -y -qq

# ── Ajustes de performance (kernel) ───────────────────────────────────────────
cat >> /etc/sysctl.conf <<'EOF'
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_keepalive_time=60
net.core.somaxconn=32768
net.core.netdev_max_backlog=8192
fs.file-max=2097152
vm.swappiness=10
EOF
sysctl -p

# Limites de descritores
cat >> /etc/security/limits.conf <<'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

# ── Instalar Docker ────────────────────────────────────────────────────────────
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

# Docker Compose v2
COMPOSE_VER=\$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
curl -fsSL "https://github.com/docker/compose/releases/download/\${COMPOSE_VER}/docker-compose-linux-x86_64" \
  -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# ── Clonar repositório ────────────────────────────────────────────────────────
apt-get install -y -qq git
git clone ${REPO_URL} ${PROJ_DIR} 2>/dev/null || (cd ${PROJ_DIR} && git pull)

# ── Arquivo .env ──────────────────────────────────────────────────────────────
cat > ${PROJ_DIR}/.env <<'ENVEOF'
${ENV_CONTENT}
ENVEOF

# ── Deploy ────────────────────────────────────────────────────────────────────
cd ${PROJ_DIR}
docker-compose pull --quiet 2>/dev/null || true
docker-compose up -d --build

# ── Script de update rápido ───────────────────────────────────────────────────
cat > /usr/local/bin/scanner-update <<'UPDEOF'
#!/bin/bash
cd ${PROJ_DIR}
git pull
docker-compose up -d --build
UPDEOF
chmod +x /usr/local/bin/scanner-update

echo "SCANNER DEPLOY CONCLUIDO" > /tmp/scanner-ready
CLOUDINIT
)

# Codificar em base64 para a API
USERDATA_B64=$(echo "$CLOUD_INIT" | base64 | tr -d '\n')
log "Cloud-init preparado (${#CLOUD_INIT} bytes)"

# ── 3. Criar CVM ──────────────────────────────────────────────────────────────
step "3/4 — Criando CVM $INSTANCE_TYPE (16 vCPU / 32 GB)"

CVM_RESP=$(tccli cvm RunInstances \
  --InstanceChargeType "POSTPAID_BY_HOUR" \
  --Placement '{"Zone":"'"$ZONE"'","ProjectId":0}' \
  --InstanceType "$INSTANCE_TYPE" \
  --ImageId "$IMAGE_ID" \
  --SystemDisk '{"DiskType":"CLOUD_HSSD","DiskSize":'"$DISK_SIZE"'}' \
  --VirtualPrivateCloud '{"VpcId":"'"$VPC_ID"'","SubnetId":"'"$SUBNET_ID"'"}' \
  --InternetAccessible '{"InternetChargeType":"TRAFFIC_POSTPAID_BY_HOUR","InternetMaxBandwidthOut":100,"PublicIpAssigned":true}' \
  --InstanceName "$VM_NAME" \
  --LoginSettings '{"Password":"'"$VM_PASSWORD"'"}' \
  --SecurityGroupIds '["'"$SG_ID"'"]' \
  --EnhancedService '{"SecurityService":{"Enabled":true},"MonitorService":{"Enabled":true}}' \
  --UserData "$USERDATA_B64" \
  --InstanceCount 1 \
  --secretId "$SECRET_ID" --secretKey "$SECRET_KEY" --region "$REGION" 2>&1)

INSTANCE_ID=$(echo "$CVM_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['InstanceIdSet'][0])" 2>/dev/null || true)
[[ -z "$INSTANCE_ID" ]] && { echo "$CVM_RESP"; err "Falha ao criar CVM."; }
log "CVM criada: $INSTANCE_ID"

# ── 4. Aguardar e mostrar resultado ───────────────────────────────────────────
step "4/4 — Aguardando VM ficar Running"

PUBLIC_IP=""
for i in $(seq 1 30); do
  sleep 10
  VM_INFO=$(tccli cvm DescribeInstances \
    --InstanceIds '["'"$INSTANCE_ID"'"]' \
    --secretId "$SECRET_ID" --secretKey "$SECRET_KEY" --region "$REGION" 2>/dev/null)
  STATUS=$(echo "$VM_INFO" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['InstanceSet'][0]['InstanceState'])" 2>/dev/null || echo "unknown")
  PUBLIC_IP=$(echo "$VM_INFO" | python3 -c "
import sys,json
d=json.load(sys.stdin)
ips=d['InstanceSet'][0].get('PublicIpAddresses',[])
print(ips[0] if ips else '')
" 2>/dev/null || echo "")
  printf "  [%2d/30] status: %-12s ip: %-16s\r" "$i" "$STATUS" "${PUBLIC_IP:-aguardando...}"
  [[ "$STATUS" == "RUNNING" && -n "$PUBLIC_IP" ]] && break
done
echo ""

[[ -z "$PUBLIC_IP" ]] && err "Não foi possível obter o IP público."

# ── Resultado final ───────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  ✅  VM CRIADA E DEPLOY INICIADO!${NC}"
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}VM ID:${NC}        $INSTANCE_ID"
echo -e "  ${BOLD}IP Público:${NC}   ${CYAN}$PUBLIC_IP${NC}"
echo -e "  ${BOLD}Tipo:${NC}         $INSTANCE_TYPE (16 vCPU / 32 GB RAM)"
echo -e "  ${BOLD}OS:${NC}           Ubuntu 22.04 LTS"
echo -e "  ${BOLD}Disco:${NC}        ${DISK_SIZE}GB SSD NVMe"
echo ""
echo -e "  ${BOLD}Acesso SSH:${NC}"
echo -e "    ${YELLOW}ssh root@$PUBLIC_IP${NC}  (senha: $VM_PASSWORD)"
echo ""
echo -e "  ${BOLD}Dashboard (após ~5 min do deploy):${NC}"
echo -e "    Frontend : ${CYAN}http://$PUBLIC_IP:3000${NC}"
echo -e "    API      : ${CYAN}http://$PUBLIC_IP:5001/api/health${NC}"
echo ""
echo -e "  ${BOLD}Acompanhar deploy:${NC}"
echo -e "    ${YELLOW}ssh root@$PUBLIC_IP 'tail -f /var/log/cloud-init-output.log'${NC}"
echo ""
echo -e "  ${BOLD}Atualizar app:${NC}"
echo -e "    ${YELLOW}ssh root@$PUBLIC_IP 'scanner-update'${NC}"
echo ""

# Salvar IP para referência
echo "$PUBLIC_IP" > "$(dirname "$0")/.vm-ip"
echo -e "  IP salvo em ${YELLOW}.vm-ip${NC}"
