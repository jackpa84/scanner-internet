#!/bin/bash

echo "🧹 LIMPEZA COMPLETA - REGIÃO US-EAST-1 (Norte da Virgínia)"
echo "========================================================"

# Fixar região como us-east-1
export AWS_DEFAULT_REGION=us-east-1

echo "📍 Região configurada: us-east-1"
echo "-----------------------------------"

# 1. TERMINAR INSTÂNCIAS EC2
echo "🔴 Terminando instâncias EC2..."
INSTANCES=$(aws ec2 describe-instances --query 'Reservations[*].Instances[?State.Name!=`terminated`].InstanceId' --output text)
if [ ! -z "$INSTANCES" ]; then
    for INSTANCE in $INSTANCES; do
        echo "   Terminando: $INSTANCE"
        aws ec2 terminate-instances --instance-ids $INSTANCE > /dev/null
    done
    
    echo "   ⏳ Aguardando terminação das instâncias..."
    for INSTANCE in $INSTANCES; do
        aws ec2 wait instance-terminated --instance-ids $INSTANCE
        echo "   ✅ Instância $INSTANCE terminada"
    done
else
    echo "   ✅ Nenhuma instância ativa encontrada"
fi

# 2. LIBERAR ELASTIC IPS
echo ""
echo "🔵 Liberando Elastic IPs..."
ALLOCATIONS=$(aws ec2 describe-addresses --query 'Addresses[*].AllocationId' --output text)
if [ ! -z "$ALLOCATIONS" ]; then
    for ALLOC in $ALLOCATIONS; do
        echo "   Liberando: $ALLOC"
        aws ec2 release-address --allocation-id $ALLOC
    done
else
    echo "   ✅ Nenhum Elastic IP encontrado"
fi

# 3. DELETAR VOLUMES EBS NÃO ANEXADOS
echo ""
echo "💾 Deletando volumes EBS não anexados..."
VOLUMES=$(aws ec2 describe-volumes --filters Name=status,Values=available --query 'Volumes[*].VolumeId' --output text)
if [ ! -z "$VOLUMES" ]; then
    for VOL in $VOLUMES; do
        echo "   Deletando volume: $VOL"
        aws ec2 delete-volume --volume-id $VOL
    done
else
    echo "   ✅ Nenhum volume disponível encontrado"
fi

# 4. DELETAR SNAPSHOTS
echo ""
echo "📸 Deletando snapshots..."
SNAPSHOTS=$(aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[*].SnapshotId' --output text)
if [ ! -z "$SNAPSHOTS" ]; then
    for SNAP in $SNAPSHOTS; do
        echo "   Deletando snapshot: $SNAP"
        aws ec2 delete-snapshot --snapshot-id $SNAP
    done
else
    echo "   ✅ Nenhum snapshot encontrado"
fi

# 5. DEREGISTRAR AMIS
echo ""
echo "🖼️  Deregistrando AMIs..."
IMAGES=$(aws ec2 describe-images --owners self --query 'Images[*].ImageId' --output text)
if [ ! -z "$IMAGES" ]; then
    for IMAGE in $IMAGES; do
        echo "   Deregistrando AMI: $IMAGE"
        aws ec2 deregister-image --image-id $IMAGE
    done
else
    echo "   ✅ Nenhuma AMI encontrada"
fi

# 6. DELETAR KEY PAIRS
echo ""
echo "🔑 Deletando Key Pairs..."
KEYS=$(aws ec2 describe-key-pairs --query 'KeyPairs[*].KeyName' --output text)
if [ ! -z "$KEYS" ]; then
    for KEY in $KEYS; do
        echo "   Deletando key pair: $KEY"
        aws ec2 delete-key-pair --key-name $KEY
    done
else
    echo "   ✅ Nenhum key pair encontrado"
fi

# 7. DELETAR SECURITY GROUPS (exceto default)
echo ""
echo "🛡️  Deletando Security Groups (não default)..."
SGS=$(aws ec2 describe-security-groups --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text)
if [ ! -z "$SGS" ]; then
    for SG in $SGS; do
        echo "   Deletando security group: $SG"
        aws ec2 delete-security-group --group-id $SG 2>/dev/null 
        if [ $? -eq 0 ]; then
            echo "      ✅ Deletado com sucesso"
        else
            echo "      ⚠️  Não foi possível deletar (pode estar em uso)"
        fi
    done
else
    echo "   ✅ Nenhum security group não-default encontrado"
fi

# 8. LIMPAR LOAD BALANCERS
echo ""
echo "⚖️  Limpando Load Balancers..."

# Classic Load Balancers
CLB=$(aws elb describe-load-balancers --query 'LoadBalancerDescriptions[*].LoadBalancerName' --output text)
if [ ! -z "$CLB" ]; then
    for LB in $CLB; do
        echo "   Deletando Classic LB: $LB"
        aws elb delete-load-balancer --load-balancer-name $LB
    done
else
    echo "   ✅ Nenhum Classic LB encontrado"
fi

# ALB/NLB Load Balancers
ALB=$(aws elbv2 describe-load-balancers --query 'LoadBalancers[*].LoadBalancerArn' --output text)
if [ ! -z "$ALB" ]; then
    for LB in $ALB; do
        echo "   Deletando ALB/NLB: $LB"
        aws elbv2 delete-load-balancer --load-balancer-arn $LB
    done
else
    echo "   ✅ Nenhum ALB/NLB encontrado"
fi

# 9. LIMPAR LAUNCH TEMPLATES
echo ""
echo "📋 Limpando Launch Templates..."
TEMPLATES=$(aws ec2 describe-launch-templates --query 'LaunchTemplates[*].LaunchTemplateId' --output text)
if [ ! -z "$TEMPLATES" ]; then
    for TEMPLATE in $TEMPLATES; do
        echo "   Deletando launch template: $TEMPLATE"
        aws ec2 delete-launch-template --launch-template-id $TEMPLATE
    done
else
    echo "   ✅ Nenhum launch template encontrado"
fi

# 10. LIMPAR INTERFACES DE REDE ÓRFÃS
echo ""
echo "🌐 Limpando network interfaces não usadas..."
ENIS=$(aws ec2 describe-network-interfaces --filters Name=status,Values=available --query 'NetworkInterfaces[*].NetworkInterfaceId' --output text)
if [ ! -z "$ENIS" ]; then
    for ENI in $ENIS; do
        echo "   Deletando network interface: $ENI"
        aws ec2 delete-network-interface --network-interface-id $ENI
    done
else
    echo "   ✅ Nenhuma network interface órfã encontrada"
fi

echo ""
echo "========================================================"
echo "✅ LIMPEZA DA US-EAST-1 CONCLUÍDA!"
echo "========================================================"
