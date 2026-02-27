#!/bin/bash

echo "🧹 INICIANDO LIMPEZA COMPLETA DA AWS"
echo "====================================="

# Pegar todas as regiões
REGIONS=$(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text)

for REGION in $REGIONS; do
    echo ""
    echo "📍 Processando região: $REGION"
    echo "-----------------------------------"
    
    # Configurar região
    export AWS_DEFAULT_REGION=$REGION
    
    # 1. TERMINAR INSTÂNCIAS EC2
    echo "🔴 Terminando instâncias EC2..."
    INSTANCES=$(aws ec2 describe-instances --query 'Reservations[*].Instances[?State.Name!=`terminated`].InstanceId' --output text)
    if [ ! -z "$INSTANCES" ]; then
        for INSTANCE in $INSTANCES; do
            echo "   Terminando: $INSTANCE"
            aws ec2 terminate-instances --instance-ids $INSTANCE > /dev/null
        done
        # Aguardar terminação
        sleep 10
    else
        echo "   Nenhuma instância ativa encontrada"
    fi
    
    # 2. LIBERAR ELASTIC IPS
    echo "🔵 Liberando Elastic IPs..."
    ALLOCATIONS=$(aws ec2 describe-addresses --query 'Addresses[*].AllocationId' --output text)
    if [ ! -z "$ALLOCATIONS" ]; then
        for ALLOC in $ALLOCATIONS; do
            echo "   Liberando: $ALLOC"
            aws ec2 release-address --allocation-id $ALLOC
        done
    else
        echo "   Nenhum Elastic IP encontrado"
    fi
    
    # 3. DELETAR VOLUMES EBS NÃO ANEXADOS
    echo "💾 Deletando volumes EBS não anexados..."
    VOLUMES=$(aws ec2 describe-volumes --filters Name=status,Values=available --query 'Volumes[*].VolumeId' --output text)
    if [ ! -z "$VOLUMES" ]; then
        for VOL in $VOLUMES; do
            echo "   Deletando volume: $VOL"
            aws ec2 delete-volume --volume-id $VOL
        done
    else
        echo "   Nenhum volume disponível encontrado"
    fi
    
    # 4. DELETAR SNAPSHOTS
    echo "📸 Deletando snapshots..."
    SNAPSHOTS=$(aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[*].SnapshotId' --output text)
    if [ ! -z "$SNAPSHOTS" ]; then
        for SNAP in $SNAPSHOTS; do
            echo "   Deletando snapshot: $SNAP"
            aws ec2 delete-snapshot --snapshot-id $SNAP
        done
    else
        echo "   Nenhum snapshot encontrado"
    fi
    
    # 5. DEREGISTRAR AMIS
    echo "🖼️  Deregistrando AMIs..."
    IMAGES=$(aws ec2 describe-images --owners self --query 'Images[*].ImageId' --output text)
    if [ ! -z "$IMAGES" ]; then
        for IMAGE in $IMAGES; do
            echo "   Deregistrando AMI: $IMAGE"
            aws ec2 deregister-image --image-id $IMAGE
        done
    else
        echo "   Nenhuma AMI encontrada"
    fi
    
    # 6. DELETAR KEY PAIRS
    echo "🔑 Deletando Key Pairs..."
    KEYS=$(aws ec2 describe-key-pairs --query 'KeyPairs[*].KeyName' --output text)
    if [ ! -z "$KEYS" ]; then
        for KEY in $KEYS; do
            echo "   Deletando key pair: $KEY"
            aws ec2 delete-key-pair --key-name $KEY
        done
    else
        echo "   Nenhum key pair encontrado"
    fi
    
    # 7. DELETAR SECURITY GROUPS (exceto default)
    echo "🛡️  Deletando Security Groups (não default)..."
    SGS=$(aws ec2 describe-security-groups --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text)
    if [ ! -z "$SGS" ]; then
        for SG in $SGS; do
            echo "   Deletando security group: $SG"
            aws ec2 delete-security-group --group-id $SG 2>/dev/null || echo "      Não foi possível deletar $SG (pode estar em uso)"
        done
    else
        echo "   Nenhum security group não-default encontrado"
    fi
done

echo ""
echo "✅ LIMPEZA CONCLUÍDA!"
echo "Verifique o console da AWS para confirmar"
