#!/usr/bin/env bash
set -euo pipefail

confirm() {
  read -rp "$1 [s/N] " ans
  [[ "${ans,,}" == "s" ]] || return 1
}

if [[ $EUID -ne 0 ]]; then
  echo "Execute como root: sudo $0"
  exit 1
fi

echo "=== Limpeza básica do sistema (Kali/Debian) ==="

if confirm "1) Limpar cache do apt (download de pacotes)?"; then
  apt-get clean
  apt-get autoclean
  apt-get autoremove -y
fi

if confirm "2) Limpar logs do systemd-journald (manter últimos 7 dias)?"; then
  journalctl --vacuum-time=7d || true
fi

if confirm "3) Truncar logs antigos em /var/log (mantendo arquivos, só zerando)?"; then
  find /var/log -type f -name "*.log" -o -name "*.gz" -o -name "*.1" \
    -exec truncate -s 0 {} \; 2>/dev/null || true
fi

if confirm "4) Limpar lixeira dos usuários (~/.local/share/Trash)?"; then
  for d in /home/*/.local/share/Trash /root/.local/share/Trash; do
    [ -d "$d" ] || continue
    rm -rf "$d/files/"* "$d/info/"* 2>/dev/null || true
  done
fi

if confirm "5) Limpar caches de miniaturas (~/.cache/thumbnails)?"; then
  for d in /home/*/.cache/thumbnails /root/.cache/thumbnails; do
    [ -d "$d" ] || continue
    rm -rf "$d"/* 2>/dev/null || true
  done
fi

if command -v docker &>/dev/null && confirm "6) Limpar Docker (containers/parados, imagens órfãs, volumes não usados)?"; then
  docker system prune -af --volumes
fi

if command -v npm &>/dev/null && confirm "7) Limpar cache do npm?"; then
  npm cache clean --force || true
fi

echo "=== Limpeza concluída. ==="
