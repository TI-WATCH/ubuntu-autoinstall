#!/usr/bin/env bash
# setup_mdatp.sh
# Instala/configura Microsoft Defender for Endpoint (mdatp) no Ubuntu 24.x
# - Usa o repo config package (packages-microsoft-prod.deb) recomendado pela Microsoft
# - Usa keyring com signed-by (sem apt-key / trusted.gpg.d)
# - Detecta falha de assinatura (NO_PUBKEY) e tenta corrigir trocando a chave automaticamente

set -euo pipefail
IFS=$'\n\t'

need_sudo=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    need_sudo="sudo"
  else
    echo "ERRO: precisa de root e não há sudo."
    exit 1
  fi
fi

log() { echo -e "\n>>> $*"; }

install_pkg() {
  local pkg="$1"
  log "Instalando/checando pacote: $pkg"
  $need_sudo apt-get install -y "$pkg"
}

require_ubuntu() {
  if [ ! -r /etc/os-release ]; then
    echo "ERRO: /etc/os-release não encontrado."
    exit 1
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    echo "ERRO: este script foi feito para Ubuntu. Detectado: ${ID:-desconhecido}"
    exit 1
  fi
  if [[ "${VERSION_ID:-}" != 24.* ]]; then
    echo "AVISO: Detectado Ubuntu ${VERSION_ID:-?}. Este script foi pensado para Ubuntu 24.x."
  fi
  UBUNTU_VERSION_ID="${VERSION_ID}"
}

# Fingerprints publicados pela Microsoft (Linux Software Repository for Microsoft Products)
FP_MICROSOFT_ASC="BC52 8686 B50D 79E3 39D3 721C EB3E 94AD BE12 29CF"
FP_MICROSOFT_2025_ASC="AA86 F75E 427A 19DD 3334 6403 EE4D 7792 F748 182B"

KEYRING_DIR="/etc/apt/keyrings"
KEYRING_FILE="${KEYRING_DIR}/microsoft.gpg"
MS_LIST="/etc/apt/sources.list.d/microsoft-prod.list"

install_microsoft_repo_config_pkg() {
  require_ubuntu
  log "Configurando repo Microsoft via packages-microsoft-prod.deb (ubuntu/${UBUNTU_VERSION_ID})"
  local tmpdeb
  tmpdeb="$(mktemp --suffix=.deb)"
  curl -fsSL "https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION_ID}/packages-microsoft-prod.deb" -o "$tmpdeb"
  $need_sudo dpkg -i "$tmpdeb" >/dev/null
  rm -f "$tmpdeb"
}

write_keyring_from_asc() {
  local asc_url="$1"
  local expected_fp="$2"

  log "Instalando chave Microsoft a partir de: $asc_url"
  $need_sudo mkdir -p "$KEYRING_DIR"

  local tmpasc tmpgpg
  tmpasc="$(mktemp)"
  tmpgpg="$(mktemp)"

  curl -fsSL "$asc_url" -o "$tmpasc"
  gpg --dearmor < "$tmpasc" > "$tmpgpg"

  # Valida fingerprint (best-effort; se não bater, a gente não instala)
  local fp
  fp="$(gpg --show-keys --with-fingerprint --with-colons "$tmpgpg" 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}' | sed 's/\(..\)/\1 /g' | sed 's/ $//')"
  if [[ -n "$expected_fp" && "$fp" != "$expected_fp" ]]; then
    echo "ERRO: fingerprint da chave baixada não bate com o esperado."
    echo "Esperado: $expected_fp"
    echo "Obtido:   ${fp:-"(não consegui ler)"}"
    rm -f "$tmpasc" "$tmpgpg"
    return 1
  fi

  $need_sudo install -o root -g root -m 0644 "$tmpgpg" "$KEYRING_FILE"
  rm -f "$tmpasc" "$tmpgpg"
}

force_sources_signed_by() {
  # Garante que qualquer lista "microsoft-prod.list" use signed-by e o KEYRING_FILE
  # (mantém as linhas "deb https://packages.microsoft.com/..." mas injeta options)
  if [ ! -f "$MS_LIST" ]; then
    return 0
  fi

  log "Garantindo 'signed-by=${KEYRING_FILE}' em $MS_LIST"
  $need_sudo cp -a "$MS_LIST" "${MS_LIST}.bak.$(date +%s)" >/dev/null 2>&1 || true

  # Para cada linha "deb https://packages.microsoft.com/..." que NÃO tenha [ ... ],
  # adiciona: deb [signed-by=/etc/apt/keyrings/microsoft.gpg] ...
  $need_sudo awk -v keyring="$KEYRING_FILE" '
    BEGIN { OFS=" " }
    /^[[:space:]]*deb[[:space:]]+https:\/\/packages\.microsoft\.com\// {
      if ($2 ~ /^\[/) { print; next }
      $1="deb"
      $0=$1" [signed-by="keyring"] "$2" "$3" "$4
      print; next
    }
    { print }
  ' "$MS_LIST" | $need_sudo tee "$MS_LIST" >/dev/null
}

apt_update_capture() {
  # Captura stderr+stdout para analisar NO_PUBKEY etc
  local out
  out="$($need_sudo apt-get update 2>&1 || true)"
  echo "$out"
}

apt_update_ok() {
  local out="$1"
  # Heurística: se apt-get update retorna 0, a função acima não saberia.
  # Então checamos mensagens típicas de falha.
  if echo "$out" | grep -Eqi "NO_PUBKEY|The following signatures couldn't be verified|EXPKEYSIG|BADSIG|GPG error"; then
    return 1
  fi
  return 0
}

fix_repo_key_and_retry_update() {
  log "Rodando apt-get update (com detecção de erro de chave)..."
  local out
  out="$(apt_update_capture)"
  if apt_update_ok "$out"; then
    log "apt-get update OK."
    return 0
  fi

  echo "$out" | sed -n '1,120p' >&2

  log "Falha de assinatura detectada. Tentando corrigir chave automaticamente..."

  # 1) tenta chave "antiga" microsoft.asc (repo pré-2025)
  if write_keyring_from_asc "https://packages.microsoft.com/keys/microsoft.asc" "$FP_MICROSOFT_ASC"; then
    force_sources_signed_by
    out="$(apt_update_capture)"
    if apt_update_ok "$out"; then
      log "Corrigido usando microsoft.asc."
      return 0
    fi
  fi

  # 2) tenta chave "nova" microsoft-2025.asc (repos mais novos)
  if write_keyring_from_asc "https://packages.microsoft.com/keys/microsoft-2025.asc" "$FP_MICROSOFT_2025_ASC"; then
    force_sources_signed_by
    out="$(apt_update_capture)"
    if apt_update_ok "$out"; then
      log "Corrigido usando microsoft-2025.asc."
      return 0
    fi
  fi

  echo "ERRO: não consegui corrigir a chave do repositório automaticamente." >&2
  echo "Saída do apt-get update (última tentativa):" >&2
  echo "$out" >&2
  return 1
}

main() {
  log "==== Iniciando: setup_mdatp.sh ===="

  require_ubuntu

  log "Atualizando índices apt..."
  $need_sudo apt-get update

  install_pkg curl
  install_pkg gnupg
  install_pkg ca-certificates
  install_pkg apt-transport-https

  # Recomendado: instalar o config package da Microsoft (traz a config do repo)
  install_microsoft_repo_config_pkg

  # Garante keyring + signed-by; e se der erro de chave, tenta corrigir/trocar
  fix_repo_key_and_retry_update

  log "Instalando mdatp..."
  install_pkg mdatp

  log "Verificando mdatp health..."
  if command -v mdatp >/dev/null 2>&1; then
    mdatp health || echo "AVISO: 'mdatp health' retornou erro (possível falta de onboarding)."
  else
    echo "AVISO: 'mdatp' não está no PATH mesmo após instalação."
  fi

  log "Verificando Python3..."
  if ! command -v python3 >/dev/null 2>&1; then
    install_pkg python3
  fi

  local onboarding="MicrosoftDefenderATPOnboardingLinuxServer.py"
  log "Tentando executar onboarding script: $onboarding (se existir no diretório atual)"
  if [ -f "./$onboarding" ]; then
    $need_sudo python3 "./$onboarding"
  else
    echo "AVISO: $onboarding não encontrado em $(pwd)."
  fi

  log "Rodando apt update final..."
  $need_sudo apt-get update

  log "==== Finalizado ===="
}

main "$@"