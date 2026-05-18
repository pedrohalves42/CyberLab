#!/bin/bash

# ============================================================
# CyberLab Terminal Menu
# ============================================================

CYBERLAB_HOME="$CYBERLAB_HOME"

cyberlab_banner() {
  clear
  echo "============================================================"
  echo "   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██╗      █████╗ ██████╗ "
  echo "  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██║     ██╔══██╗██╔══██╗"
  echo "  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║     ███████║██████╔╝"
  echo "  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║     ██╔══██║██╔══██╗"
  echo "  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████╗██║  ██║██████╔╝"
  echo "   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ "
  echo "============================================================"
  echo " CyberLab Unified Security Lab"
  echo " Framework de Pentest Autorizado, Auditoria e Delivery"
  echo "============================================================"
  echo ""
}

cyberlab_quick_status() {
  if [ -d "$CYBERLAB_HOME" ]; then
    echo "[OK] CyberLab encontrado em: $CYBERLAB_HOME"
  else
    echo "[ERRO] CyberLab não encontrado em: $CYBERLAB_HOME"
  fi

  if [ -f "$CYBERLAB_HOME/bin/cyberlab" ]; then
    echo "[OK] Dispatcher: $CYBERLAB_HOME/bin/cyberlab"
  else
    echo "[ERRO] Dispatcher não encontrado."
  fi

  if [ -d "$CYBERLAB_HOME/.venv" ]; then
    echo "[OK] Ambiente Python: .venv disponível"
  else
    echo "[AVISO] Ambiente Python .venv não encontrado"
  fi

  echo ""
}

cyberlab_menu() {
  cyberlab_banner
  cyberlab_quick_status

  echo "COMANDOS PRINCIPAIS"
  echo "------------------------------------------------------------"
  echo "  cyberlab help                         -> mostra ajuda completa"
  echo "  cyberlab health                       -> checa saúde do framework"
  echo "  cyberlab validate-all                 -> valida estrutura e módulos"
  echo "  cyberlab sync-all                     -> sincroniza módulos internos"
  echo "  cyberlab status                       -> mostra status geral"
  echo ""

  echo "CLIENTES E ESCOPO"
  echo "------------------------------------------------------------"
  echo "  cyberlab client add \"Nome\" dominio.com -> adiciona cliente e escopo"
  echo "  cyberlab client scan dominio.com        -> executa scan do cliente"
  echo ""

  echo "SCAN E OPERAÇÃO"
  echo "------------------------------------------------------------"
  echo "  cyberlab web dominio.com              -> scan web inicial"
  echo "  cyberlab detect dominio.com           -> detecção e classificação"
  echo "  cyberlab threat dominio.com           -> análise de ameaças"
  echo "  cyberlab correlate dominio.com        -> correlação de evidências"
  echo "  cyberlab findings dominio.com         -> consolida achados"
  echo "  cyberlab risk dominio.com             -> calcula risco"
  echo "  cyberlab assets dominio.com           -> inventário de ativos"
  echo "  cyberlab timeline dominio.com         -> linha do tempo"
  echo "  cyberlab analytics dominio.com        -> métricas e analytics"
  echo "  cyberlab remediation dominio.com      -> plano de correção"
  echo ""

  echo "BLOCOS INTELIGENTES"
  echo "------------------------------------------------------------"
  echo "  cyberlab block12 dominio.com          -> intelligence, risco e superfície"
  echo "  cyberlab block13 dominio.com          -> relatórios MD/PDF e SLA"
  echo "  cyberlab final dominio.com            -> Bloco 12 + Bloco 13 + validação"
  echo "  cyberlab block14 dominio.com          -> validação contextual dos achados"
  echo "  cyberlab block15 dominio.com controlled -> validação ofensiva controlada"
  echo ""

  echo "FLUXOS COMPLETOS"
  echo "------------------------------------------------------------"
  echo "  cyberlab full-active dominio.com      -> fluxo completo com modo active"
  echo "  cyberlab full-offensive-controlled dominio.com"
  echo "                                      -> fluxo máximo controlado com Bloco 15"
  echo ""

  echo "FERRAMENTAS E AUDITORIA"
  echo "------------------------------------------------------------"
  echo "  cyberlab tools-check                  -> valida ferramentas instaladas"
  echo "  cyberlab tools-install                -> instala stack ofensiva controlada"
  echo "  cyberlab audit-tools dominio.com safe -> roda ferramentas com escopo/auditoria"
  echo "  cyberlab audit-tools dominio.com active"
  echo "  cyberlab audit-tools-approved dominio.com active-plus"
  echo "  cyberlab audit-tools-approved dominio.com max-controlled"
  echo ""

  echo "NAVEGAÇÃO LOCAL"
  echo "------------------------------------------------------------"
  echo "  cyberlab-home                         -> ir para ~/CyberLab"
  echo "  cyberlab-results                      -> ir para resultados"
  echo "  cyberlab-clients                      -> ir para clientes"
  echo "  cyberlab-tools                        -> ir para ferramentas"
  echo "  cyberlab-latest dominio.com           -> entrar no último scan do domínio"
  echo "  cyberlab-open-delivery dominio.com    -> listar PDFs finais"
  echo ""

  echo "ATALHOS"
  echo "------------------------------------------------------------"
  echo "  cyhelp                                -> cyberlab help"
  echo "  cyhealth                              -> cyberlab health"
  echo "  cyvalidate                            -> cyberlab validate-all"
  echo "  cytools                               -> cyberlab tools-check"
  echo "  cymenu                                -> mostra este menu novamente"
  echo ""

  echo "EXEMPLO DE USO SEGURO"
  echo "------------------------------------------------------------"
  echo "  cyberlab client add \"Cliente Teste\" exemplo.com"
  echo "  cyberlab web exemplo.com"
  echo "  cyberlab audit-tools exemplo.com active"
  echo "  cyberlab final exemplo.com"
  echo "  cyberlab block14 exemplo.com"
  echo "  cyberlab block15 exemplo.com controlled"
  echo ""

  echo "============================================================"
  echo " Ambiente pronto. Use: cyberlab help"
  echo "============================================================"
  echo ""
}

cyberlab_latest() {
  TARGET="$1"

  if [ -z "$TARGET" ]; then
    echo "[ERRO] Informe o domínio."
    echo "Uso: cyberlab-latest dominio.com"
    return 1
  fi

  LATEST_SCAN="$(ls -td "$CYBERLAB_HOME/results/web/$TARGET"/*/ 2>/dev/null | head -n 1 | sed 's:/*$::')"

  if [ -z "$LATEST_SCAN" ]; then
    echo "[ERRO] Nenhum scan encontrado para: $TARGET"
    return 1
  fi

  cd "$LATEST_SCAN" || return 1
  echo "[OK] Último scan:"
  pwd
}

cyberlab_open_delivery() {
  TARGET="$1"

  if [ -z "$TARGET" ]; then
    echo "[ERRO] Informe o domínio."
    echo "Uso: cyberlab-open-delivery dominio.com"
    return 1
  fi

  LATEST_SCAN="$(ls -td "$CYBERLAB_HOME/results/web/$TARGET"/*/ 2>/dev/null | head -n 1 | sed 's:/*$::')"

  if [ -z "$LATEST_SCAN" ]; then
    echo "[ERRO] Nenhum scan encontrado para: $TARGET"
    return 1
  fi

  echo "Último scan:"
  echo "$LATEST_SCAN"
  echo ""

  echo "Relatórios encontrados:"
  find "$LATEST_SCAN" -type f \( -name "*.pdf" -o -name "*.md" -o -name "*.json" \) | grep -E "block_13|block_14|block_15|client_delivery|report|summary|status" | sort
}

# Aliases principais
alias cyberlab-home='cd ~/CyberLab'
alias cyberlab-results='cd ~/CyberLab/results'
alias cyberlab-clients='cd ~/CyberLab/clients'
alias cyberlab-tools='cd ~/CyberLab/tools'

alias cyhelp='cyberlab help'
alias cyhealth='cyberlab health'
alias cyvalidate='cyberlab validate-all'
alias cytools='cyberlab tools-check'
alias cymenu='cyberlab_menu'

# Funções úteis
alias cyberlab-latest='cyberlab_latest'
alias cyberlab-open-delivery='cyberlab_open_delivery'

# Carrega ambiente do CyberLab se existir
if [ -d "$CYBERLAB_HOME/.venv" ]; then
  source "$CYBERLAB_HOME/.venv/bin/activate" 2>/dev/null || true
fi

# Garante PATH do CyberLab
export PATH="$PATH:$CYBERLAB_HOME/bin:$CYBERLAB_HOME/tools/bin:$HOME/go/bin:$HOME/.local/bin"

# Mostrar menu automaticamente ao abrir terminal
cyberlab_menu
