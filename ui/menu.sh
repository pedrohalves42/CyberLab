#!/usr/bin/env bash

set -u

CYBERLAB_HOME="${CYBERLAB_HOME:-$HOME/CyberLab}"
CYBERLAB_BIN="$CYBERLAB_HOME/bin/cyberlab"

run_cyberlab() {
  if [ -f "$CYBERLAB_BIN" ]; then
    bash "$CYBERLAB_BIN" "$@"
  else
    echo "[ERRO] EntryPoint não encontrado: $CYBERLAB_BIN"
    return 1
  fi
}

pause_menu() {
  echo ""
  read -rp "Enter para continuar..."
}

ask_client() {
  local cname
  read -rp "Cliente: " cname

  if [ -z "$cname" ]; then
    echo "[ERRO] Cliente não informado."
    pause_menu
    return 1
  fi

  echo "$cname"
}

while true; do
  clear
  echo "========================================"
  echo "        CYBERLAB UNIFIED CLEAN"
  echo "========================================"
  echo ""
  echo " 1) Dashboard Web"
  echo " 2) Novo Scan Web"
  echo " 3) HUD com Scan"
  echo " 4) LAN Scan"
  echo " 5) Último Relatório Web"
  echo " 6) Risk Latest"
  echo " 7) Health / Tools"
  echo " 8) Network Status"
  echo " 9) Recovery"
  echo "10) Editar Escopo"
  echo "11) Clientes"
  echo "12) Entrega PRO Cliente"
  echo "13) Red Team Lab"
  echo "14) Threat Intel / Detection / Correlation"
  echo "15) Entrega Cliente"
  echo ""
  echo " 0) Sair"
  echo ""
  read -rp "Escolha: " op

  case "$op" in
    1)
      run_cyberlab dashboard
      pause_menu
      ;;

    2)
      run_cyberlab web
      pause_menu
      ;;

    3)
      run_cyberlab monitor
      pause_menu
      ;;

    4)
      run_cyberlab lan
      pause_menu
      ;;

    5)
      run_cyberlab report
      pause_menu
      ;;

    6)
      run_cyberlab risk latest
      pause_menu
      ;;

    7)
      run_cyberlab health
      echo ""
      run_cyberlab tools
      pause_menu
      ;;

    8)
      run_cyberlab network status
      pause_menu
      ;;

    9)
      run_cyberlab recovery
      pause_menu
      ;;

    10)
      run_cyberlab scope
      pause_menu
      ;;

    11)
      run_cyberlab client list
      echo ""
      echo "1) Adicionar cliente"
      echo "2) Scan por cliente"
      echo "0) Voltar"
      echo ""
      read -rp "Escolha: " cop

      case "$cop" in
        1)
          run_cyberlab client add
          ;;
        2)
          run_cyberlab client scan
          ;;
        0)
          ;;
        *)
          echo "Opção inválida."
          ;;
      esac

      pause_menu
      ;;

    12)
      cname="$(ask_client)" || continue
      run_cyberlab delivery generate "$cname"
      pause_menu
      ;;

    13)
      run_cyberlab redteam
      pause_menu
      ;;

    14)
      echo ""
      echo "1) Threat"
      echo "2) Detect"
      echo "3) Correlate"
      echo "4) Intelligence"
      echo "5) Findings"
      echo "0) Voltar"
      echo ""
      read -rp "Escolha: " top

      case "$top" in
        1) run_cyberlab threat ;;
        2) run_cyberlab detect ;;
        3) run_cyberlab correlate ;;
        4) run_cyberlab intelligence ;;
        5) run_cyberlab findings ;;
        0) ;;
        *) echo "Opção inválida." ;;
      esac

      pause_menu
      ;;

    15)
      cname="$(ask_client)" || continue
      run_cyberlab delivery generate "$cname"
      pause_menu
      ;;

    0)
      echo "Saindo..."
      exit 0
      ;;

    *)
      echo "Opção inválida."
      pause_menu
      ;;
  esac
done
