#!/bin/bash
set -euo pipefail

CYBERLAB_HOME="$CYBERLAB_HOME"
CYBERLAB_BIN="$CYBERLAB_HOME/bin/cyberlab"

run_cyberlab() {
    "$CYBERLAB_BIN" "$@"
}

usage_main() {
    cat <<'EOF'
============================================================
 CyberLab — Command Center
 Camada 5: Fluxo Simplificado
============================================================

Grupos oficiais:

  cyberlab audit ...
  cyberlab recon ...
  cyberlab deliver ...
  cyberlab maintain ...
  cyberlab lab ...

Exemplos principais:

  cyberlab audit run "Cliente" dominio.com.br max-controlled
  cyberlab audit status
  cyberlab audit check

  cyberlab deliver latest
  cyberlab deliver build

  cyberlab maintain health
  cyberlab maintain validate
  cyberlab maintain cleanup preview
EOF
}

usage_audit() {
    cat <<'EOF'
Uso:
  cyberlab audit run "Cliente" dominio.com.br [perfil]
  cyberlab audit active "Cliente" dominio.com.br [modo]
  cyberlab audit tools dominio.com.br [perfil]
  cyberlab audit status
  cyberlab audit check
  cyberlab audit context show|validate|path|json

Perfis:
  max-controlled
  active-plus
EOF
}

usage_recon() {
    cat <<'EOF'
Uso:
  cyberlab recon web dominio.com.br
  cyberlab recon detect dominio.com.br
  cyberlab recon threat dominio.com.br
  cyberlab recon correlate dominio.com.br
  cyberlab recon intelligence dominio.com.br
  cyberlab recon findings dominio.com.br
  cyberlab recon risk dominio.com.br
  cyberlab recon assets dominio.com.br
  cyberlab recon timeline dominio.com.br
  cyberlab recon analytics dominio.com.br
  cyberlab recon remediation dominio.com.br
  cyberlab recon lan
EOF
}

usage_deliver() {
    cat <<'EOF'
Uso:
  cyberlab deliver build [scan_dir]
  cyberlab deliver polish [scan_dir]
  cyberlab deliver latest
EOF
}

usage_maintain() {
    cat <<'EOF'
Uso:
  cyberlab maintain health
  cyberlab maintain validate
  cyberlab maintain sync
  cyberlab maintain sync-all
  cyberlab maintain tools
  cyberlab maintain labup

  cyberlab maintain cleanup preview
  cyberlab maintain cleanup apply
  cyberlab maintain cleanup status
EOF
}

usage_lab() {
    cat <<'EOF'
Uso:
  cyberlab lab redteam
  cyberlab lab dashboard
  cyberlab lab monitor
EOF
}

show_latest_delivery() {
    python3 - <<'PY'
import json
from pathlib import Path

ctx = Path.home() / "CyberLab/state/audit/current_audit_context.json"

if not ctx.exists():
    print("[WARN] Nenhum contexto oficial encontrado.")
    raise SystemExit(0)

data = json.loads(ctx.read_text(encoding="utf-8"))

scan_dir = data.get("scan_dir")
print("=== CyberLab — Última Entrega ===")
print("Cliente:", data.get("client_name") or data.get("client"))
print("Alvo:", data.get("target"))
print("Status:", data.get("status"))
print("Scan:", scan_dir or "-")
print("")

artifacts = data.get("artifacts", {})
wanted = [
    "block17_final_executive_pdf",
    "block17_final_technical_pdf",
    "block17_final_remediation_pdf",
    "block17_client_delivery_dir",
    "block17_client_delivery_index_md",
]

for key in wanted:
    item = artifacts.get(key)
    if isinstance(item, dict):
        print(f"[OK] {key}: {item.get('path')}")
    else:
        print(f"[WARN] {key}: não registrado")
PY
}

GROUP="${1:-}"

case "$GROUP" in
    audit)
        ACTION="${2:-}"
        case "$ACTION" in
            run)
                CLIENT="${3:-}"
                TARGET="${4:-}"
                PROFILE="${5:-max-controlled}"

                if [ -z "$CLIENT" ] || [ -z "$TARGET" ]; then
                    usage_audit
                    exit 1
                fi

                run_cyberlab client-audit-final-approved "$CLIENT" "$TARGET" "$PROFILE"
                ;;
            active)
                CLIENT="${3:-}"
                TARGET="${4:-}"
                MODE="${5:-active}"

                if [ -z "$CLIENT" ] || [ -z "$TARGET" ]; then
                    usage_audit
                    exit 1
                fi

                run_cyberlab active run "$CLIENT" "$TARGET" "$MODE"
                ;;
            tools)
                TARGET="${3:-}"
                PROFILE="${4:-max-controlled}"

                if [ -z "$TARGET" ]; then
                    usage_audit
                    exit 1
                fi

                run_cyberlab audit-tools-approved "$TARGET" "$PROFILE"
                ;;
            status)
                run_cyberlab audit-context show
                ;;
            check)
                echo "=== 1) HEALTH ==="
                run_cyberlab health
                echo ""
                echo "=== 2) VALIDATE-ALL ==="
                run_cyberlab validate-all
                echo ""
                echo "=== 3) CONTEXTO ATUAL ==="
                run_cyberlab audit-context validate || true
                ;;
            context)
                SUB="${3:-show}"
                run_cyberlab audit-context "$SUB"
                ;;
            ""|help)
                usage_audit
                ;;
            *)
                echo "[ERRO] Ação de audit desconhecida: $ACTION"
                usage_audit
                exit 1
                ;;
        esac
        ;;

    recon)
        ACTION="${2:-}"
        TARGET="${3:-}"

        case "$ACTION" in
            lan)
                run_cyberlab lan
                ;;
            web|detect|threat|correlate|intelligence|findings|risk|assets|timeline|analytics|remediation)
                if [ -z "$TARGET" ]; then
                    usage_recon
                    exit 1
                fi
                run_cyberlab "$ACTION" "$TARGET"
                ;;
            ""|help)
                usage_recon
                ;;
            *)
                echo "[ERRO] Ação de recon desconhecida: $ACTION"
                usage_recon
                exit 1
                ;;
        esac
        ;;

    deliver)
        ACTION="${2:-}"
        SCAN_DIR="${3:-}"

        case "$ACTION" in
            build)
                if [ -n "$SCAN_DIR" ]; then
                    run_cyberlab client-final-delivery "$SCAN_DIR"
                else
                    run_cyberlab client-final-delivery
                fi
                ;;
            polish)
                if [ -n "$SCAN_DIR" ]; then
                    run_cyberlab client-final-polish "$SCAN_DIR"
                else
                    run_cyberlab client-final-polish
                fi
                ;;
            latest)
                show_latest_delivery
                ;;
            ""|help)
                usage_deliver
                ;;
            *)
                echo "[ERRO] Ação de deliver desconhecida: $ACTION"
                usage_deliver
                exit 1
                ;;
        esac
        ;;

    maintain)
        ACTION="${2:-}"
        SUB="${3:-}"

        case "$ACTION" in
            health)
                run_cyberlab health
                ;;
            validate)
                run_cyberlab validate-all
                ;;
            sync)
                run_cyberlab sync
                ;;
            sync-all)
                run_cyberlab sync-all
                ;;
            tools)
                run_cyberlab tools
                ;;
            labup)
                run_cyberlab labup
                ;;
            cleanup)
                case "$SUB" in
                    preview)
                        run_cyberlab cleanup-obsolete dry-run
                        ;;
                    apply)
                        run_cyberlab cleanup-obsolete apply
                        ;;
                    status)
                        run_cyberlab cleanup-status
                        ;;
                    *)
                        usage_maintain
                        exit 1
                        ;;
                esac
                ;;
            ""|help)
                usage_maintain
                ;;
            *)
                echo "[ERRO] Ação de maintain desconhecida: $ACTION"
                usage_maintain
                exit 1
                ;;
        esac
        ;;

    lab)
        ACTION="${2:-}"
        case "$ACTION" in
            redteam|dashboard|monitor)
                run_cyberlab "$ACTION"
                ;;
            ""|help)
                usage_lab
                ;;
            *)
                echo "[ERRO] Ação de lab desconhecida: $ACTION"
                usage_lab
                exit 1
                ;;
        esac
        ;;

    ""|help)
        usage_main
        ;;

    *)
        echo "[ERRO] Grupo desconhecido: $GROUP"
        usage_main
        exit 1
        ;;
esac
