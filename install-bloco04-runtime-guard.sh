    done
}
EMERGENCY

chmod +x "$MOD/emergency.sh"

############################################
# integração no bin/cyberlab
############################################

python3 << 'PY'
from pathlib import Path

p = Path.home() / 'CyberLab/bin/cyberlab'
s = p.read_text()

block = r'''
runtime)
    source "$HOME/CyberLab/modules/runtime/runtime.sh"

    SUB="${1:-}"
    shift || true

    case "$SUB" in
        lock)
            runtime_lock "$1"
            ;;

        unlock)
            runtime_unlock "$1"
            ;;

        validate)
            runtime_validate_limits "$1" "$2"
            ;;

        *)
            echo "Uso: cyberlab runtime {lock|unlock|validate}"
            ;;
    esac
    ;;
'''

if 'runtime)' not in s:
    idx = s.rfind('*)')

    if idx != -1:
        s = s[:idx] + block + '\n' + s[idx:]

p.write_text(s)
PY

chmod +x "$BASE/bin/cyberlab"

############################################
# mensagem final
############################################

echo

echo "==== CYBERLAB BLOCO 04 — RUNTIME GUARD ENTERPRISE ===="

echo "[OK] Runtime Guard instalado"

echo

echo "Fluxo recomendado:"

echo "source ~/CyberLab/core/bootstrap.sh"
echo "hash -r"
echo "cyberlab runtime validate 5 5"
echo "cyberlab runtime lock op-teste"
echo "cyberlab runtime unlock op-teste"

