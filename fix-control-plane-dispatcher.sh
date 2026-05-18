#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"
BIN="$BASE/bin/cyberlab"

echo "==== FIX CONTROL PLANE DISPATCHER ===="

python3 <<'PY'
from pathlib import Path

p = Path.home() / "CyberLab/bin/cyberlab"

s = p.read_text()

blocks = {
"evidence": '''
evidence)
    shift
    bash "$CYBERLAB_HOME/modules/evidence/evidence.sh" "$@"
    ;;
''',

"rbac": '''
rbac)
    shift
    bash "$CYBERLAB_HOME/modules/rbac/rbac.sh" "$@"
    ;;
''',

"approval": '''
approval)
    shift
    bash "$CYBERLAB_HOME/modules/approval/approval.sh" "$@"
    ;;
''',

"queue": '''
queue)
    shift
    bash "$CYBERLAB_HOME/modules/queue/queue.sh" "$@"
    ;;
''',

"control": '''
control)
    shift
    bash "$CYBERLAB_HOME/modules/control/control.sh" "$@"
    ;;
'''
}

for key, block in blocks.items():
    if f"{key})" not in s:

        idx = s.rfind("*)")

        if idx != -1:
            s = s[:idx] + block + "\n" + s[idx:]
        else:
            s += "\n" + block

p.write_text(s)

print("[OK] dispatcher sincronizado")
PY

chmod +x "$BIN"

echo
echo "[OK] Fix aplicado"
echo
echo "Recarregue:"
echo "source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh""
echo "hash -r"
