#!/usr/bin/env bash
set -euo pipefail

BIN="$HOME/CyberLab/bin/cyberlab"

echo "==== FIX DISPATCHER CONTROL PLANE V3 ===="

python3 <<'PY'
from pathlib import Path
import re

p = Path.home() / "CyberLab/bin/cyberlab"
s = p.read_text()

for cmd in ["rbac", "evidence", "approval", "control", "queue"]:
    pattern = rf'\n?{cmd}\)\n.*?\n\s*;;\n'
    s = re.sub(pattern, "\n", s, flags=re.S)

blocks = '''
rbac)
    bash "$HOME/CyberLab/modules/rbac/rbac.sh" "$@"
    ;;

evidence)
    bash "$HOME/CyberLab/modules/evidence/evidence.sh" "$@"
    ;;

approval)
    bash "$HOME/CyberLab/modules/approval/approval.sh" "$@"
    ;;

control)
    bash "$HOME/CyberLab/modules/control/control.sh" "$@"
    ;;

queue)
    bash "$HOME/CyberLab/modules/queue/queue.sh" "$@"
    ;;
'''

idx = s.rfind("*)")
if idx == -1:
    raise SystemExit("[ERRO] não achei bloco *) no dispatcher")

s = s[:idx] + blocks + "\n" + s[idx:]
p.write_text(s)

print("[OK] dispatcher corrigido sem shift duplo")
PY

chmod +x "$BIN"

echo "[OK] Fix aplicado"
