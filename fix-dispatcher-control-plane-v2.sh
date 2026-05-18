#!/usr/bin/env bash
set -euo pipefail

BIN="$CYBERLAB_HOME/bin/cyberlab"

echo "==== FIX DISPATCHER CONTROL PLANE V2 ===="

python3 <<'PY'
from pathlib import Path
import re

p = Path.home() / "CyberLab/bin/cyberlab"
s = p.read_text()

# remove blocos antigos problemáticos
for cmd in ["rbac", "evidence", "approval", "control", "queue"]:
    pattern = rf'\n?{cmd}\)\n.*?\n\s*;;\n'
    s = re.sub(pattern, "\n", s, flags=re.S)

blocks = '''
rbac)
    shift
    bash "$CYBERLAB_HOME/modules/rbac/rbac.sh" "$@"
    ;;

evidence)
    shift
    bash "$CYBERLAB_HOME/modules/evidence/evidence.sh" "$@"
    ;;

approval)
    shift
    bash "$CYBERLAB_HOME/modules/approval/approval.sh" "$@"
    ;;

control)
    shift
    bash "$CYBERLAB_HOME/modules/control/control.sh" "$@"
    ;;

queue)
    shift
    bash "$CYBERLAB_HOME/modules/queue/queue.sh" "$@"
    ;;
'''

idx = s.rfind("*)")
if idx == -1:
    raise SystemExit("[ERRO] não achei bloco *) no dispatcher")

s = s[:idx] + blocks + "\n" + s[idx:]
p.write_text(s)
print("[OK] dispatcher regravado com HOME absoluto")
PY

chmod +x "$BIN"

echo "[OK] Fix aplicado"
