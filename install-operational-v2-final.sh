#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"

echo "==== CYBERLAB OPERATION + SQLITE V2 FINAL ===="

mkdir -p \
  "$BASE/modules/operation" \
  "$BASE/modules/db" \
  "$BASE/operations" \
  "$BASE/db" \
  "$BASE/state"

cp "$BASE/bin/cyberlab" "$BASE/bin/cyberlab.bak.v2.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true

cat > "$BASE/modules/operation/operation-v2.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"
OPS="$BASE/operations"
CURRENT="$BASE/state/current-operation.txt"

mkdir -p "$OPS" "$BASE/state"

[ "${1:-}" = "op" ] && shift || true

slugify() {
  echo "$1" | tr '[:upper:]' '[:lower:]' \
  | sed 's/[^a-z0-9]/-/g' \
  | sed 's/-\+/-/g' \
  | sed 's/^-//;s/-$//'
}

current_path() {
  cat "$CURRENT" 2>/dev/null || true
}

create_op() {
  CLIENT="${1:-}"
  TARGET="${2:-}"

  [ -z "$CLIENT" ] && {
    echo "[ERRO] Uso: cyberlab op create \"Cliente\" dominio.com"
    exit 1
  }

  SLUG="$(slugify "$CLIENT")"
  OP_ID="op-$(date +%Y%m%d-%H%M%S)-$SLUG"
  OP="$OPS/$OP_ID"

  mkdir -p \
    "$OP/state/intelligence" \
    "$OP/state/reports" \
    "$OP/evidence" \
    "$OP/delivery" \
    "$OP/logs"

  cat > "$OP/client.json" <<JSON
{
  "operation_id": "$OP_ID",
  "client": "$CLIENT",
  "client_slug": "$SLUG",
  "target": "$TARGET",
  "created_at": "$(date -Iseconds)"
}
JSON

  cat > "$OP/manifest.json" <<JSON
{
  "operation_id": "$OP_ID",
  "client": "$CLIENT",
  "client_slug": "$SLUG",
  "target": "$TARGET",
  "status": "created",
  "created_at": "$(date -Iseconds)"
}
JSON

  echo "$OP" > "$CURRENT"

  echo "[OK] Operação criada:"
  echo "$OP"
}

use_op() {
  ID="${1:-}"

  [ -z "$ID" ] && {
    echo "[ERRO] Uso: cyberlab op use op-id"
    exit 1
  }

  if [ -d "$OPS/$ID" ]; then
    echo "$OPS/$ID" > "$CURRENT"
  elif [ -d "$ID" ]; then
    echo "$ID" > "$CURRENT"
  else
    echo "[ERRO] Operação não encontrada: $ID"
    exit 1
  fi

  echo "[OK] Operação ativa:"
  cat "$CURRENT"
}

sync_op() {
  OP="$(current_path)"

  [ -z "$OP" ] || [ ! -d "$OP" ] && {
    echo "[ERRO] Nenhuma operação ativa"
    exit 1
  }

  mkdir -p "$OP/state/intelligence" "$OP/state/reports"

  cp "$BASE/state/intelligence/"*.json "$OP/state/intelligence/" 2>/dev/null || true
  cp "$BASE/state/reports/"* "$OP/state/reports/" 2>/dev/null || true

  LATEST_DELIVERY="$(cat "$BASE/clients/"*/reports/latest-delivery.txt 2>/dev/null | tail -n 1 || true)"
  if [ -n "$LATEST_DELIVERY" ] && [ -d "$LATEST_DELIVERY" ]; then
    rm -rf "$OP/delivery/latest"
    mkdir -p "$OP/delivery"
    cp -r "$LATEST_DELIVERY" "$OP/delivery/latest"
  fi

  python3 <<PY
import json, time
from pathlib import Path

op = Path("$OP")
client = {}
try:
    client = json.loads((op / "client.json").read_text())
except Exception:
    pass

manifest = {
    "operation_id": op.name,
    "client": client.get("client", ""),
    "client_slug": client.get("client_slug", ""),
    "target": client.get("target", ""),
    "status": "synced",
    "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "paths": {
        "state": str(op / "state"),
        "reports": str(op / "state/reports"),
        "delivery": str(op / "delivery")
    }
}

(op / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
PY

  echo "[OK] Operação sincronizada:"
  echo "$OP"
}

run_op() {
  CLIENT="${1:-}"
  TARGET="${2:-}"
  MODE="${3:-safe}"

  [ -z "$CLIENT" ] || [ -z "$TARGET" ] && {
    echo "[ERRO] Uso: cyberlab op run \"Cliente\" dominio.com safe"
    exit 1
  }

  create_op "$CLIENT" "$TARGET"

  cyberlab run-basic "$CLIENT" "$TARGET" "$MODE"
  cyberlab intelligence
  cyberlab correlate
  cyberlab report
  cyberlab delivery generate "$CLIENT"

  sync_op
  cyberlab db sync || true

  echo "[OK] Operação completa finalizada"
}

case "${1:-help}" in
  create) shift; create_op "$@" ;;
  use) shift; use_op "$@" ;;
  current) current_path ;;
  list) find "$OPS" -maxdepth 1 -type d -name "op-*" | sort ;;
  sync) sync_op ;;
  run) shift; run_op "$@" ;;
  *)
    echo "Uso:"
    echo "cyberlab op create \"Cliente\" dominio.com"
    echo "cyberlab op use op-id"
    echo "cyberlab op current"
    echo "cyberlab op list"
    echo "cyberlab op sync"
    echo "cyberlab op run \"Cliente\" dominio.com safe"
    ;;
esac
SCRIPT

chmod +x "$BASE/modules/operation/operation-v2.sh"

cat > "$BASE/modules/db/db-v2.py" <<'PY'
#!/usr/bin/env python3
import json, sqlite3, sys, time
from pathlib import Path

BASE = Path.home() / "CyberLab"
DB = BASE / "db/cyberlab.db"
CURRENT = BASE / "state/current-operation.txt"

def connect():
    DB.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB)

def init():
    con = connect()
    cur = con.cursor()

    cur.executescript("""
    PRAGMA journal_mode=WAL;

    CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      slug TEXT UNIQUE,
      name TEXT,
      target TEXT,
      created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS operations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      operation_id TEXT UNIQUE,
      client_slug TEXT,
      client_name TEXT,
      target TEXT,
      path TEXT,
      status TEXT,
      created_at TEXT,
      updated_at TEXT
    );

    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      operation_id TEXT,
      severity TEXT,
      title TEXT,
      description TEXT,
      asset TEXT,
      recommendation TEXT,
      priority_score INTEGER,
      confidence INTEGER,
      created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS scores (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      operation_id TEXT,
      score INTEGER,
      level TEXT,
      critical INTEGER,
      high INTEGER,
      medium INTEGER,
      low INTEGER,
      info INTEGER,
      created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS correlations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      operation_id TEXT,
      name TEXT,
      risk TEXT,
      description TEXT,
      recommendation TEXT,
      created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      operation_id TEXT,
      type TEXT,
      path TEXT,
      created_at TEXT
    );
    """)

    con.commit()
    con.close()
    print(f"[OK] DB inicializado: {DB}")

def load_json(path, default):
    try:
        if path.exists() and path.stat().st_size > 0:
            return json.loads(path.read_text(errors="ignore"))
    except Exception:
        pass
    return default

def current_op():
    if not CURRENT.exists():
        return None
    p = Path(CURRENT.read_text().strip())
    return p if p.exists() else None

def sync():
    init()

    op = current_op()
    if not op:
        print("[ERRO] Nenhuma operação ativa. Use: cyberlab op create \"Cliente\" dominio.com")
        sys.exit(1)

    client = load_json(op / "client.json", {})
    op_id = op.name
    slug = client.get("client_slug", "cliente")
    name = client.get("client", "Cliente")
    target = client.get("target", "")
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")

    intel = BASE / "state/intelligence"
    reports = BASE / "state/reports"

    findings_data = load_json(intel / "findings-scored.json", {"findings": []})
    risk = load_json(intel / "risk-summary.json", {})
    corr = load_json(intel / "correlation-summary.json", {"correlations": []})

    con = connect()
    cur = con.cursor()

    cur.execute(
        "INSERT OR IGNORE INTO clients (slug, name, target, created_at) VALUES (?, ?, ?, ?)",
        (slug, name, target, now)
    )

    cur.execute("""
        INSERT OR REPLACE INTO operations
        (operation_id, client_slug, client_name, target, path, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM operations WHERE operation_id=?), ?), ?)
    """, (op_id, slug, name, target, str(op), "synced", op_id, now, now))

    for table in ["findings", "scores", "correlations", "reports"]:
        cur.execute(f"DELETE FROM {table} WHERE operation_id=?", (op_id,))

    for f in findings_data.get("findings", []):
        if not isinstance(f, dict):
            continue
        cur.execute("""
            INSERT INTO findings
            (operation_id, severity, title, description, asset, recommendation, priority_score, confidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            op_id,
            f.get("severity", "INFO"),
            f.get("title", ""),
            f.get("description", ""),
            f.get("asset", ""),
            f.get("recommendation", ""),
            int(f.get("priority_score", 0) or 0),
            int(f.get("confidence", 0) or 0),
            now
        ))

    cur.execute("""
        INSERT INTO scores
        (operation_id, score, level, critical, high, medium, low, info, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        op_id,
        int(risk.get("score", 0) or 0),
        risk.get("level", "BAIXO"),
        int(risk.get("critical", 0) or 0),
        int(risk.get("high", 0) or 0),
        int(risk.get("medium", 0) or 0),
        int(risk.get("low", 0) or 0),
        int(risk.get("info", 0) or 0),
        now
    ))

    for c in corr.get("correlations", []):
        if not isinstance(c, dict):
            continue
        cur.execute("""
            INSERT INTO correlations
            (operation_id, name, risk, description, recommendation, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            op_id,
            c.get("name", ""),
            c.get("risk", "INFO"),
            c.get("description", ""),
            c.get("recommendation", ""),
            now
        ))

    if reports.exists():
        for p in reports.iterdir():
            if p.is_file():
                cur.execute(
                    "INSERT INTO reports (operation_id, type, path, created_at) VALUES (?, ?, ?, ?)",
                    (op_id, p.suffix.replace(".", "") or "file", str(p), now)
                )

    con.commit()
    con.close()

    print(f"[OK] DB sincronizado: {op_id}")

def status():
    init()
    con = connect()
    cur = con.cursor()

    print("==== OPERAÇÕES ====")
    for row in cur.execute("SELECT operation_id, client_name, target, status, updated_at FROM operations ORDER BY id DESC LIMIT 10"):
        print(" | ".join(str(x) for x in row))

    print("\n==== SCORES ====")
    for row in cur.execute("SELECT operation_id, score, level, critical, high, medium, low, info FROM scores ORDER BY id DESC LIMIT 10"):
        print(" | ".join(str(x) for x in row))

    print("\n==== FINDINGS POR OPERAÇÃO ====")
    for row in cur.execute("SELECT operation_id, COUNT(*) FROM findings GROUP BY operation_id ORDER BY COUNT(*) DESC LIMIT 10"):
        print(" | ".join(str(x) for x in row))

    con.close()

cmd = sys.argv[1] if len(sys.argv) > 1 else "status"

if cmd == "init":
    init()
elif cmd == "sync":
    sync()
elif cmd == "status":
    status()
else:
    print("Uso: cyberlab db init|sync|status")
PY

chmod +x "$BASE/modules/db/db-v2.py"

python3 <<'PY'
from pathlib import Path

p = Path.home() / "CyberLab/bin/cyberlab"
s = p.read_text()

def upsert_case(src, name, block):
    if f"{name})" in src:
        start = src.find(f"{name})")
        end = src.find(";;", start)
        if end != -1:
            end += 2
            return src[:start] + block + src[end:]
    idx = src.rfind("*)")
    if idx != -1:
        return src[:idx] + block + "\n" + src[idx:]
    return src + "\n" + block

op_block = '''op)
    bash "$CYBERLAB_HOME/modules/operation/operation-v2.sh" "$@"
    ;;
'''

db_block = '''db)
    python3 "$CYBERLAB_HOME/modules/db/db-v2.py" "${1:-status}"
    ;;
'''

s = upsert_case(s, "op", op_block)
s = upsert_case(s, "db", db_block)

p.write_text(s)
PY

chmod +x "$BASE/bin/cyberlab"

echo "[OK] Operational V2 Final instalado"
echo
echo "Fluxo recomendado:"
echo "source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh""
echo "hash -r"
echo "cyberlab op run \"Loja Maromba\" lojamaromba.com safe"
echo "cyberlab db status"
