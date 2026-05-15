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
