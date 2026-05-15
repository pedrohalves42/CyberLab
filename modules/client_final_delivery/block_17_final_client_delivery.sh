#!/bin/bash
set -euo pipefail

source "$HOME/CyberLab/core/bootstrap.sh" 2>/dev/null || true
source "$HOME/CyberLab/.venv/bin/activate" 2>/dev/null || true

CONTEXT="$HOME/CyberLab/state/audit/current_audit_context.json"

if [ ! -f "$CONTEXT" ]; then
    echo "[ERRO] Contexto oficial não encontrado: $CONTEXT"
    exit 1
fi

SCAN_DIR="${1:-}"

if [ -z "$SCAN_DIR" ]; then
    SCAN_DIR="$(python3 - <<'PY'
import json
from pathlib import Path

p = Path.home() / "CyberLab/state/audit/current_audit_context.json"
data = json.loads(p.read_text(encoding="utf-8"))

print(
    data.get("scan_dir")
    or data.get("paths", {}).get("scan_dir")
    or data.get("paths", {}).get("official_scan_dir")
    or ""
)
PY
)"
fi

if [ -z "$SCAN_DIR" ] || [ ! -d "$SCAN_DIR" ]; then
    echo "[ERRO] Scan oficial inválido: $SCAN_DIR"
    exit 1
fi

OUT="$SCAN_DIR/block_17_client_final_delivery"
mkdir -p "$OUT"

echo "============================================================"
echo " CyberLab — BLOCO 17 FINAL"
echo " Entrega final sincronizada ao cliente"
echo "============================================================"
echo "[OK] Scan oficial: $SCAN_DIR"
echo ""

run_stage() {
    local IDX="$1"
    local NAME="$2"
    shift 2

    local STDOUT_LOG="$OUT/${IDX}_${NAME}_stdout.log"
    local STDERR_LOG="$OUT/${IDX}_${NAME}_stderr.log"

    echo "------------------------------------------------------------"
    echo "[B17] $IDX — $NAME"
    echo "------------------------------------------------------------"
    echo "[CMD] $*"

    if "$@" >"$STDOUT_LOG" 2>"$STDERR_LOG"; then
        cat "$STDOUT_LOG"
        echo "[OK] $NAME concluído."
    else
        RC=$?
        echo "[ERRO] $NAME falhou com código $RC"
        echo "--- STDOUT ---"
        cat "$STDOUT_LOG" 2>/dev/null || true
        echo "--- STDERR ---"
        cat "$STDERR_LOG" 2>/dev/null || true
        exit "$RC"
    fi

    echo ""
}

run_stage "01" "block17_4a_findings_consolidator" \
    bash "$HOME/CyberLab/modules/client_final_delivery/block_17_4a_findings_consolidator.sh"

run_stage "02" "block17_4a1_client_calibration" \
    bash "$HOME/CyberLab/modules/client_final_delivery/block_17_4a1_client_calibration.sh" "$SCAN_DIR"

run_stage "03" "block17_4b_client_language_translator" \
    bash "$HOME/CyberLab/modules/client_final_delivery/block_17_4b_client_language_translator.sh"

run_stage "04" "block17_4c_final_report_assembler" \
    bash "$HOME/CyberLab/modules/client_final_delivery/block_17_4c_final_report_assembler.sh"

run_stage "05" "block17_4c1_editorial_polisher" \
    bash "$HOME/CyberLab/modules/client_final_delivery/block_17_4c1_editorial_polisher.sh" "$SCAN_DIR"

run_stage "06" "block17_4c2_technical_severity_integrity_fix" \
  bash "$HOME/CyberLab/modules/client_final_delivery/block_17_4c2_technical_severity_integrity_fix.sh" "$SCAN_DIR"

run_stage "07" "block17_4d_final_pdf_publisher" \
    bash "$HOME/CyberLab/modules/client_final_delivery/block_17_4d_final_pdf_publisher.sh" "$SCAN_DIR"

python3 - "$SCAN_DIR" <<'PY'
import json
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

HOME = Path.home()
CYBERLAB = HOME / "CyberLab"
CONTEXT = CYBERLAB / "state/audit/current_audit_context.json"
SCAN_DIR = Path(sys.argv[1]).expanduser().resolve()
OUT = SCAN_DIR / "block_17_client_final_delivery"

def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")

def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "cliente"

def artifact(path: Path, kind="file"):
    return {
        "path": str(path),
        "kind": kind,
        "exists": path.exists(),
        "registered_at": now_iso(),
    }

data = json.loads(CONTEXT.read_text(encoding="utf-8"))

client = str(data.get("client_name") or data.get("client") or "Cliente")
target = str(data.get("target") or "alvo")
session_id = str(data.get("session_id") or SCAN_DIR.name)

pdfs = {
    "executive_pdf": OUT / "client_final_executive_report.pdf",
    "technical_pdf": OUT / "client_final_technical_report.pdf",
    "remediation_pdf": OUT / "client_final_remediation_plan.pdf",
}

for key, path in pdfs.items():
    if not path.exists():
        raise SystemExit(f"[ERRO] PDF final ausente: {path}")

status_path = OUT / "block_17_final_delivery_status.json"
manifest_path = OUT / "block_17_final_delivery_manifest.json"
summary_path = OUT / "block_17_final_delivery_summary.md"

client_delivery_dir = (
    CYBERLAB
    / "clients"
    / slugify(client)
    / "reports"
    / "client-final-delivery"
    / session_id
)
client_delivery_dir.mkdir(parents=True, exist_ok=True)

copied = {}
for name, path in pdfs.items():
    dest = client_delivery_dir / path.name
    shutil.copy2(path, dest)
    copied[name] = str(dest)

index_path = client_delivery_dir / "delivery_index.md"

status = {
    "block": "17",
    "module": "Final Client Delivery Orchestrator",
    "status": "OK",
    "client": client,
    "target": target,
    "scan_dir": str(SCAN_DIR),
    "delivery_dir": str(client_delivery_dir),
    "generated_at": now_iso(),
    "pdfs": {k: str(v) for k, v in pdfs.items()},
    "client_mirror": copied,
}

manifest = {
    "schema": "cyberlab.block17.final_delivery.v1",
    "client": client,
    "target": target,
    "scan_dir": str(SCAN_DIR),
    "generated_at": status["generated_at"],
    "outputs": {
        "pdfs": {k: str(v) for k, v in pdfs.items()},
        "client_delivery_dir": str(client_delivery_dir),
        "status_json": str(status_path),
        "summary_md": str(summary_path),
        "delivery_index_md": str(index_path),
    },
}

summary = f"""# CyberLab — Bloco 17 Finalizado

## Entrega final ao cliente

- **Cliente:** {client}
- **Alvo:** {target}
- **Scan oficial:** `{SCAN_DIR}`
- **Pacote espelhado em:** `{client_delivery_dir}`

## PDFs finais

- Executivo: `{pdfs["executive_pdf"]}`
- Técnico: `{pdfs["technical_pdf"]}`
- Plano de correção: `{pdfs["remediation_pdf"]}`

## Espelho por cliente

- Executivo: `{copied["executive_pdf"]}`
- Técnico: `{copied["technical_pdf"]}`
- Plano de correção: `{copied["remediation_pdf"]}`

## Status

**Bloco 17 concluído com sincronização total.**
"""

index = f"""# Entrega Final — {client}

## Alvo auditado
`{target}`

## PDFs prontos para entrega

1. `client_final_executive_report.pdf`
2. `client_final_technical_report.pdf`
3. `client_final_remediation_plan.pdf`

## Origem do scan
`{SCAN_DIR}`

## Status
Entrega final gerada pelo Bloco 17 do CyberLab.
"""

status_path.write_text(json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
summary_path.write_text(summary, encoding="utf-8")
index_path.write_text(index, encoding="utf-8")

stages = data.setdefault("stages", {})
stages["block17_final_client_delivery"] = {
    "status": "OK",
    "message": "Entrega final ao cliente concluída com PDFs e espelho por cliente.",
    "updated_at": now_iso(),
    "scan_dir": str(SCAN_DIR),
    "delivery_dir": str(client_delivery_dir),
    "status_json": str(status_path),
    "manifest_json": str(manifest_path),
    "summary_md": str(summary_path),
}

artifacts = data.setdefault("artifacts", {})
artifacts["block17_final_delivery_status_json"] = artifact(status_path)
artifacts["block17_final_delivery_manifest_json"] = artifact(manifest_path)
artifacts["block17_final_delivery_summary_md"] = artifact(summary_path)
artifacts["block17_client_delivery_index_md"] = artifact(index_path)
artifacts["block17_client_delivery_dir"] = artifact(client_delivery_dir, "dir")

for key, path in pdfs.items():
    artifacts[f"block17_final_{key}"] = artifact(path)

CONTEXT.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

print("============================================================")
print(" BLOCO 17 FINALIZADO")
print("============================================================")
print(f"[OK] Cliente: {client}")
print(f"[OK] Alvo: {target}")
print(f"[OK] Scan oficial: {SCAN_DIR}")
print("")
print("[PDFs FINAIS]")
for _, path in pdfs.items():
    print(f" - {path}")
print("")
print("[ESPELHO POR CLIENTE]")
print(f" - {client_delivery_dir}")
print("")
print(f"[OK] Manifesto: {manifest_path}")
print(f"[OK] Status: {status_path}")
print(f"[OK] Resumo: {summary_path}")
print(f"[OK] Índice cliente: {index_path}")
PY

echo ""
echo "============================================================"
echo "[OK] Bloco 17 final concluído com sincronia total."
echo "============================================================"
