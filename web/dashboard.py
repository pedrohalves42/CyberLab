#!/usr/bin/env python3

import json
import os
import subprocess
from pathlib import Path
from flask import Flask, render_template, send_file, redirect, url_for, request, abort

CYBERLAB_HOME = Path.home() / "CyberLab"
RESULTS_WEB = CYBERLAB_HOME / "results" / "web"

app = Flask(__name__)


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def scan_dirs():
    scans = []

    if not RESULTS_WEB.exists():
        return scans

    for target_dir in RESULTS_WEB.iterdir():
        if not target_dir.is_dir():
            continue

        for scan_dir in target_dir.iterdir():
            if not scan_dir.is_dir():
                continue

            summary = read_json(scan_dir / "10-json" / "summary.json")
            risk = read_json(scan_dir / "10-json" / "risk-summary.json")

            scans.append({
                "target": summary.get("target", target_dir.name),
                "client": summary.get("client", "Cliente"),
                "mode": summary.get("mode", "-"),
                "url": summary.get("url", "-"),
                "date": summary.get("date", scan_dir.name),
                "score": risk.get("score", summary.get("score", 0)),
                "level": risk.get("level", summary.get("level", "BAIXO")),
                "low": risk.get("findings", {}).get("low", 0),
                "medium": risk.get("findings", {}).get("medium", 0),
                "high": risk.get("findings", {}).get("high", 0),
                "critical": risk.get("findings", {}).get("critical", 0),
                "path": str(scan_dir),
                "id": scan_dir.name,
            })

    scans.sort(key=lambda x: x["path"], reverse=True)
    return scans


def find_scan(scan_path):
    p = Path(scan_path).expanduser()
    if not p.exists():
        return None
    if not str(p).startswith(str(RESULTS_WEB)):
        return None
    return p


@app.route("/")
def index():
    scans = scan_dirs()

    total = len(scans)
    high_or_more = len([s for s in scans if s["level"] in ["ALTO", "CRÍTICO"]])
    clients = len(set(s["client"] for s in scans))
    targets = len(set(s["target"] for s in scans))

    return render_template(
        "index.html",
        scans=scans,
        total=total,
        high_or_more=high_or_more,
        clients=clients,
        targets=targets
    )


@app.route("/scan")
def scan_form():
    return render_template("scan.html")


@app.route("/scan/run", methods=["POST"])
def scan_run():
    target = request.form.get("target", "").strip()
    mode = request.form.get("mode", "safe").strip()
    client = request.form.get("client", "Cliente").strip()

    if not target:
        return redirect(url_for("scan_form"))

    cmd = [
        str(CYBERLAB_HOME / "bin" / "cyberlab"),
        "scan",
        target,
        mode,
        client
    ]

    subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return redirect(url_for("index"))


@app.route("/view")
def view_scan():
    scan_path = request.args.get("path", "")
    p = find_scan(scan_path)

    if not p:
        abort(404)

    summary = read_json(p / "10-json" / "summary.json")
    risk = read_json(p / "10-json" / "risk-summary.json")

    matrix = ""
    matrix_path = p / "09-report" / "risk-matrix.tsv"
    if matrix_path.exists():
        matrix = matrix_path.read_text(encoding="utf-8", errors="ignore")

    analysis = ""
    analysis_path = p / "09-report" / "risk-analysis.md"
    if analysis_path.exists():
        analysis = analysis_path.read_text(encoding="utf-8", errors="ignore")

    return render_template(
        "view.html",
        path=str(p),
        summary=summary,
        risk=risk,
        matrix=matrix,
        analysis=analysis
    )


@app.route("/file")
def file_view():
    scan_path = request.args.get("path", "")
    name = request.args.get("name", "")

    p = find_scan(scan_path)
    if not p:
        abort(404)

    allowed = {
        "html": p / "09-report" / "report.html",
        "pdf": p / "09-report" / "report.pdf",
        "executive": p / "09-report" / "executive-report.md",
        "technical": p / "09-report" / "technical-report.md",
        "risk": p / "09-report" / "risk-analysis.md",
        "matrix": p / "09-report" / "risk-matrix.tsv",
    }

    file_path = allowed.get(name)

    if not file_path or not file_path.exists():
        abort(404)

    return send_file(file_path)








@app.route("/delivery")
def delivery():
    client = request.args.get("client", "").strip()

    if not client:
        return "Cliente não informado", 400

    result = subprocess.run(
        [str(CYBERLAB_HOME / "bin" / "cyberlab"), "delivery", "generate", client],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return "<pre>" + result.stdout + "\n" + result.stderr + "</pre>", 500

    return redirect("/clients")


@app.route("/delivery/download")
def delivery_download():
    client = request.args.get("client", "").strip()

    if not client:
        return "Cliente não informado", 400

    result = subprocess.run(
        [str(CYBERLAB_HOME / "bin" / "cyberlab"), "delivery", "zip", client],
        capture_output=True,
        text=True
    )

    zip_path = result.stdout.strip()

    if result.returncode != 0 or not zip_path:
        return "<pre>" + result.stdout + "\n" + result.stderr + "</pre>", 404

    p = Path(zip_path)

    if not p.exists():
        return "ZIP não encontrado", 404

    return send_file(p, as_attachment=True)

@app.route("/clients")
def clients():
    clients_dir = CYBERLAB_HOME / "clients"
    items = []

    if clients_dir.exists():
        for d in clients_dir.iterdir():
            if not d.is_dir():
                continue

            info = read_json(d / "client.json")
            if not info:
                continue

            latest_file = d / "reports" / "latest.txt"
            latest = latest_file.read_text().strip() if latest_file.exists() else ""

            items.append({
                "name": info.get("name", d.name),
                "slug": info.get("slug", d.name),
                "domain": info.get("primary_domain", "-"),
                "created": info.get("created_at", "-"),
                "latest": latest
            })

    return render_template("clients.html", clients=items)


@app.route("/latest")
def latest():
    latest_file = RESULTS_WEB / "latest.txt"

    if not latest_file.exists():
        return redirect(url_for("index"))

    scan_path = latest_file.read_text().strip()
    return redirect(url_for("view_scan", path=scan_path))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9088, debug=False)
