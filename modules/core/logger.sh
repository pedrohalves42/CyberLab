#!/bin/bash
set -u

LOG_DIR="$HOME/CyberLab/logs"
mkdir -p "$LOG_DIR"

log_event() {
  local level="$1"
  local module="$2"
  local msg="$3"

  printf '{"ts":"%s","level":"%s","module":"%s","message":"%s"}\n' \
    "$(date -Iseconds)" "$level" "$module" "$msg" \
    >> "$LOG_DIR/cyberlab.jsonl"
}
