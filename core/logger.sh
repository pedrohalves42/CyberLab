#!/bin/bash

log_file="$CYBERLAB_LOGS/cyberlab.log"

log() {
  level="$1"
  msg="$2"
  mkdir -p "$CYBERLAB_LOGS"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg" | tee -a "$log_file"
}

info() {
  log "INFO" "$1"
}

warn() {
  log "WARN" "$1"
}

error() {
  log "ERROR" "$1"
}
