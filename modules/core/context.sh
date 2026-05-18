#!/bin/bash
set -u

export CYBERLAB_BASE="$CYBERLAB_HOME"
export CYBERLAB_STATE="$CYBERLAB_BASE/state"
export CYBERLAB_INTEL="$CYBERLAB_STATE/intelligence"
export CYBERLAB_LOGS="$CYBERLAB_BASE/logs"
export CYBERLAB_CLIENTS="$CYBERLAB_BASE/clients"

slugify() {
  echo "$1" \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/[^a-z0-9]/-/g' \
  | sed 's/-\+/-/g' \
  | sed 's/^-//;s/-$//'
}

client_dir() {
  local client="$1"
  local slug
  slug="$(slugify "$client")"
  echo "$CYBERLAB_CLIENTS/$slug"
}

latest_delivery() {
  local client="$1"
  local slug
  slug="$(slugify "$client")"
  find "$CYBERLAB_CLIENTS/$slug/reports/delivery" -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1
}
