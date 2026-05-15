#!/bin/bash

clean_target() {
  target="$1"
  target="${target#http://}"
  target="${target#https://}"
  target="${target%%/*}"
  target="${target%/}"
  echo "$target"
}

timestamp() {
  date '+%Y-%m-%d_%H-%M-%S'
}

require_tool() {
  tool="$1"
  command -v "$tool" >/dev/null 2>&1
}

safe_mkdir() {
  mkdir -p "$1"
}
