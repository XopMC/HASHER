#!/usr/bin/env bash
set -u
exe=${1:?HASHER executable required}
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
for ((i=0; i<20000; ++i)); do printf 'abc\n'; done > "$tmp"
set +e
"$exe" -sha256 -i "$tmp" 2>/dev/null | head -n 1 >/dev/null
rc=${PIPESTATUS[0]}
set -e
if [[ $rc -ne 2 ]]; then
  echo "expected HASHER exit 2 on broken pipe, got $rc" >&2
  exit 1
fi
