#!/usr/bin/env bash
set -euo pipefail

# Explicit files exercise the same predicate as the repository scan.
pattern='si''lo|sp''ike|\bw[0-9]{2}[a-z]?\b|\bs1-'
# Module paths name the organization that hosts the repositories, not a product,
# so that prefix is dropped before matching.
org_prefix='github\.com/Si''lo-Server/'
check_file() {
  local status=0
  sed "s#${org_prefix}##g" -- "$1" | grep -nEi -- "$pattern" || status=$?
  case "$status" in
    0) return 1 ;;
    1) return 0 ;;
    *) return 2 ;;
  esac
}

if [ "$#" -gt 0 ]; then
  result=0
  for file in "$@"; do
    if check_file "$file"; then
      :
    else
      status=$?
      if [ "$status" -gt "$result" ]; then result=$status; fi
    fi
  done
  exit "$result"
fi

cd "$(dirname "$0")/.."
# Include new files so a local run checks the current tree before staging.
files=$(git -c core.fsmonitor=false ls-files --cached --others --exclude-standard -- \
  '*.go' '*.md' '*.json' '*.sh')
result=0
while IFS= read -r file; do
  case "$file" in
    ''|NOTICE|.github/workflows/ci.yml|scripts/testdata/names-bad.txt) continue ;;
  esac
  if check_file "$file"; then
    :
  else
    status=$?
    printf 'name check refuses %s\n' "$file" >&2
    if [ "$status" -gt "$result" ]; then result=$status; fi
  fi
done <<< "$files"
exit "$result"
