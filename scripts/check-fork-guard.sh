#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
case "${1-}" in
  '') keep=false ;;
  --keep-replace) keep=true ;;
  *) printf 'usage: %s [--keep-replace]\n' "$0" >&2; exit 1 ;;
esac

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
# Include untracked implementation files without copying repository metadata.
tar --exclude=.git -cf - . | tar -xf - -C "$scratch"
cd "$scratch"
export GOWORK=off
export GOFLAGS=
# Preserve the meaning of relative replacements after relocating the copy.
for module in github.com/quic-go/quic-go tailscale.com; do
  target=$(cd "$root" && go list -mod=readonly -m -f '{{.Dir}}' "$module")
  go mod edit "-replace=$module=$target"
done
# Establish that these same production sources compile against the forks.
if ! go build -mod=mod ./engine/... >build.log 2>&1; then
  cat build.log
  exit 1
fi
if ! "$keep"; then
  go mod edit -dropreplace=github.com/quic-go/quic-go -dropreplace=tailscale.com
fi

if go build -mod=mod -gcflags=-e ./engine/... >build.log 2>&1; then
  printf 'fork guard refused: build succeeded\n' >&2
  exit 1
fi
cat build.log
# Every diagnostic must be a missing fork API in production engine code.
# Unknown failures, including downloads and missing checksums, refuse the gate.
awk '
  /^# / { next }
  /^engine\/.*\.go:[0-9]+:[0-9]+: / && !/_test\.go:/ {
    signature=0
    if ($0 ~ /undefined: [[:alnum:]_.]+$/ ||
        $0 ~ /unknown field [[:alnum:]_]+ in struct literal of type / ||
        $0 ~ /has no field or method [[:alnum:]_]+\)$/) { missing++; next }
    # The positive control attributes signature differences in these
    # unchanged sources to replacing the dependencies, too.
    if ($0 ~ /(too many|not enough) arguments in call to /) { signature=1; next }
  }
  signature && /^[[:space:]]+(have|want) \(/ { next }
  { invalid=1 }
  END { exit !(missing > 0 && !invalid) }
' build.log
