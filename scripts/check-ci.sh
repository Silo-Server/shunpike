#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(go list -m -f '{{.Version}}' tailscale.com)
if [ "$version" != v1.104.2 ]; then
  printf 'tailscale.com requirement is %s; want v1.104.2\n' "$version" >&2
  exit 1
fi
printf 'tailscale.com requirement: %s\n' "$version"

inventory=$(go run scripts/licenses.go)
printf '%s\n' "$inventory" | sed -n '/^Module: /p' | while IFS= read -r module; do
  if ! grep -Fqx -- "$module" NOTICE; then
    printf 'NOTICE is missing %s\n' "$module" >&2
    exit 1
  fi
done
printf 'NOTICE covers the Linux license inventory.\n'
