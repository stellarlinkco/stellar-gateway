#!/usr/bin/env bash
set -euo pipefail

max_bytes="${MAX_FILE_BYTES:-524288}"
failed=0

echo "checking tracked file sizes <= ${max_bytes} bytes"
while IFS= read -r file; do
  [[ -f "$file" ]] || continue
  size="$(wc -c < "$file" | tr -d ' ')"
  if [[ "$size" -gt "$max_bytes" ]]; then
    echo "large file: $file (${size} bytes > ${max_bytes})" >&2
    failed=1
  fi
done < <(git ls-files)

echo "checking debt markers include an issue reference"
debt_pattern="$(printf '%s|%s' 'TODO' 'FIXME')"
if git grep -nE "$debt_pattern" -- ':!scripts/readiness-check.sh' >/tmp/stellar-gateway-debt.txt; then
  while IFS= read -r line; do
    if [[ ! "$line" =~ (TODO|FIXME)\((#[0-9]+|[A-Z][A-Z0-9]+-[0-9]+)\) ]]; then
      echo "untracked debt marker: $line" >&2
      failed=1
    fi
  done </tmp/stellar-gateway-debt.txt
fi
rm -f /tmp/stellar-gateway-debt.txt

echo "checking forbidden tracked paths"
for forbidden in \
  ".env" \
  ".idea/" \
  ".vscode/" \
  "id_rsa" \
  "id_ed25519"; do
  if git ls-files | grep -qE "(^|/)${forbidden//./\\.}"; then
    echo "forbidden tracked path pattern: $forbidden" >&2
    failed=1
  fi
done

if [[ "$failed" -ne 0 ]]; then
  echo "readiness checks failed" >&2
  exit 1
fi

echo "readiness checks passed"
