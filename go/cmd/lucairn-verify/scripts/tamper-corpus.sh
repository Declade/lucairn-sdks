#!/usr/bin/env bash
# Build lucairn-verify, generate the SYNTHETIC tamper corpus, run every case
# against the BUILT binary, print a table, and fail if a must-detect mutation
# exits 0 or a clean bundle does not exit 0.
#
#   go/cmd/lucairn-verify/scripts/tamper-corpus.sh [WORKDIR]
#
# PRD specs/2026-10/prd-2026-10-06-evidence-bundle-export.md (Slice 1).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
gomod="$(cd "$here/../../.." && pwd)"
work="${1:-$(mktemp -d)}"
mkdir -p "$work"
(cd "$gomod" && CGO_ENABLED=0 go build -trimpath -o "$work/lucairn-verify" ./cmd/lucairn-verify)
(cd "$gomod" && go run ./internal/tools/bundlecorpus -out "$work/corpus")
flags=()
while IFS= read -r line; do [ -n "$line" ] && flags+=("$line"); done < "$work/corpus/flags.txt"

bad=0
printf '%-36s %-14s %-5s %s\n' CASE EXPECT EXIT RESULT
while IFS=$'\t' read -r name expect what; do
  set +e
  out="$("$work/lucairn-verify" "${flags[@]}" "$work/corpus/cases/$name.zip" 2>&1)"
  code=$?
  set -e
  verdict="$(printf '%s\n' "$out" | sed -n 's/^RESULT: \([A-Z]*\).*/\1/p')"
  ok=yes
  case "$expect" in
    'VALID(0)'|'KNOWN-GAP(0)') [ "$code" -eq 0 ] || ok=no ;;
    'DETECTED(1|2)') [ "$code" -eq 1 ] || [ "$code" -eq 2 ] || ok=no ;;
  esac
  [ "$ok" = yes ] || bad=$((bad + 1))
  printf '%-36s %-14s %-5s %s%s\n' "$name" "$expect" "$code" "${verdict:-?}" "$([ "$ok" = yes ] || echo '  <-- UNEXPECTED')"
done < "$work/corpus/expected.tsv"
echo
if [ "$bad" -ne 0 ]; then
  echo "tamper corpus: $bad unexpected result(s)"
  exit 1
fi
echo "tamper corpus: all cases as expected"
