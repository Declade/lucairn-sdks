#!/usr/bin/env bash
# Build lucairn-bundle-verify, generate the SYNTHETIC tamper corpus, run every case
# against the BUILT binary, print a table, and fail if a must-detect mutation
# exits 0 or a clean bundle does not exit 0.
#
#   go/cmd/lucairn-bundle-verify/scripts/tamper-corpus.sh [WORKDIR]
#
# --online cases run against a local fake Rekor (bundlecorpus -serve on
# 127.0.0.1, synthetic entries only); nothing leaves the machine.
#
# Expectations: VALID(0) and KNOWN-GAP(0) must exit 0; DETECTED(1|2) must
# exit 1 or 2; TAMPERED(1) must exit exactly 1; INCOMPLETE(2) must exit
# exactly 2 (something is missing, and nothing may be called tampering).
#
# PRD specs/2026-10/prd-2026-10-06-evidence-bundle-export.md (Slices 1, 2a, 2b).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
gomod="$(cd "$here/../../.." && pwd)"
work="${1:-$(mktemp -d)}"
mkdir -p "$work"
(cd "$gomod" && CGO_ENABLED=0 go build -trimpath -o "$work/lucairn-bundle-verify" ./cmd/lucairn-bundle-verify)
(cd "$gomod" && go build -o "$work/bundlecorpus" ./internal/tools/bundlecorpus)
"$work/bundlecorpus" -out "$work/corpus"
flags=()
while IFS= read -r line; do [ -n "$line" ] && flags+=("$line"); done < "$work/corpus/flags.txt"

rm -f "$work/rekor-url"
"$work/bundlecorpus" -serve "$work/corpus" -port-file "$work/rekor-url" &
srv=$!
trap 'kill "$srv" 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do [ -s "$work/rekor-url" ] && break; sleep 0.1; done
[ -s "$work/rekor-url" ] || { echo "fake Rekor did not start"; exit 1; }
rekor_url="$(tr -d '\n' < "$work/rekor-url")"

bad=0
printf '%-40s %-14s %-5s %s\n' CASE EXPECT EXIT RESULT
while IFS=$'\t' read -r name expect what extra; do
  extra_args=()
  allow=no
  for a in ${extra:-}; do
    extra_args+=("${a//@REKOR_URL@/$rekor_url}")
    [ "$a" = "--allow-unanchored" ] && allow=yes
  done
  # A case run with --allow-unanchored drops the corpus's --require-anchors
  # (the two exclude each other) — the same rule as bundletest.CaseArgs.
  base=()
  for f in "${flags[@]}"; do
    [ "$allow" = yes ] && [ "$f" = "--require-anchors" ] && continue
    base+=("$f")
  done
  set +e
  out="$("$work/lucairn-bundle-verify" "${base[@]}" ${extra_args[@]+"${extra_args[@]}"} "$work/corpus/cases/$name.zip" 2>&1)"
  code=$?
  set -e
  verdict="$(printf '%s\n' "$out" | sed -n 's/^RESULT: \([A-Z]*\).*/\1/p')"
  ok=yes
  case "$expect" in
    'VALID(0)'|'KNOWN-GAP(0)') [ "$code" -eq 0 ] || ok=no ;;
    'DETECTED(1|2)') [ "$code" -eq 1 ] || [ "$code" -eq 2 ] || ok=no ;;
    'TAMPERED(1)') [ "$code" -eq 1 ] || ok=no ;;
    'INCOMPLETE(2)') [ "$code" -eq 2 ] || ok=no ;;
    *) ok=no ;;
  esac
  [ "$ok" = yes ] || bad=$((bad + 1))
  printf '%-40s %-14s %-5s %s%s\n' "$name" "$expect" "$code" "${verdict:-?}" "$([ "$ok" = yes ] || echo '  <-- UNEXPECTED')"
done < "$work/corpus/expected.tsv"
echo
if [ "$bad" -ne 0 ]; then
  echo "tamper corpus: $bad unexpected result(s)"
  exit 1
fi
echo "tamper corpus: all cases as expected"
