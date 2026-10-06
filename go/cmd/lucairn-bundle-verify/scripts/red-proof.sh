#!/usr/bin/env bash
# RED-PROOF for the tamper corpus: run every case on the CURRENT binary and on
# an independent reference binary built from an OLDER head (e.g. the round-1
# head 0811712b), side by side.
#
#   go/cmd/lucairn-bundle-verify/scripts/red-proof.sh OLD_BINARY [WORKDIR]
#
# The old binary reads the round-1 manifest shape (completeness.state) and
# has no --require-anchors flag, so its corpus is generated with
# -legacy-manifest and run without that flag; every mutation is otherwise the
# same. A case that is new in this round should show OLD exit 0 (the defect)
# and NEW exit 1 or 2 (the fix). Synthetic data only; the fake Rekor listens
# on 127.0.0.1.
set -euo pipefail
old="$1"
here="$(cd "$(dirname "$0")" && pwd)"
gomod="$(cd "$here/../../.." && pwd)"
work="${2:-$(mktemp -d)}"
mkdir -p "$work"
(cd "$gomod" && CGO_ENABLED=0 go build -trimpath -o "$work/lucairn-bundle-verify" ./cmd/lucairn-bundle-verify)
(cd "$gomod" && go build -o "$work/bundlecorpus" ./internal/tools/bundlecorpus)
"$work/bundlecorpus" -out "$work/new"
"$work/bundlecorpus" -out "$work/legacy" -legacy-manifest

pids=()
trap 'for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null || true; done' EXIT
start() { # dir → prints url
  rm -f "$1/rekor-url"
  "$work/bundlecorpus" -serve "$1" -port-file "$1/rekor-url" &
  pids+=("$!")
  for _ in $(seq 1 50); do [ -s "$1/rekor-url" ] && break; sleep 0.1; done
}
start "$work/new"; start "$work/legacy"
url_new="$(tr -d '\n' < "$work/new/rekor-url")"
url_old="$(tr -d '\n' < "$work/legacy/rekor-url")"

run() { # bin dir url drop-require-anchors name extra → exit code
  local bin="$1" dir="$2" url="$3" drop="$4" name="$5" extra="$6" f=() e=() skipnext=no allow=no
  case " $extra " in *" --allow-unanchored "*) allow=yes ;; esac
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if [ "$skipnext" = yes ]; then skipnext=no; continue; fi
    [ "$drop" = yes ] && [ "$line" = "--require-anchors" ] && continue
    [ "$allow" = yes ] && [ "$line" = "--require-anchors" ] && continue
    # Flags newer than the reference binary (S2a) are dropped with their value.
    if [ "$drop" = yes ] && [ "$line" = "--require-binding-after" ]; then skipnext=yes; continue; fi
    f+=("$line")
  done < "$dir/flags.txt"
  for a in $extra; do e+=("${a//@REKOR_URL@/$url}"); done
  set +e
  "$bin" "${f[@]}" ${e[@]+"${e[@]}"} "$dir/cases/$name.zip" >/dev/null 2>&1
  local c=$?
  set -e
  echo "$c"
}
printf '%-40s %-14s %-4s %-4s\n' CASE EXPECT NEW OLD
while IFS=$'\t' read -r name expect what extra; do
  n="$(run "$work/lucairn-bundle-verify" "$work/new" "$url_new" no "$name" "${extra:-}")"
  o="$(run "$old" "$work/legacy" "$url_old" yes "$name" "${extra:-}")"
  printf '%-40s %-14s %-4s %-4s\n' "$name" "$expect" "$n" "$o"
done < "$work/new/expected.tsv"
