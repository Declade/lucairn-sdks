#!/usr/bin/env bash
# Re-sync the vendored T-935 S3 verifier parity corpus from
# Declade/dual-sandbox-architecture (tools/parity-corpus) at a pinned commit.
#
#   testdata/parity-corpus/sync.sh <path-to-dual-sandbox-architecture-clone> <commit>
#
# Copies corpus/v1 (manifest.json, keys.json, cases/*.json) byte for byte,
# extracts the ordered check table of the corpus README (between its
# recipe-table markers) into recipe-table.md, and records the source commit,
# the sha256 of the upstream README and of every vendored top-level file in
# SOURCE.json. The full README stays in the source repository (it carries
# internal build and replay notes); this repository carries only the table
# the three verifiers are tested against. The parity tests of all three SDKs
# (ts/src/verify-chain/parityCorpus.test.ts, python/tests/test_parity_corpus.py,
# go/parity_corpus_test.go) fail when the vendored copy drifts from SOURCE.json
# or a case file drifts from its manifest sha256 — re-run this script, never
# hand-edit the vendored files.
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 <dual-sandbox-architecture clone> <commit>" >&2
  exit 2
fi
src_repo=$1
commit=$2
here=$(cd "$(dirname "$0")" && pwd)
full_sha=$(git -C "$src_repo" rev-parse --verify "$commit^{commit}")

rm -rf "$here/v1"
mkdir -p "$here/v1"
git -C "$src_repo" archive "$full_sha" tools/parity-corpus/corpus/v1 | tar -x -C "$here/v1" --strip-components=4
readme=$(mktemp)
trap 'rm -f "$readme"' EXIT
git -C "$src_repo" show "$full_sha:tools/parity-corpus/README.md" > "$readme"
{
  echo "<!-- Extracted by sync.sh from Declade/dual-sandbox-architecture tools/parity-corpus/README.md @ $full_sha — do not edit. -->"
  sed -n '/<!-- recipe-table:begin -->/,/<!-- recipe-table:end -->/p' "$readme"
} > "$here/recipe-table.md"
grep -q 'recipe-table:end' "$here/recipe-table.md" || { echo "recipe table markers not found" >&2; exit 1; }

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
format=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["format"])' "$here/v1/manifest.json")
cat > "$here/SOURCE.json" <<JSON
{
  "source_repo": "Declade/dual-sandbox-architecture",
  "source_path": "tools/parity-corpus",
  "source_commit": "$full_sha",
  "format": "$format",
  "manifest_sha256": "$(sha "$here/v1/manifest.json")",
  "keys_sha256": "$(sha "$here/v1/keys.json")",
  "upstream_readme_sha256": "$(sha "$readme")",
  "recipe_table_sha256": "$(sha "$here/recipe-table.md")"
}
JSON
echo "synced $(ls "$here/v1/cases" | wc -l | tr -d ' ') cases from $full_sha"
cat "$here/SOURCE.json"
