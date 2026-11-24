#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p target
scratch=$(mktemp -d "$(pwd -P)/target/check.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
export TMPDIR="$scratch"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$scratch/cargo}"
for project in distribution distribution-tests; do
  cargo metadata --locked --all-features --manifest-path "crates/$project/Cargo.toml" --format-version 1 > "$scratch/dependencies.json"
  jq -e --arg product "$(pwd -P)/crates/distribution/Cargo.toml" --arg tests "$(pwd -P)/crates/distribution-tests/Cargo.toml" '
    all(.packages[];
      if .source == null then .manifest_path == $product or .manifest_path == $tests
      elif (.source | startswith("registry+")) then true
      elif (.source | startswith("git+")) then
        (.source | test("github\\.com[:/]((chrono-harness/)|(ChronoAIProject/chrono-harness([./?#]|$)))"; "i") | not)
      else false end)' "$scratch/dependencies.json" >/dev/null || {
        echo "unexpected source in $project dependencies" >&2
        exit 1
      }
done
export CARGO_NET_OFFLINE=true
cargo fmt --check --manifest-path crates/distribution/Cargo.toml
cargo fmt --check --manifest-path crates/distribution-tests/Cargo.toml
product=crates/distribution/Cargo.toml
cargo build --locked --message-format=json-render-diagnostics --manifest-path "$product" > "$scratch/build.jsonl"
cargo test --locked --manifest-path crates/distribution-tests/Cargo.toml

coverage_failure() {
  echo "E_VERUS_COVERAGE: $*" >&2
  exit 1
}

prove() {
  local label=$1 root=$2
  local output="$scratch/$label.rlib" report="$scratch/$label.json"
  "${VERUS:-verus}" --crate-type=lib --no-cheating --no-external-by-default --num-threads 2 \
    --output-json --compile "--emit=link=$output,dep-info=$output.d" "$root" -o "$output" \
    -Zchecksum-hash-algorithm=sha256 > "$report" || { cat "$report" >&2; coverage_failure "$label: verifier failed"; }
}

admit_proof() {
  local label=$1
  shift
  local output="$scratch/$label.rlib" report="$scratch/$label.json"
  test -s "$report" && test -s "$output" && test -s "$output.d" ||
    coverage_failure "$label: missing required proof result"
  cat "$report"
  jq -e '.verus.version == "0.2026.04.24.f8e1704" and
    .verus.commit == "f8e17045c4ac17a02e566b8997070f2eecc255be" and
    (."verification-results" | .success == true and ."is-verifying-entire-crate" == true and
    ."encountered-error" == false and ."encountered-vir-error" == false and
    .errors == 0 and .verified > 0)' "$report" >/dev/null || coverage_failure "$label: unexpected verifier report"
  chrono-host-bootstrap check-compiler-sources proof "$output" "$@" || coverage_failure "$label: compiled sources differ from required inputs"
}

# Read the exact library selected by Cargo in the build of the tested executable.
metadata=$(jq -ers --arg manifest "$(pwd -P)/$product" '
  [.[] | select(.reason == "compiler-artifact" and .manifest_path == $manifest
                 and .target.kind == ["lib"]) | .filenames[] | select(endswith(".rmeta"))]
  | if length == 1 then .[0] else error("expected the product library") end
' "$scratch/build.jsonl") || coverage_failure "native library was not identified"
filename=${metadata##*/}
stem=${filename#lib}
stem=${metadata%/*}/${stem%.rmeta}
chrono-host-bootstrap check-compiler-sources native "$stem" src/asset_identity.rs src/lib.rs ||
  coverage_failure "distribution: native library differs from required sources"

asset=crates/distribution/src/asset_identity.rs
cases=crates/distribution-tests/tests/asset_identity.rs
launcher=crates/distribution-tests/tests/support/bootstrap.rs

prove asset-identity "$asset"
prove asset-identity-tests "$cases"
prove bootstrap "$launcher"

admit_proof asset-identity "$asset"
admit_proof asset-identity-tests "$cases" crates/distribution-tests/tests/../../distribution/src/asset_identity.rs
admit_proof bootstrap "$launcher"
