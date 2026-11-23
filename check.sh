#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p target
scratch=$(mktemp -d "$(pwd -P)/target/check.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
export TMPDIR="$scratch"
export CARGO_TARGET_DIR="$scratch/cargo"
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
cargo build --locked --manifest-path crates/distribution/Cargo.toml
cargo test --locked --manifest-path crates/distribution-tests/Cargo.toml

prove() {
  local label=$1 root=$2
  local output="$scratch/$label.rlib"
  "${VERUS:-verus}" --crate-type=lib --no-cheating --no-external-by-default --num-threads 2 \
    --output-json --compile "--emit=link=$output,dep-info=$output.d" "$root" -o "$output" \
    -Zchecksum-hash-algorithm=sha256 > "$scratch/proof.json" || { cat "$scratch/proof.json" >&2; return 1; }
  cat "$scratch/proof.json"
  jq -e '.verus.version == "0.2026.04.24.f8e1704" and
    .verus.commit == "f8e17045c4ac17a02e566b8997070f2eecc255be" and
    (."verification-results" | .success == true and ."is-verifying-entire-crate" == true and
    ."encountered-error" == false and ."encountered-vir-error" == false and
    .errors == 0 and .verified > 0)' "$scratch/proof.json" >/dev/null
  test -s "$output" && test -s "$output.d"
}

prove bootstrap crates/distribution-tests/tests/support/bootstrap.rs
