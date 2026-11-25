#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ $# -eq 0 ]]; then
  /bin/sh .chrono-harness/ci/install.sh
  export PATH="$PWD/.chrono-harness/bin:$PATH"
  export CHRONO_CHECK_SOURCE=${CHRONO_CHECK_SOURCE:-local}
  exec .chrono-harness/bin/chrono-harness check
fi
if [[ $# -ne 1 || $1 != --native ]]; then
  echo 'usage: ./check.sh [--native]' >&2
  exit 2
fi

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
cargo test --locked --manifest-path crates/distribution-tests/Cargo.toml --color never -- --format pretty | tee "$scratch/tests.log"
for consumer in \
  adoption_selects_exact_destinations_and_preserves_the_prior_lock_on_first_error \
  adoption_reports_the_first_invalid_published_identity_before_writing_host_files \
  launcher_options_preserve_modes_and_first_failure \
  bootstrap_rejects_corrupt_installer_and_propagates_real_exit \
  pack_and_assemble_bind_real_source_and_declared_members; do
  grep -Fxq "test $consumer ... ok" "$scratch/tests.log" || {
    echo "E_VERUS_COVERAGE: required distribution consumer did not pass: $consumer" >&2
    exit 1
  }
done

coverage_failure() {
  echo "E_VERUS_COVERAGE: $*" >&2
  exit 1
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
