#!/usr/bin/env bash
# .ci/verify.sh for cnbx — ports ALL Linux verification gates from
# .github/workflows/ci.yml (resolve selftest, check, dependency-policy
# first-party, coverage) in CI order, environment, and flags.
set -euo pipefail
exec 2>&1
CNBX_LAST_GATE="init"
trap 'rc=$?; echo "CNBX-DIAG last_gate=$CNBX_LAST_GATE exit=$rc" >&2; exit $rc' EXIT
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"

# A C compiler covers the lock-evidenced blake3 cc edge (direct cnbx dep);
# the Ubuntu image supplies gcc, the job supplies pinned clang (cc wrapper).
command -v cc >/dev/null || { echo 'missing cc for lock-evidenced cc edges' >&2; exit 2; }
clang --version
# Wasm target on stable is guaranteed by run-cached.sh (helper readiness +
# exclusive provisioning); no toolchain mutation here under the shared lock.

# --- resolve pure selftest (committed graph only; update refresh excluded) ---
CNBX_LAST_GATE="resolve-first-party"
python3 .github/check-first-party.py
CNBX_LAST_GATE="resolve-metadata"
cargo metadata --locked --format-version 1 > dependency-metadata.json

# --- dependency-policy first-party (deny advisories separate always-run) ---
CNBX_LAST_GATE="dependency-policy-first-party"
python3 .github/check-first-party.py

# --- check job in exact CI order ---
# Formatting is continue-on-error in CI with the failure enforced at the end,
# so every gate still executes when formatting drifts.
CNBX_LAST_GATE="fmt"
cargo fmt --all
formatting_outcome=0
CNBX_LAST_GATE="fmt-capture"
git diff --exit-code -- src tests > formatting.patch || formatting_outcome=$?
CNBX_LAST_GATE="clippy"
cargo clippy --locked --all-targets -- -D warnings
CNBX_LAST_GATE="native-tests"
cargo test --locked --no-fail-fast
# Install the lock-matched prebuilt wasm runner job-locally (adapts CI's
# GITHUB_PATH step to an explicit PATH export for Crow).
CNBX_LAST_GATE="wasm-runner-version"
version=$(jq -r '.packages[] | select(.name == "wasm-bindgen") | .version' dependency-metadata.json)
test -n "$version" || { echo 'could not resolve wasm-bindgen version from dependency-metadata.json' >&2; exit 2; }
archive="wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz"
base="https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${version}"
mkdir -p "$RUNNER_TEMP/wasm-runner"
cd "$RUNNER_TEMP/wasm-runner"
CNBX_LAST_GATE="wasm-runner-fetch"
curl --fail --location --retry 3 --remote-name "$base/$archive"
curl --fail --location --retry 3 --remote-name "$base/$archive.sha256sum"
checksum=$(cut -d ' ' -f1 "$archive.sha256sum")
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check
tar -xzf "$archive" --strip-components=1
export PATH="$PWD:$PATH"
cd - > /dev/null
command -v wasm-bindgen-test-runner >/dev/null || { echo 'wasm test runner not on PATH' >&2; exit 2; }
wasm-bindgen --version | grep -q "$version" || { echo 'wasm runner version mismatch' >&2; exit 2; }
# CI consumes the runner-image chromedriver; the job runtime supplies the
# paired pinned nix chromium+chromedriver.
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="wasm-bindgen-test-runner"
export WASM_BINDGEN_USE_BROWSER="1"
export WASM_BINDGEN_TEST_TIMEOUT="60"
export CHROMEDRIVER="$(command -v chromedriver)"
test -x "$CHROMEDRIVER" || { echo "missing chromedriver at $CHROMEDRIVER" >&2; exit 2; }
# Stock runners discover a google-chrome binary; link the pinned chromium
# under that name job-locally so discovery is deterministic.
CHROME_BIN="${CHROME_BIN:-$(command -v chromium)}"
test -x "$CHROME_BIN" || { echo "missing chromium at $CHROME_BIN" >&2; exit 2; }
mkdir -p "$RUNNER_TEMP/bin"
ln -sf "$CHROME_BIN" "$RUNNER_TEMP/bin/google-chrome"
export PATH="$RUNNER_TEMP/bin:$PATH"
CNBX_LAST_GATE="wasm-tests"
cargo test --locked --target wasm32-unknown-unknown --test inbox --test waves --test contacts --test authority --test release
# CI's end-of-job formatting gate (runs even when earlier steps fail the
# patch capture above only as advisory): enforce the captured outcome now.
CNBX_LAST_GATE="formatting-gate"
if [ "$formatting_outcome" != "0" ]; then
  echo 'formatting gate failed (see formatting.patch)' >&2
  exit 1
fi

# --- coverage job (nightly only) ---
# Select nightly exactly as CI's nightly job does; every bare cargo/rustc
# below resolves nightly via RUSTC/CARGO/PATH/RUSTUP_TOOLCHAIN.
CNBX_LAST_GATE="nightly-select"
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
CNBX_LAST_GATE="native-coverage"
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --branch --no-cfg-coverage --no-cfg-coverage-nightly --json --output-path coverage.json --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --lcov --output-path coverage.lcov
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --text --output-path coverage.txt
)
CNBX_LAST_GATE="coverage-check"
python3 .github/test-source-coverage.py
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt
