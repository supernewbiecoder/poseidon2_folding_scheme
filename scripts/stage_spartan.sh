#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

function get_time_ms() {
  date +%s%3N
}

if [ -z "$1" ]; then
  echo "Usage: $0 <shard_count> [shard_dir] [challenge_count]" >&2
  exit 1
fi

SHARD_COUNT="$1"
SHARD_DIR="${2:-$ROOT_DIR}"
CHALLENGE_COUNT="${3:-4}"

energy_joules() {
  awk -v watts="$1" -v ms="$2" 'BEGIN { printf "%.3f", (watts * ms) / 1000.0 }'
}

avg_watts_build="${ENGRAM_WATTS_BUILD:-60}"
avg_watts_runtime="${ENGRAM_WATTS_SPARTAN_RUNTIME:-85}"

echo "[SPARTAN] BUILD RUST PROVER..."
START_BUILD=$(get_time_ms)
cd "$ROOT_DIR/prover-rust"
cargo build --release > /dev/null
END_BUILD=$(get_time_ms)
BUILD_MS=$((END_BUILD - START_BUILD))
BUILD_J=$(energy_joules "$avg_watts_build" "$BUILD_MS")

echo "[SPARTAN] RUN NOVA FOLDING + SPARTAN COMPRESSION..."
START_RUNTIME=$(get_time_ms)
cd "$ROOT_DIR"
ENGRAM_ROOT_DIR="$ROOT_DIR" ENGRAM_SHARD_COUNT="$SHARD_COUNT" ENGRAM_SHARD_DIR="$SHARD_DIR" ENGRAM_CHALLENGE_COUNT="$CHALLENGE_COUNT" ./prover-rust/target/release/engram-prover
END_RUNTIME=$(get_time_ms)
RUNTIME_MS=$((END_RUNTIME - START_RUNTIME))
RUNTIME_J=$(energy_joules "$avg_watts_runtime" "$RUNTIME_MS")

echo "SPARTAN_BUILD_MS=$BUILD_MS"
echo "SPARTAN_BUILD_JOULES=$BUILD_J"
echo "SPARTAN_RUNTIME_MS=$RUNTIME_MS"
echo "SPARTAN_RUNTIME_JOULES=$RUNTIME_J"
