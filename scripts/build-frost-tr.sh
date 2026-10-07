#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 PrivKey LLC
# SPDX-License-Identifier: MIT
#
# Build components/frost_tr/lib/libfrost_tr.a for the ESP32-S3.
#
# Runs inside the pinned Espressif Rust image (FROST_TR_IMAGE). Called directly
# by Dockerfile.reproducible and CI; for a local build without that toolchain
# installed, run it through Docker:
#
#   scripts/build-frost-tr.sh --docker          build the device archive
#   scripts/build-frost-tr.sh --docker --test   run the crate's host tests
#
set -euo pipefail

FROST_TR_IMAGE="espressif/idf-rust:esp32s3_1.95.0.0@sha256:ee04f9c2bd68543b73ffcccb34c44c328fcadaa2ce3eaf99c17b06671372793a"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

MODE=build
DOCKER=0
for arg in "$@"; do
    case "$arg" in
        --docker) DOCKER=1 ;;
        --test) MODE=test ;;
        *) echo "usage: $0 [--docker] [--test]" >&2; exit 2 ;;
    esac
done

if [ "$DOCKER" = 1 ]; then
    inner=()
    [ "$MODE" = test ] && inner=(--test)
    # Runs as root with the image's toolchain home so it works whatever uid owns
    # the checkout (CI runners are not uid 1000), then hands the outputs back.
    exec docker run --rm -u 0 -e HOME=/home/esp \
        -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" -e FROST_TR_TARGET_DIR \
        -v "$ROOT:/work" -w /work "$FROST_TR_IMAGE" \
        bash -c 'bash scripts/build-frost-tr.sh "$@"; rc=$?
                 chown -R "$HOST_UID:$HOST_GID" components/frost_tr/lib components/frost_tr/rust/target 2>/dev/null
                 exit $rc' _ "${inner[@]}"
fi

if [ -f /home/esp/export-esp.sh ]; then
    # shellcheck disable=SC1091
    . /home/esp/export-esp.sh
fi

CRATE="$ROOT/components/frost_tr/rust"
TARGET=xtensa-esp32s3-none-elf
TARGET_DIR="${FROST_TR_TARGET_DIR:-$CRATE/target}"

# Panic and source locations embed paths; map them to fixed names so the
# archive does not depend on where the tree or the cargo home live.
export RUSTFLAGS="--remap-path-prefix=$CRATE=/frost_tr --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo ${RUSTFLAGS:-}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

if [ "$MODE" = test ]; then
    cargo +esp test --lib --locked --manifest-path "$CRATE/Cargo.toml" --target-dir "$TARGET_DIR"
    exit 0
fi

cargo +esp build --release --locked \
    -Z build-std=core,alloc \
    --target "$TARGET" \
    --manifest-path "$CRATE/Cargo.toml" \
    --target-dir "$TARGET_DIR"

mkdir -p "$ROOT/components/frost_tr/lib"
cp "$TARGET_DIR/$TARGET/release/libfrost_tr.a" "$ROOT/components/frost_tr/lib/libfrost_tr.a"
sha256sum "$ROOT/components/frost_tr/lib/libfrost_tr.a"
