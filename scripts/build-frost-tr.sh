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
#   scripts/build-frost-tr.sh --docker --host   build lib/host/ for the native tests
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
        --host) MODE=host ;;
        *) echo "usage: $0 [--docker] [--test|--host]" >&2; exit 2 ;;
    esac
done

if [ "$DOCKER" = 1 ]; then
    inner=()
    [ "$MODE" = build ] || inner=(--"$MODE")
    mkdir -p "$ROOT/components/frost_tr/lib"
    # The source tree is mounted read-only and only lib/ is writable, so crate
    # build scripts running in the container cannot change the checkout. Runs
    # as root with the image's toolchain home (CI runners are not uid 1000),
    # then hands the archive back to the caller's uid.
    exec "${DOCKER_CMD:-docker}" run --rm -u 0 -e HOME=/home/esp \
        -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
        -v "$ROOT:/work:ro" \
        -v "$ROOT/components/frost_tr/lib:/work/components/frost_tr/lib" \
        -w /work "$FROST_TR_IMAGE" \
        bash -c 'FROST_TR_TARGET_DIR=/tmp/frost_tr-target bash scripts/build-frost-tr.sh "$@"; rc=$?
                 chown -R "$HOST_UID:$HOST_GID" components/frost_tr/lib 2>/dev/null
                 exit $rc' _ ${inner[@]+"${inner[@]}"}
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
export RUSTFLAGS="--remap-path-prefix=$CRATE=/frost_tr --remap-path-prefix=$TARGET_DIR=/target --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo ${RUSTFLAGS:-}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

if [ "$MODE" = test ]; then
    cargo +esp test --lib --locked --manifest-path "$CRATE/Cargo.toml" --target-dir "$TARGET_DIR"
    exit 0
fi

OUT="$ROOT/components/frost_tr/lib"
if [ "$MODE" = host ]; then
    # The native tests link the same crate built for the machine running them.
    TARGET="$(rustc +esp -vV | sed -n 's/^host: //p')"
    OUT="$OUT/host"
fi

cargo +esp build --release --locked \
    -Z build-std=core,alloc \
    --target "$TARGET" \
    --manifest-path "$CRATE/Cargo.toml" \
    --target-dir "$TARGET_DIR"

mkdir -p "$OUT"
cp "$TARGET_DIR/$TARGET/release/libfrost_tr.a" "$OUT/libfrost_tr.a"
sha256sum "$OUT/libfrost_tr.a"
