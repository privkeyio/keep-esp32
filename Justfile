# SPDX-FileCopyrightText: © 2026 PrivKey LLC
# SPDX-License-Identifier: AGPL-3.0-or-later

set shell := ["bash", "-uc"]

docker_cmd := env("DOCKER_CMD", "docker")
_valid_docker := if docker_cmd == "docker" { "ok" } else { if docker_cmd == "podman" { "ok" } else { error("DOCKER_CMD must be 'docker' or 'podman'") } }
port_raw := env("PORT", "/dev/ttyACM0")
port := if port_raw =~ '^/dev/tty[A-Za-z0-9]+$' { port_raw } else { error("PORT must match /dev/tty* pattern") }

default:
    @just --list

build:
    idf.py build

flash:
    idf.py -p {{port}} flash

monitor:
    idf.py -p {{port}} monitor

flash-monitor:
    idf.py -p {{port}} flash monitor

test:
    #!/usr/bin/env bash
    set -euo pipefail
    cd test/native
    mkdir -p build && cd build
    cmake ..
    make -j$(nproc)
    for t in test_frost test_session test_storage test_secure_element test_secresult \
             test_integration test_self_test test_hw_entropy test_anti_glitch test_psbt_fraud \
             test_frost_signer_core test_protocol test_integration_full test_psbt_fraud_integration; do
        [ ! -f "./$t" ] || ./$t
    done

fuzz target="" duration="30":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{target}}" ] && ! [[ "{{target}}" =~ ^[a-zA-Z0-9_]+$ ]]; then
        echo "Error: target must be alphanumeric (with underscores)" >&2
        exit 1
    fi
    if ! [[ "{{duration}}" =~ ^[0-9]+$ ]]; then
        echo "Error: duration must be a positive integer" >&2
        exit 1
    fi
    cd fuzz
    mkdir -p build && cd build
    CC=clang cmake ..
    make -j$(nproc)
    if [ -n "{{target}}" ]; then
        ./fuzz_{{target}} ../corpus/{{target}} -max_total_time={{duration}}
    else
        for fuzzer in fuzz_hex fuzz_protocol fuzz_dkg fuzz_policy fuzz_nostr; do
            if [ -f "./$fuzzer" ]; then
                corpus="${fuzzer#fuzz_}"
                echo "Running $fuzzer..."
                timeout {{duration}} ./$fuzzer ../corpus/$corpus -max_total_time={{duration}} || [ $? -eq 124 ]
            fi
        done
    fi

docs:
    doxygen Doxyfile

clean:
    rm -rf build test/native/build fuzz/build docs/html output

docker-build:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p output
    {{docker_cmd}} build -f Dockerfile.reproducible -o output .
    sha256sum output/keep.bin
    sha256sum output/keep-merged.bin

verify-sha expected="":
    #!/usr/bin/env bash
    set -euo pipefail
    [ -f output/keep.bin ] || { echo "Run 'just docker-build' first"; exit 1; }
    BUILT_HASH=$(sha256sum output/keep.bin | cut -d' ' -f1)
    echo "Build hash: $BUILT_HASH"
    if [ -n "{{expected}}" ]; then
        if ! [[ "{{expected}}" =~ ^[a-f0-9]{64}$ ]]; then
            echo "Error: expected must be a valid SHA256 hash (64 hex chars)" >&2
            exit 1
        fi
        [ "$BUILT_HASH" = "{{expected}}" ] || { echo "Mismatch: expected {{expected}}"; exit 1; }
        echo "Match"
    fi

verify-release version:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! [[ "{{version}}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: version must be in semver format (vX.Y.Z)" >&2
        exit 1
    fi
    [ -f output/keep.bin ] || { echo "Run 'just docker-build' first"; exit 1; }
    BUILT_HASH=$(sha256sum output/keep.bin | cut -d' ' -f1)
    TMP=$(mktemp -d)
    trap "rm -rf $TMP" EXIT
    curl -fSL "https://github.com/privkeyio/keep-esp32/releases/download/{{version}}/keep-esp32-firmware-{{version}}.tar.gz" | tar -xz -C "$TMP"
    RELEASE_HASH=$(sha256sum "$TMP/keep.bin" | cut -d' ' -f1)
    echo "Built:   $BUILT_HASH"
    echo "Release: $RELEASE_HASH"
    [ "$BUILT_HASH" = "$RELEASE_HASH" ] || { echo "Mismatch"; exit 1; }
    echo "Match"

verify-device:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -f output/keep.bin ] || { echo "Run 'just docker-build' first"; exit 1; }
    SIZE=$(wc -c < output/keep.bin | tr -d '[:space:]')
    TMP=$(mktemp)
    trap "rm -f $TMP" EXIT
    esptool.py --port {{port}} read_flash 0x10000 "$SIZE" "$TMP"
    DEVICE_HASH=$(sha256sum "$TMP" | cut -d' ' -f1)
    BUILT_HASH=$(sha256sum output/keep.bin | cut -d' ' -f1)
    echo "Device: $DEVICE_HASH"
    echo "Built:  $BUILT_HASH"
    [ "$DEVICE_HASH" = "$BUILT_HASH" ] || { echo "Mismatch"; exit 1; }
    echo "Match"

ci: test docs
