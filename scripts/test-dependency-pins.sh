#!/usr/bin/env bash
# Self-test for check-dependency-pins.sh.
#
# The guard's whole value is failing on diffs that otherwise look clean, so each
# case below is a diff that passed every other check in CI. The first is the
# shape dependabot produces for an ESP-IDF bump: it can only edit the Dockerfile
# FROM line, so the workflows stay behind and the reproducible build stops
# matching the released artifact, with nothing red anywhere.
#
# Cases run against a throwaway copy of the tree, so the real working tree is
# never modified. Freshness needs the network and is not what is under test, so
# the copies run with an unreachable proxy: the guard's documented no-network
# path skips freshness and still enforces agreement, which keeps this fast and
# usable offline.
set -uo pipefail

cd "$(dirname "$0")/.." || { echo "FAIL: cannot cd to the repo root"; exit 1; }
GUARD=scripts/check-dependency-pins.sh
[ -x "$GUARD" ] || { echo "FAIL: $GUARD not found or not executable"; exit 1; }

TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT
fails=0

# Offline: forces the guard's no-network branch so only agreement is exercised.
export https_proxy=http://127.0.0.1:1 http_proxy=http://127.0.0.1:1
export GIT_TERMINAL_PROMPT=0

# run_case <name> <pass|fail> <expected-substring-when-failing> <mutator...>
run_case() {
    local name="$1" expect="$2" want="$3"; shift 3
    local work="$TMPD/$name"
    rm -rf "$work"; mkdir -p "$work/scripts" "$work/.github/workflows"
    cp Dockerfile.reproducible "$work/"
    cp .github/workflows/ci.yml .github/workflows/release.yml "$work/.github/workflows/"
    cp "$GUARD" "$work/scripts/"
    ( cd "$work" && "$@" )

    local rc=0 out
    out=$( cd "$work" && ./scripts/check-dependency-pins.sh 2>&1 ) || rc=$?

    if [ "$expect" = fail ]; then
        if [ "$rc" -eq 0 ]; then
            echo "  BYPASS: $name (guard passed a diff it must reject)"; fails=$((fails+1))
        elif ! printf '%s' "$out" | grep -qF "$want"; then
            echo "  WRONG REASON: $name (failed, but not for '$want')"
            printf '%s\n' "$out" | grep -i fail | head -2 | sed 's/^/      /'
            fails=$((fails+1))
        else
            echo "  ok: $name"
        fi
    else
        if [ "$rc" -ne 0 ]; then
            echo "  FALSE POSITIVE: $name"
            printf '%s\n' "$out" | grep -i fail | head -3 | sed 's/^/      /'
            fails=$((fails+1))
        else
            echo "  ok: $name"
        fi
    fi
}

echo "== accepts the tree as committed =="
run_case baseline pass "" true

echo "== rejects a partial ESP-IDF bump =="

# Exactly what dependabot opens: Dockerfile moves, workflows do not.
run_case idf-dockerfile-only fail "ESP-IDF version disagrees" \
    sed -i -E 's|(espressif/idf:)v[0-9]+\.[0-9]+(\.[0-9]+)?|\1v9.9.9|' Dockerfile.reproducible

# The mirror image: someone edits the workflows and forgets the image.
run_case idf-workflow-only fail "ESP-IDF version disagrees" \
    sed -i -E 's|(esp_idf_version:[[:space:]]*)v?[0-9]+\.[0-9]+(\.[0-9]+)?|\1v9.9.9|' .github/workflows/ci.yml

# A tag with no digest is not a pin: tags can be repushed.
run_case idf-tag-not-digest fail "no digest-pinned espressif/idf" \
    sed -i -E 's|(FROM[[:space:]]+espressif/idf:v[0-9]+\.[0-9]+(\.[0-9]+)?)@sha256:[a-f0-9]{64}|\1|' Dockerfile.reproducible

echo "== the pre-existing dependency rule still bites =="

# Positive control for rule 1. If this stops failing, the scanner has gone
# quiet and every case above would pass while detecting nothing.
run_case dep-commit-disagree fail "disagrees between" \
    sed -i -E '0,/ref: [a-f0-9]{40}/s//ref: 0000000000000000000000000000000000000000/' .github/workflows/ci.yml

echo
if [ "$fails" -ne 0 ]; then
    echo "FAIL: $fails case(s) did not behave as required"
    exit 1
fi
echo "OK: check-dependency-pins.sh rejects every known partial bump and accepts the committed tree"
