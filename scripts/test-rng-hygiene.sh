#!/usr/bin/env bash
# Self-test for check-rng-hygiene.sh.
#
# This guard holds the invariant behind the v0.2.1 entropy fix: the SAR ADC
# source stays enabled for the life of the device, raw HWRNG draws stay in one
# file, and nothing takes the ADC back. A scanner that quietly stops scanning
# reports a clean tree exactly like a clean tree does, so the rules are asserted
# rather than trusted.
#
# Each reject case requires the guard to NAME the probe file. Without that, a
# guard aborting for an unrelated reason would be credited as a detection and
# every case below would pass while detecting nothing.
#
# Probes are staged into a throwaway GIT_INDEX_FILE, so the real index is never
# touched. The file itself must exist on disk while the guard runs, because the
# scanner reads bytes; it is removed on every path including the EXIT trap.
set -uo pipefail

cd "$(dirname "$0")/.." || { echo "FAIL: cannot cd to the repo root"; exit 1; }
GUARD=scripts/check-rng-hygiene.sh
[ -x "$GUARD" ] || { echo "FAIL: $GUARD not found or not executable"; exit 1; }

TMPD=$(mktemp -d)
PROBE=""
cleanup() { rm -rf "$TMPD"; [ -n "$PROBE" ] && rm -f "$PROBE"; }
trap cleanup EXIT

fails=0

# run_probe <path> <content> <pass|fail> <description>
run_probe() {
    local name="$1" content="$2" expect="$3" desc="$4"

    if [ -e "$name" ]; then
        echo "  HARNESS BROKEN: $name exists; refusing to overwrite a real file"
        fails=$((fails + 1)); return
    fi
    PROBE="$name"
    printf '%s' "$content" > "$name"

    rm -f "$TMPD/index"
    GIT_INDEX_FILE="$TMPD/index" git read-tree HEAD 2>/dev/null
    GIT_INDEX_FILE="$TMPD/index" git add -f "$name" 2>/dev/null

    local staged
    staged=$(GIT_INDEX_FILE="$TMPD/index" git ls-files | wc -l)
    if [ "$staged" -lt 10 ]; then
        echo "  HARNESS BROKEN: only $staged file(s) staged; the guard would scan almost nothing"
        fails=$((fails + 1)); rm -f "$name"; PROBE=""; return
    fi

    # Both that the tree is populated AND that this probe is in it. The git

    # errors above are discarded, so a failed `git add` would otherwise leave

    # the guard scanning a probe-free tree and the case judged on a file it

    # never saw.

    if ! GIT_INDEX_FILE="$TMPD/index" git ls-files --error-unmatch "$name" >/dev/null 2>&1; then

        echo "  HARNESS BROKEN: $name was not staged; the guard would never see it"

        fails=$((fails + 1)); rm -f "$name"; PROBE=""; return

    fi


    local rc=0 out
    out=$(GIT_INDEX_FILE="$TMPD/index" "$GUARD" 2>&1) || rc=$?
    rm -f "$name"; PROBE=""

    if [ "$expect" = fail ]; then
        if [ "$rc" -eq 0 ]; then
            echo "  BYPASS: $desc"; fails=$((fails + 1))
        elif ! printf '%s' "$out" | grep -qF "$name"; then
            echo "  WRONG REASON: $desc (guard failed without naming $name)"; fails=$((fails + 1))
        else
            echo "  ok: $desc"
        fi
    else
        if [ "$rc" -ne 0 ]; then
            echo "  FALSE POSITIVE: $desc"
            printf '%s\n' "$out" | sed 's/^/      /' | head -4
            fails=$((fails + 1))
        else
            echo "  ok: $desc"
        fi
    fi
}

echo "== rejects what it must reject =="

run_probe main/probe_ctl.c 'void f(void){ esp_wifi_start(); }
' fail "plain SAR-ADC contender (positive control: if this passes, nothing below means anything)"

# The bypass this file was written for.
run_probe main/probe_splice.c 'void f(void){ adc_oneshot\
_new_unit(); }
' fail "identifier split by a line continuation"

run_probe main/probe_splice3.c 'void f(void){ esp_\
wifi_\
start(); }
' fail "identifier split across three lines"

run_probe main/probe_disable.c 'void f(void){ bootloader_random_disable(); }
' fail "bootloader_random_disable, which returns the RNG to pseudo-random"

run_probe main/probe_rawdraw.c 'void f(void){ uint32_t x = esp_random(); }
' fail "raw HWRNG draw outside main/hw_entropy.c"

run_probe main/probe_libc.c 'void f(void){ int x = rand(); }
' fail "libc PRNG"

run_probe main/probe_i2s.c 'void f(void){ i2s_new_channel(0, 0, 0); }
' fail "I2S, which contends for the SAR ADC"

echo "== accepts what it must accept =="

run_probe main/probe_clean.c 'void f(void){ int x = 1; (void)x; }
' pass "ordinary code"

run_probe main/probe_comment.c '/* esp_wifi_start() is named here in prose only */
void f(void){ int x = 1; (void)x; }
' pass "a banned token inside a comment is not code"

run_probe main/probe_dead.c '#if 0
void f(void){ esp_wifi_start(); }
#endif
' pass "a banned token inside #if 0 is not live code"

echo
if [ "$fails" -ne 0 ]; then
    echo "FAIL: $fails case(s) did not behave as required"
    exit 1
fi
echo "OK: check-rng-hygiene.sh rejects every known bypass and accepts sanctioned use"
