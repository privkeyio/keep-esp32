#!/usr/bin/env bash
# Fail if this firmware can silently fall back to predictable randomness.
#
# Motivated by the COLDCARD firmware disclosure (Block, 2026-07):
# https://engineering.block.xyz/blog/predictable-rng-fallback-and-32-bit-reseed-in-coldcard-firmware
# A guard that checked only whether a macro was *defined* -- not whether it was
# *enabled* -- silently bound wallet seed generation to a non-cryptographic
# fallback PRNG. Nothing crashed, nothing logged, and the firmware shipped that
# way for years. The lesson is not "use a CSPRNG"; every codebase already
# intends to. The lesson is that a degraded RNG path must not be able to succeed
# quietly, and that only a mechanical check keeps it that way.
#
# The shapes that bug takes on an air-gapped ESP32-S3:
#
#   1. The hardware RNG is only a true RNG while an entropy source is running.
#      With no RF subsystem -- which is this device's whole design -- that means
#      bootloader_random_enable(). The second-stage bootloader turns the SAR ADC
#      source on and back off before the app starts, so an app that never
#      re-enables it draws pseudo-random bytes for its entire life, with nothing
#      failing or logging. Rules 1 and 2 pin the enable and ban the disable.
#   2. esp_random()/esp_fill_random() return void or a value; there is no error
#      to discard, so the only defence is that key material goes through
#      rng_fill_checked(). Rule 3 keeps raw draws confined to the entropy module.
#   3. libc rand()/random() is a seeded PRNG. Rule 4 bans it on the device.
#
# Deliberate non-crypto randomness (glitch-defence delays, host-only test
# fallbacks) is allowed with an inline opt-out on the same line or the line
# above:
#
#     r = esp_random();   // rng-hygiene: ok - delay length, not key material
#
# Scope: TRACKED files only (git ls-files), so build output under build/ and
# managed_components/ can never trip a rule or hide one. Sources under test/ and
# fuzz/ are excluded -- fixtures are deterministic on purpose.
#
# What this does NOT cover, stated so nobody reads a green run as more than it
# is: it is a grep. It catches the shape, not the intent. It cannot tell whether
# a checked draw is used correctly once generated, it does not see into
# managed_components/ or the sibling component repos (libnostr-c, noscrypt,
# secp256k1-frost, libwally-core), and it cannot prove the SAR ADC is physically
# producing noise on real silicon. Those stay review and bench questions.
#
# Run from anywhere. Exits non-zero with the offending lines.

set -uo pipefail
cd "$(dirname "$0")/.."

status=0
fail() { printf '\n\033[31mFAIL\033[0m %s\n' "$1"; status=1; }

OPT_OUT='rng-hygiene: ok'
# The one module allowed to draw from esp_random()/esp_fill_random() directly:
# it owns the entropy source and whitens its output.
ENTROPY_MODULE='main/hw_entropy.c'

# Tracked C sources, minus test and fuzz trees. Extensions the repo does not use
# today are listed anyway: a rule that only covers the files that exist now is a
# rule someone bypasses by adding a .cpp.
list_sources() {
  git ls-files '*.c' '*.h' '*.cpp' '*.hpp' '*.cc' \
    | grep -vE '^(test|fuzz)/' \
    || true
}

# Emit "file:line:text" for lines matching $1, dropping comment lines (prose
# about a rule must not trip the rule) and lines carrying the opt-out marker.
# The marker also covers the first code line after the comment block it appears
# in, so a multi-line justification above a call works -- a one-line-lookback
# would silently stop honouring the marker as soon as someone added a second
# sentence, which is the wrong failure direction for an opt-out.
scan() { # $1 = ERE
  local files
  files=$(list_sources)
  [ -z "$files" ] && return 0
  printf '%s\n' "$files" | tr '\n' '\0' | xargs -0 -r awk -v pat="$1" -v optout="$OPT_OUT" '
    FNR==1 { blockopt = 0 }
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
      if (line ~ /^(\/\/|\*|\/\*)/) {
        if (index($0, optout)) blockopt = 1
        next
      }
      if (line ~ /^#[[:space:]]*include/) next
      if (index($0, optout) || blockopt) { blockopt = 0; next }
      # Match against code with string literals blanked, so a log message that
      # says "pseudo-random" is not itself a finding. Report the original line.
      code = $0
      gsub(/"[^"]*"/, "\"\"", code)
      if (code ~ pat) printf "%s:%d:%s\n", FILENAME, FNR, $0
      blockopt = 0
    }
  ' 2>/dev/null || true
}

# ------------------------------------------ 1. entropy source is enabled ----
# The single most important line in this repo. Without it every esp_random()
# draw on an air-gapped S3 is pseudo-random only, and nothing says so.
enable_sites=$(list_sources | tr '\n' '\0' | xargs -0 -r grep -nHE 'bootloader_random_enable[[:space:]]*\(' 2>/dev/null | grep -vE ':[[:space:]]*(\*|//)' || true)
enable_count=$(printf '%s' "$enable_sites" | grep -c . || true)
if [ "$enable_count" -ne 1 ]; then
  fail "expected exactly one bootloader_random_enable() call, found $enable_count:"
  [ -n "$enable_sites" ] && printf '%s\n' "$enable_sites" | sed 's/^/  /'
  echo "  → the ESP32-S3 HWRNG is pseudo-random without an entropy source, and this"
  echo "    firmware never brings up RF. The call belongs in $ENTROPY_MODULE."
fi

# ----------------------------------------- 2. and is never turned back off --
disable_sites=$(list_sources | tr '\n' '\0' | xargs -0 -r grep -nHE 'bootloader_random_disable[[:space:]]*\(' 2>/dev/null | grep -vE ':[[:space:]]*(\*|//)' || true)
if [ -n "$disable_sites" ]; then
  fail "bootloader_random_disable() drops the RNG back to pseudo-random for every later draw:"
  printf '%s\n' "$disable_sites" | sed 's/^/  /'
  echo "  → if RF, the ADC driver, or I2S ever needs the SAR ADC, that trade-off needs"
  echo "    a deliberate decision, not a call site."
fi

# ------------------------------------- 3. raw HWRNG draws stay in one place --
# Match the token, not the call shape: `esp_random(x)` and taking the function's
# address (`fn = esp_random;`) reach the same generator, and a rule that only
# knows the first is one refactor from useless. #include lines are skipped in
# scan(), so "esp_random.h" does not trip this.
raw_bad=$(
  scan 'esp_random|esp_fill_random' \
    | grep -vF "$ENTROPY_MODULE:" \
    || true
)
if [ -n "$raw_bad" ]; then
  fail "raw HWRNG draw outside $ENTROPY_MODULE (bypasses whitening and the health check):"
  printf '%s\n' "$raw_bad" | sed 's/^/  /'
  echo "  → use rng_fill_checked() from main/random_utils.h,"
  echo "    or mark a deliberate non-key-material use: // $OPT_OUT - <reason>"
fi

# ------------------------------------------------- 4. no libc seeded PRNG ----
libc_bad=$(scan '(^|[^_[:alnum:]])(rand|random|srand|srandom)[[:space:]]*[(;,)]')
if [ -n "$libc_bad" ]; then
  fail "libc seeded PRNG in firmware code:"
  printf '%s\n' "$libc_bad" | sed 's/^/  /'
  echo "  → use rng_fill_checked(); rand()/random() is a seeded, predictable generator"
fi

if [ "$status" -eq 0 ]; then
  echo "RNG hygiene: OK (entropy source enabled once and never disabled, raw draws confined to $ENTROPY_MODULE, no libc PRNG)"
fi
exit "$status"
