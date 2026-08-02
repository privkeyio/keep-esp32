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
#      failing or logging. Rule 1 pins the enable to the body of
#      hw_entropy_init(), and rule 2 bans the disable.
#   2. Anything that takes the SAR ADC away again: the ADC driver, RF, I2S, or
#      sleep. Rule 5 bans them, because the enable surviving is worth as much as
#      the enable existing.
#   3. esp_random()/esp_fill_random()/getrandom() return void or a value; there
#      is no error to discard, so the only defence is that key material goes
#      through rng_fill_checked(). Rule 3 keeps raw draws in the entropy module.
#   4. libc rand()/random() is a seeded PRNG. Rule 4 bans it on the device.
#
# Deliberate non-crypto randomness (glitch-defence delays, host-only test
# fallbacks) is allowed with an inline opt-out on the same line, or anywhere in
# the comment block directly above:
#
#     r = esp_random();   // rng-hygiene: ok - delay length, not key material
#
# Lines are preprocessed before any rule sees them: // and /* */ comments are
# stripped with real state tracking, string literals are blanked, and #if 0 /
# #ifdef of an unset symbol regions are dropped. Without that, `*out =
# esp_random();` reads as a comment (leading `*`), a rule-name mentioned in
# prose reads as a violation, and a call parked inside `#if 0` reads as live.
# All three were live bypasses in an earlier version of this script.
#
# Scope: TRACKED files only (git ls-files), so build output and
# managed_components/ can never trip a rule or hide one. Sources under test/ and
# fuzz/ are excluded -- fixtures are deterministic on purpose.
#
# What this does NOT cover, stated so nobody reads a green run as more than it
# is:
#   - It is a grep. It catches shapes, not intent, and cannot tell whether a
#     checked draw is used correctly once generated.
#   - It sees only this repo. The sibling component checkouts (libnostr-c,
#     noscrypt, secp256k1-frost, libwally-core) and managed_components/ are
#     invisible to it, and libnostr-c does draw from esp_fill_random directly.
#   - Rule 1 proves the call is present and live in the source. It cannot prove
#     the SAR ADC is producing noise on real silicon. The device reports its own
#     register readback as `rng_entropy_source` over get_status; that is the
#     runtime half of this check, and it is also only a state check.
#
# Run from anywhere. Exits non-zero with the offending lines.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

status=0
fail() { printf '\n\033[31mFAIL\033[0m %s\n' "$1"; status=1; }

OPT_OUT='rng-hygiene: ok'
# The one module allowed to draw from the HWRNG directly and the one function
# allowed to switch the entropy source on.
ENTROPY_MODULE='main/hw_entropy.c'
ENTROPY_INIT='hw_entropy_init'

# Tracked C sources, minus test and fuzz trees. Extensions the repo does not use
# today are listed anyway: a rule that only covers the files that exist now is a
# rule someone bypasses by adding a .cpp.
list_sources() {
  git ls-files '*.c' '*.h' '*.cpp' '*.hpp' '*.cc' \
    | grep -vE '^(test|fuzz)/'
}

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  printf '\n\033[31mFAIL\033[0m not inside a git work tree; this guard scans tracked files only\n'
  exit 1
}

# Emit "file:line:code" for every live code line, with comments stripped,
# string literals blanked, #if 0 regions dropped, and opt-out lines removed.
# Rules then match plain text against real code only.
#
# Written as one POSIX awk pass per file so it runs the same under gawk on CI
# and BSD awk on a developer's macOS. No gawk extensions, no `xargs -r`.
preprocess() {
  local f rc out
  rc=0
  for f in $(list_sources); do
    out=$(awk -v fname="$f" -v optout="$OPT_OUT" '
      function strip(s,   out, i, c, d, n) {
        # Walk the line tracking block-comment and string state. Comment text is
        # collected in cmt so the opt-out marker can still be seen; code text is
        # returned with strings blanked.
        out = ""; cmt = ""; n = length(s)
        for (i = 1; i <= n; i++) {
          c = substr(s, i, 1); d = substr(s, i, 2)
          if (inblock) { if (d == "*/") { inblock = 0; i++ } else cmt = cmt c; continue }
          if (instr)   { if (c == "\\") { i++; continue }
                         if (c == quote) { instr = 0; out = out "\"\"" }
                         continue }
          if (d == "/*") { inblock = 1; i++; continue }
          if (d == "//") { cmt = cmt substr(s, i + 2); break }
          if (c == "\"" || c == "'"'"'") { instr = 1; quote = c; continue }
          out = out c
        }
        return out
      }
      function trim(s) { sub(/^[ \t]*/, "", s); sub(/[ \t]*$/, "", s); return s }

      BEGIN { inblock = 0; instr = 0; skip = 0; blockopt = 0 }
      {
        # Splice C line continuations before anything looks at the text. A
        # backslash-newline inside an identifier is legal: translation phase 2
        # removes it before tokenization, so the compiler sees
        # adc_oneshot_new_unit() while a per-physical-line scanner sees
        # "adc_oneshot\\" and "_new_unit();" and matches neither. That defeated
        # rule 5, the one holding the SAR ADC invariant behind the v0.2.1
        # entropy fix. startline keeps the finding pointing at the first
        # physical line, which is where a reader has to go to fix it.
        startline = FNR
        while (sub(/\\[ \t]*$/, "", $0) > 0) {
          if ((getline nextpart) <= 0) break
          $0 = $0 nextpart
        }

        code = trim(strip($0))

        # A comment block carrying the marker covers the next code line, however
        # many comment or blank lines sit between.
        if (code == "") { if (index(cmt, optout)) blockopt = 1; next }

        # #if 0 / #if 0-equivalent regions are not live code. Nesting is tracked
        # so an inner #if inside a dead region does not end it early.
        if (code ~ /^#[ \t]*if/) {
          if (skip > 0) { skip++; next }
          if (code ~ /^#[ \t]*if[ \t]+0([^0-9]|$)/) { skip = 1; next }
          next
        }
        if (skip > 0) {
          if (code ~ /^#[ \t]*endif/) skip--
          next
        }
        if (code ~ /^#[ \t]*(endif|else|elif)/) next

        if (index(cmt, optout) || blockopt) { blockopt = 0; cmt = ""; next }
        blockopt = 0; cmt = ""
        printf "%s:%d:%s\n", fname, startline, code
      }
    ' "$f") || rc=2
    [ -n "$out" ] && printf '%s\n' "$out"
  done
  return "$rc"
}

# Fails CLOSED: a broken awk or an empty file list is a failure, never a pass.
CODE=$(preprocess) || {
  printf '\n\033[31mFAIL\033[0m the scanner itself failed; refusing to report a clean tree\n'
  exit 1
}
if [ -z "$CODE" ]; then
  fail "no source lines to scan; the preprocessor or the file list is broken"
  echo "  → a guard that finds nothing must not report success"
  exit 1
fi

scan() { # $1 = ERE, matched against code text only
  printf '%s\n' "$CODE" | awk -F: -v pat="$1" '{
    line = $0; sub(/^[^:]*:[0-9]+:/, "", line)
    if (line ~ pat) print $0
  }'
}

# ------------------------------------------ 1. entropy source is enabled ----
# The single most important line in this repo. Without it every esp_random()
# draw on an air-gapped S3 is pseudo-random only, and nothing says so.
#
# Pinned to the body of hw_entropy_init() in the entropy module, not merely
# "present somewhere". A call sitting in a function nobody invokes satisfies a
# bare count while changing nothing, which is the COLDCARD defect one level up.
enable_sites=$(scan 'bootloader_random_enable')
enable_in_init=$(
  awk -v mod="$ENTROPY_MODULE" -v fn="$ENTROPY_INIT" '
    function count(s, ch,   i, n) {
      # Literal character count: gsub()/split() would treat ch as a regex,
      # and "(" alone is not a valid one -- BSD awk aborts on it.
      n = 0
      for (i = length(s); i > 0; i--) if (substr(s, i, 1) == ch) n++
      return n
    }
    BEGIN { FS = ":" ; depth = 0; inside = 0; found = 0 }
    {
      file = $1; lineno = $2
      code = $0; sub(/^[^:]*:[0-9]+:/, "", code)
      if (file != mod) next
      if (!inside && code ~ ("(^|[^a-zA-Z0-9_])" fn "[ \t]*\\(")) { inside = 1; depth = 0 }
      if (inside) {
        depth += count(code, "{") - count(code, "}")
        if (code ~ /bootloader_random_enable/) found++
        if (depth <= 0 && code ~ /\}/) inside = 0
      }
    }
    END { print found }
  ' <<EOF
$CODE
EOF
)
enable_total=$(printf '%s' "$enable_sites" | grep -c . || true)
if [ "$enable_total" -ne 1 ] || [ "$enable_in_init" -ne 1 ]; then
  fail "expected exactly one live bootloader_random_enable(), inside ${ENTROPY_MODULE}'s ${ENTROPY_INIT}() (found $enable_total live, $enable_in_init of them in that function):"
  [ -n "$enable_sites" ] && printf '%s\n' "$enable_sites" | sed 's/^/  /'
  echo "  → the ESP32-S3 HWRNG is pseudo-random without an entropy source, and this"
  echo "    firmware never brings up RF. A call that is compiled out, duplicated, or"
  echo "    parked in an uncalled helper is the same as no call at all."
fi

# ----------------------------------------- 2. and is never turned back off --
disable_sites=$(scan 'bootloader_random_disable')
if [ -n "$disable_sites" ]; then
  fail "bootloader_random_disable() drops the RNG back to pseudo-random for every later draw:"
  printf '%s\n' "$disable_sites" | sed 's/^/  /'
  echo "  → if RF, the ADC driver, or I2S ever needs the SAR ADC, that trade-off needs"
  echo "    a deliberate decision, not a call site."
fi

# ------------------------------------- 3. raw HWRNG draws stay in one place --
# Match the token, not the call shape: `esp_random(x)` and taking the function's
# address (`fn = esp_random;`) reach the same generator. getrandom()/getentropy()
# are included because ESP-IDF implements both on top of esp_fill_random.
raw_bad=$(
  scan 'esp_random|esp_fill_random|(^|[^a-zA-Z0-9_])(getrandom|getentropy)[ \t]*[(]' \
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
libc_bad=$(scan '(^|[^a-zA-Z0-9_])(rand|random|srand|srandom|rand_r|random_r|lrand48|drand48)[ \t]*[(]')
if [ -n "$libc_bad" ]; then
  fail "libc seeded PRNG in firmware code:"
  printf '%s\n' "$libc_bad" | sed 's/^/  /'
  echo "  → use rng_fill_checked(); rand()/random() is a seeded, predictable generator"
fi

# ------------------------------- 5. nothing takes the SAR ADC away again ----
# bootloader_random_enable() is documented as unsafe alongside the ADC driver,
# RF, or I2S, and sleep can drop the SAR/RTC state it configures. Each of these
# turns the entropy source off without touching rule 1 or 2, so the device would
# keep reporting a healthy RNG while producing pseudo-random bytes.
contend_bad=$(scan '(adc_oneshot_|adc_continuous_|adc_cali_|esp_wifi_|esp_bt_controller_|i2s_new_channel|i2s_driver_install|esp_light_sleep_start|esp_deep_sleep)')
contend_bad="$contend_bad$(printf '\n')$(grep -nHE '(^|[^a-zA-Z0-9_])esp_adc([^a-zA-Z0-9_]|$)' main/CMakeLists.txt 2>/dev/null || true)"
contend_bad=$(printf '%s\n' "$contend_bad" | grep -v '^$' || true)
if [ -n "$contend_bad" ]; then
  fail "this contends with the SAR ADC entropy source and would silently disable it:"
  printf '%s\n' "$contend_bad" | sed 's/^/  /'
  echo "  → the ADC driver, RF, I2S, and sleep all take back the peripheral"
  echo "    bootloader_random_enable() configured. Resolve the conflict deliberately"
  echo "    (see docs/SECURITY.md) rather than by adding a call site."
fi

if [ "$status" -eq 0 ]; then
  echo "RNG hygiene: OK (entropy source enabled once in ${ENTROPY_INIT}() and never disabled or contended, raw draws confined to $ENTROPY_MODULE, no libc PRNG)"
fi
exit "$status"
