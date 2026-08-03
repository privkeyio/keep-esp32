#!/usr/bin/env bash
# Fail if the upstream dependency pins have drifted, or disagree between the
# three places that declare them.
#
# Why this exists and dependabot does not cover it: every dependency of this
# firmware is a `git clone` in Dockerfile.reproducible plus a `ref:` passed to
# actions/checkout in the workflows. Dependabot has no ecosystem for either --
# it understands `uses:`, `FROM`, and package manifests. So the pins here are
# invisible to it.
#
# That is not hypothetical. Before this check existed:
#   - libwally-core sat on release_1.5.1 while 1.5.2 through 1.5.6 shipped, every
#     one of them labelled "Users are advised to update as soon as possible",
#     including PSBT parse hardening and a BIP-341 signing fix on the path that
#     handles attacker-supplied PSBTs.
#   - secp256k1-frost and noscrypt were checked out BY BRANCH in CI, so they were
#     not pinned at all: a push to someone else's fork silently changed what this
#     repo built and released.
#   - Dockerfile.reproducible pinned secp256k1-frost to a commit that was not even
#     on the branch CI used, so the reproducible build failed outright.
# Nothing failed, nothing reported, CI was green throughout. That is the same
# shape as the RNG defect scripts/check-rng-hygiene.sh exists to catch.
#
# Two rules:
#   1. AGREEMENT  - Dockerfile.reproducible and both workflows must name the
#      identical commit for every dependency, and it must be a 40-hex commit, not
#      a branch or tag. Runs offline; always enforced.
#   2. FRESHNESS  - each pin is compared against upstream. Requires network; skipped
#      with a clear message when unavailable so the agreement rule still runs.
#
# Freshness is a WARNING by default and only fails under --strict, because an
# upstream release landing should not turn an unrelated PR red. The scheduled
# workflow runs --strict so drift surfaces as its own failure.
#
# Run from anywhere. Exits non-zero on a violation.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1

status=0
fail() { printf '\n\033[31mFAIL\033[0m %s\n' "$1"; status=1; }
warn() { printf '\n\033[33mWARN\033[0m %s\n' "$1"; }

DOCKERFILE='Dockerfile.reproducible'
WORKFLOWS='.github/workflows/ci.yml .github/workflows/release.yml'

for f in $DOCKERFILE $WORKFLOWS; do
  [ -f "$f" ] || { fail "$f not found; this guard cannot run (was it moved?)"; exit 1; }
done

# repo -> commit, as declared in the Dockerfile's clone loop.
docker_pins=$(grep -oE '"(privkeyio|ElementsProject)/[A-Za-z0-9._-]+ [a-f0-9]{40}"' "$DOCKERFILE" \
  | tr -d '"' | sort -u)

if [ -z "$docker_pins" ]; then
  fail "no commit pins found in $DOCKERFILE; the guard would pass vacuously"
  exit 1
fi

# ------------------------------------------------------- 1. agreement ------
while read -r repo pin; do
  [ -n "$repo" ] || continue
  for wf in $WORKFLOWS; do
    # the `ref:` line following `repository: <repo>`, skipping comment lines
    wf_ref=$(awk -v r="repository: $repo\$" '
      $0 ~ r { found = 1; next }
      found && /^[[:space:]]*#/ { next }
      found && /^[[:space:]]*ref:/ { sub(/^[[:space:]]*ref:[[:space:]]*/, ""); sub(/[[:space:]]*#.*$/, ""); print; exit }
      found && NF == 0 { exit }
    ' "$wf")
    if [ -z "$wf_ref" ]; then
      fail "$wf does not check out $repo, but $DOCKERFILE pins it. The reproducible build and CI would build different sources."
      continue
    fi
    if ! printf '%s' "$wf_ref" | grep -qE '^[a-f0-9]{40}$'; then
      fail "$wf pins $repo to '$wf_ref', which is a branch or tag, not a commit."
      echo "  → a branch ref is not a pin: whoever can push to it changes what this repo builds"
      echo "    and releases, with no diff here. Tags can be force-moved. Use the commit SHA."
      continue
    fi
    if [ "$wf_ref" != "$pin" ]; then
      fail "$repo disagrees between $DOCKERFILE and $wf:"
      echo "    $DOCKERFILE: $pin"
      echo "    $wf:        $wf_ref"
      echo "  → the reproducible build and the released artifact would be built from different source."
    fi
  done
done <<EOF
$docker_pins
EOF

# ------------------------------------------- 1b. ESP-IDF agreement ---------
# The base image in the Dockerfile and esp_idf_version in the workflows must
# name the same toolchain, for the same reason the dependency pins must: the
# reproducible build is only meaningful if it builds what the release built.
#
# This rule exists because dependabot cannot get it right. It sees the FROM line
# and nothing else; esp_idf_version is not an ecosystem it can parse. So every
# IDF bump it opens moves the Dockerfile alone and leaves the workflows behind,
# and until this check existed the whole suite went green on exactly that diff.
idf_from=$(grep -oE '^FROM[[:space:]]+espressif/idf:v[0-9]+\.[0-9]+(\.[0-9]+)?@sha256:[a-f0-9]{64}' "$DOCKERFILE" | head -1)
if [ -z "$idf_from" ]; then
  fail "$DOCKERFILE has no digest-pinned espressif/idf base image."
  echo "  → a bare tag is not a pin: image tags can be repushed, so the reproducible"
  echo "    build could silently change toolchain. Use image:vX.Y.Z@sha256:<digest>."
else
  idf_docker_ver=${idf_from##*espressif/idf:}
  idf_docker_ver=${idf_docker_ver%%@*}
  for wf in $WORKFLOWS; do
    wf_idf_all=$(grep -oE 'esp_idf_version:[[:space:]]*v?[0-9]+\.[0-9]+(\.[0-9]+)?' "$wf" \
      | sed -E 's/.*esp_idf_version:[[:space:]]*//' | sort -u)
    if [ -z "$wf_idf_all" ]; then
      fail "$wf does not set esp_idf_version, but $DOCKERFILE pins the toolchain to $idf_docker_ver."
      continue
    fi
    for wf_idf in $wf_idf_all; do
      if [ "$wf_idf" != "$idf_docker_ver" ]; then
        fail "ESP-IDF version disagrees between $DOCKERFILE and $wf:"
        echo "    $DOCKERFILE: $idf_docker_ver"
        echo "    $wf:        $wf_idf"
        echo "  → the reproducible build and the released artifact would be built with"
        echo "    different toolchains, so verifying a release against source would fail."
      fi
    done
  done
fi

# ------------------------------------------------------- 2. freshness ------
if ! git ls-remote --exit-code https://github.com/privkeyio/keep-esp32.git HEAD >/dev/null 2>&1; then
  echo
  echo "NOTE: no network access to github.com; skipping the freshness check."
  echo "      The agreement rule above still ran."
else
  while read -r repo pin; do
    [ -n "$repo" ] || continue
    url="https://github.com/$repo.git"
    # Newest semver-ish tag, if the project tags releases at all.
    latest_tag=$(git ls-remote --tags --refs "$url" 2>/dev/null \
      | awk -F'refs/tags/' '{print $2}' | grep -E '^(v|release_)?[0-9]+\.[0-9]+' | sort -V | tail -1)
    if [ -n "$latest_tag" ]; then
      tag_commit=$(git ls-remote "$url" "refs/tags/$latest_tag^{}" 2>/dev/null | cut -f1)
      [ -z "$tag_commit" ] && tag_commit=$(git ls-remote "$url" "refs/tags/$latest_tag" 2>/dev/null | cut -f1)
      if [ -n "$tag_commit" ] && [ "$tag_commit" != "$pin" ]; then
        # Differing from the newest release is not the same as being behind it.
        # A pin deliberately ahead of a tag is the normal case here: libnostr-c
        # v0.2.0 predates the ESP RNG fix, so keep-esp32 pins past it on purpose.
        # Reporting that as stale is a false alarm that trains people to ignore
        # this job. Ask GitHub which direction the difference runs.
        # $repo is already owner/name; deriving it back out of $url was how the
        # first attempt at this failed, by swallowing the .git suffix.
        direction=""; cmp_err=""
        if command -v gh >/dev/null 2>&1; then
          # stderr is kept. Discarding it once already turned "gh has no token"
          # into an indistinguishable "pin looks stale", which cost a debugging
          # cycle against CI.
          cmp_out=$(gh api "repos/$repo/compare/${tag_commit}...${pin}" --jq .status 2>&1)
          direction=$(printf '%s' "$cmp_out" | head -1)
          case "$direction" in
            ahead|behind|identical|diverged) ;;
            *) cmp_err="$direction"; direction="" ;;
          esac
        else
          cmp_err="gh not installed"
        fi
        if [ -z "$direction" ] && [ -n "$cmp_err" ]; then
          echo "  note: could not determine direction vs $latest_tag: $cmp_err"
          echo "        (falling back to reporting any difference as drift)"
        fi
        case "$direction" in
          ahead)
            # Ahead of the newest release, which is the intended state. Say so
            # rather than staying silent, so the pin's position stays visible.
            echo "  ok  $repo is pinned ahead of $latest_tag (${pin:0:8}), not behind it"
            ;;
          identical)
            # Only reachable if the tag and the pin name the same commit through
            # different refs, since the enclosing test already excluded an exact
            # string match. Reported accurately rather than as "ahead".
            echo "  ok  $repo is pinned at $latest_tag (${pin:0:8})"
            ;;
          *)
            msg="$repo is pinned to ${pin:0:8} but upstream's newest release is $latest_tag (${tag_commit:0:8})"
            [ -n "$direction" ] && msg="$msg [$direction]"
            if [ "$STRICT" -eq 1 ]; then fail "$msg"; else warn "$msg"; fi
            echo "  → review the changelog before bumping; these are consumed by a signer's"
            echo "    untrusted-input paths, so a 'patch' release can still be security-relevant."
            ;;
        esac
      fi
    else
      # Fork with no releases: the useful signal is the tip of the branch it was cut from.
      for br in esp-idf-support main master; do
        tip=$(git ls-remote "$url" "refs/heads/$br" 2>/dev/null | cut -f1)
        [ -n "$tip" ] || continue
        if [ "$tip" != "$pin" ]; then
          msg="$repo is pinned to ${pin:0:8} but $br is at ${tip:0:8}"
          if [ "$STRICT" -eq 1 ]; then fail "$msg"; else warn "$msg"; fi
        fi
        break
      done
    fi
  done <<EOF
$docker_pins
EOF
fi

if [ "$status" -eq 0 ]; then
  echo "Dependency pins: OK (all commit-pinned and identical across $DOCKERFILE and the workflows)"
fi
exit "$status"
