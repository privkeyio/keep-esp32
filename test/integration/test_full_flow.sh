#!/bin/bash
set -e

DEVICE="${1:-/dev/ttyUSB0}"
KEEP_PATH="${KEEP_PATH:-$HOME/.keep}"
GROUP_NAME="test_integration_$$"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "${GREEN}OK${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }
step() { echo -e "\n>>> $1"; }

cleanup() {
    if [ -n "$GROUP" ]; then
        step "Cleanup: deleting hardware share"
        keep frost hardware delete --device "$DEVICE" --group "$GROUP" 2>/dev/null || true
    fi
}
trap cleanup EXIT

step "1. Hardware ping"
keep frost hardware ping --device "$DEVICE" || fail "Hardware ping failed"
pass "Hardware ping"

step "2. Generate FROST group (t=2, n=3)"
keep frost generate --threshold 2 --shares 3 --name "$GROUP_NAME" || fail "Generate failed"
pass "Generated group: $GROUP_NAME"

step "3. Get group pubkey"
GROUP=$(keep frost list 2>/dev/null | grep "$GROUP_NAME" | awk '{print $NF}' | head -1)
if [ -z "$GROUP" ]; then
    fail "Could not find group pubkey"
fi
pass "Group pubkey: ${GROUP:0:16}..."

step "4. Export share 3 to hardware"
keep frost hardware import --device "$DEVICE" --group "$GROUP" --share 3 || fail "Hardware import failed"
pass "Imported share 3"

step "5. Verify share on hardware"
keep frost hardware list --device "$DEVICE" | grep -q "$GROUP" || fail "Share not found on hardware"
pass "Share verified on hardware"

step "6. Test signing with hardware"
MESSAGE=$(echo -n "integration test $(date +%s)" | sha256sum | cut -d' ' -f1)
echo "Message hash: $MESSAGE"

SIGN_OUTPUT=$(keep frost network sign --group "$GROUP" --message "$MESSAGE" --hardware "$DEVICE" 2>&1) && SIGN_STATUS=0 || SIGN_STATUS=$?
echo "$SIGN_OUTPUT"

if [ $SIGN_STATUS -eq 0 ]; then
    pass "Signature completed"
else
    echo -e "${RED}SKIP${NC}: Network signing failed (requires relay connectivity and multiple signers)"
fi

step "7. Delete share from hardware"
keep frost hardware delete --device "$DEVICE" --group "$GROUP" || fail "Hardware delete failed"
pass "Share deleted"

step "8. Verify share removed"
if keep frost hardware list --device "$DEVICE" | grep -q "$GROUP"; then
    fail "Share still present on hardware"
fi
pass "Share removal verified"

GROUP=""

echo -e "\n${GREEN}=== Integration test passed ===${NC}\n"
