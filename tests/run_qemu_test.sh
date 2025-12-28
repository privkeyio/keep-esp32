#!/bin/bash
set -e

if [ -n "$QEMU" ]; then
    :
elif command -v qemu-system-xtensa >/dev/null 2>&1; then
    QEMU=$(command -v qemu-system-xtensa)
elif command -v qemu-system-xtensa-alt >/dev/null 2>&1; then
    QEMU=$(command -v qemu-system-xtensa-alt)
else
    echo "Error: QEMU not found. Set QEMU environment variable or add qemu-system-xtensa to PATH" >&2
    exit 1
fi

FLASH=${FLASH:-build/merged_flash.bin}

if [ ! -f "$FLASH" ]; then
    echo "Error: Flash image not found: $FLASH" >&2
    exit 1
fi

cleanup() {
    rm -f /tmp/qemu_serial_in /tmp/qemu_serial_out
}
trap cleanup EXIT

rm -f /tmp/qemu_serial_in /tmp/qemu_serial_out
mkfifo /tmp/qemu_serial_in
mkfifo /tmp/qemu_serial_out

echo "Starting QEMU..."
$QEMU -M esp32s3 -nographic \
    -drive file=$FLASH,format=raw,if=mtd \
    -serial pipe:/tmp/qemu_serial \
    -no-reboot &
QEMU_PID=$!

sleep 5

echo "Sending ping..."
echo '{"id":1,"method":"ping"}' > /tmp/qemu_serial_in &

sleep 2
timeout 2 cat /tmp/qemu_serial_out || true

echo "Cleaning up..."
kill $QEMU_PID 2>/dev/null || true
