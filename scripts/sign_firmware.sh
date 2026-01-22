#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"
KEYS_DIR="${PROJECT_DIR}/keys"
SIGNING_KEY="${SIGNING_KEY:-${KEYS_DIR}/secure_boot_signing_key.pem}"

usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  generate-key     Generate new RSA-3072 signing key"
    echo "  sign-app         Sign application binary"
    echo "  sign-bootloader  Sign bootloader binary"
    echo "  sign-all         Sign both bootloader and application"
    echo "  verify           Verify signatures on built binaries"
    echo ""
    echo "Environment:"
    echo "  SIGNING_KEY      Path to signing key (default: keys/secure_boot_signing_key.pem)"
    exit 1
}

check_espsecure() {
    if ! command -v espsecure.py &> /dev/null; then
        echo "Error: espsecure.py not found. Ensure ESP-IDF is activated."
        exit 1
    fi
}

check_signing_key() {
    if [ ! -f "$SIGNING_KEY" ]; then
        echo "Error: Signing key not found at $SIGNING_KEY"
        echo "Run '$0 generate-key' first."
        exit 1
    fi
}

generate_key() {
    check_espsecure
    mkdir -p "$KEYS_DIR"

    if [ -f "$SIGNING_KEY" ]; then
        echo "Error: Key already exists at $SIGNING_KEY"
        echo "Remove it first if you want to generate a new key."
        exit 1
    fi

    echo "Generating RSA-3072 signing key..."
    (umask 077; espsecure.py generate_signing_key --version 2 "$SIGNING_KEY")

    echo "Key generated: $SIGNING_KEY"
    echo "CRITICAL: Back up this key securely. Loss means inability to update firmware."
}

sign_app() {
    check_espsecure
    check_signing_key

    local app_bin="${BUILD_DIR}/keep.bin"
    local signed_bin="${BUILD_DIR}/keep-signed.bin"

    if [ ! -f "$app_bin" ]; then
        echo "Error: Application binary not found at $app_bin"
        echo "Build the project first with: idf.py build"
        exit 1
    fi

    echo "Signing application..."
    espsecure.py sign_data --version 2 --keyfile "$SIGNING_KEY" \
        --output "$signed_bin" "$app_bin"

    echo "Signed application: $signed_bin"
}

sign_bootloader() {
    check_espsecure
    check_signing_key

    local bootloader_bin="${BUILD_DIR}/bootloader/bootloader.bin"
    local signed_bin="${BUILD_DIR}/bootloader/bootloader-signed.bin"

    if [ ! -f "$bootloader_bin" ]; then
        echo "Error: Bootloader binary not found at $bootloader_bin"
        echo "Build the project first with: idf.py build"
        exit 1
    fi

    echo "Signing bootloader..."
    espsecure.py sign_data --version 2 --keyfile "$SIGNING_KEY" \
        --output "$signed_bin" "$bootloader_bin"

    echo "Signed bootloader: $signed_bin"
}

verify_signatures() {
    check_espsecure

    local app_bin="${BUILD_DIR}/keep-signed.bin"
    local bootloader_bin="${BUILD_DIR}/bootloader/bootloader-signed.bin"

    echo "Verifying signatures..."

    if [ -f "$app_bin" ]; then
        echo "Verifying application..."
        espsecure.py verify_signature --version 2 --keyfile "$SIGNING_KEY" "$app_bin"
    else
        echo "Warning: Signed application not found"
    fi

    if [ -f "$bootloader_bin" ]; then
        echo "Verifying bootloader..."
        espsecure.py verify_signature --version 2 --keyfile "$SIGNING_KEY" "$bootloader_bin"
    else
        echo "Warning: Signed bootloader not found"
    fi

    echo "Verification complete."
}

case "${1:-}" in
    generate-key)
        generate_key
        ;;
    sign-app)
        sign_app
        ;;
    sign-bootloader)
        sign_bootloader
        ;;
    sign-all)
        sign_bootloader
        sign_app
        ;;
    verify)
        verify_signatures
        ;;
    *)
        usage
        ;;
esac
